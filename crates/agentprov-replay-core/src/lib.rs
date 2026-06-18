//! APCAP replay layer — converts verified APCAP frame streams to asciicast v2.
//!
//! Every public function verifies the full chain before emitting output (fail-closed).
//! A tampered or truncated file returns `Err(ReplayError::Verify(...))` and nothing
//! is written.
//!
//! # ponytail limitation
//! `to_asciicast` and `to_asciicast_range` buffer all asciicast event lines in memory
//! before writing. For Tier-1 local replay this is fine (terminal sessions are tens of
//! MiB at most), but a streaming design would avoid the intermediate `Vec<String>`.

use agentprov_capture_format::{verify, Frame, FrameType, VerifyError};
use std::io::{self, Read, Write};

// ── error ──────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ReplayError {
    Verify(VerifyError),
    Io(io::Error),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify(e) => write!(f, "verify: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Verify(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

impl From<VerifyError> for ReplayError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}

impl From<io::Error> for ReplayError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── asciicast header ────────────────────────────────────────────────────────────

/// Write the asciicast v2 header line: `{"version":2,"width":W,"height":H}`.
/// No serde — compact, no extra keys the player doesn't need.
fn write_header<W: Write>(out: &mut W, width: u16, height: u16) -> io::Result<()> {
    writeln!(out, "{{\"version\":2,\"width\":{width},\"height\":{height}}}")
}

// ── JSON string escaping ────────────────────────────────────────────────────────

/// Escape terminal bytes as a JSON string value (without the surrounding quotes).
/// Input is raw PTY bytes; we go through `from_utf8_lossy` so partial UTF-8 is
/// replaced by U+FFFD before escaping rather than emitted as invalid JSON.
///
/// Escaping rules:
/// - `\` → `\\`
/// - `"` → `\"`
/// - `\n` → `\n`, `\r` → `\r`, `\t` → `\t`
/// - other control chars (< 0x20, including ESC 0x1b) → `\u00XX`
/// - everything else (including multi-byte UTF-8) → emitted raw
fn escape_json_string(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as FmtWrite;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Format one asciicast event line: `[elapsed_secs, "o", "escaped_payload"]`.
fn format_event(elapsed_secs: f64, payload: &[u8]) -> String {
    let escaped = escape_json_string(payload);
    format!("[{elapsed_secs:.6},\"o\",\"{escaped}\"]\n")
}

// ── collector (shared by all three public fns) ──────────────────────────────────

/// Data gathered in a single `verify` pass. Used by all three public functions.
struct Collected {
    /// Each PtyOutput frame as `(mono_ns, event_line)`.
    events: Vec<(u64, String)>,
    /// mono_ns of the very first frame seen (time base for relative timestamps).
    base_ns: Option<u64>,
    /// mono_ns of the last frame seen.
    last_ns: u64,
    /// Terminal width (from first Resize frame, default 80).
    width: u16,
    /// Terminal height (from first Resize frame, default 24).
    height: u16,
    /// True once we've seen a Resize frame (so we use only the first one).
    saw_resize: bool,
    /// SessionStart payload as UTF-8 command string.
    command: String,
    /// SessionEnd payload as UTF-8 exit string.
    exit: String,
    /// Total PtyOutput payload bytes.
    output_bytes: u64,
    /// Hash of the last frame verified (hex), or empty if stream is empty.
    tip_hash: [u8; 32],
    /// Total verified frame count (matches `verify`'s return value).
    frames: u64,
}

impl Collected {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            base_ns: None,
            last_ns: 0,
            width: 80,
            height: 24,
            saw_resize: false,
            command: String::new(),
            exit: String::new(),
            output_bytes: 0,
            tip_hash: [0u8; 32],
            frames: 0,
        }
    }

    fn ingest(&mut self, f: &Frame) {
        self.frames += 1;
        self.tip_hash = f.frame_hash;

        if self.base_ns.is_none() {
            self.base_ns = Some(f.mono_ns);
        }
        self.last_ns = f.mono_ns;

        match f.frame_type {
            FrameType::SessionStart => {
                self.command = String::from_utf8_lossy(&f.payload).into_owned();
            }
            FrameType::SessionEnd => {
                self.exit = String::from_utf8_lossy(&f.payload).into_owned();
            }
            FrameType::Resize if !self.saw_resize => {
                if f.payload.len() == 4 {
                    self.width = u16::from_le_bytes([f.payload[0], f.payload[1]]);
                    self.height = u16::from_le_bytes([f.payload[2], f.payload[3]]);
                    self.saw_resize = true;
                }
                // malformed payload (len != 4) → keep default 80×24
            }
            FrameType::PtyOutput => {
                let base = self.base_ns.unwrap_or(0);
                let elapsed = f.mono_ns.saturating_sub(base) as f64 / 1_000_000_000.0;
                self.output_bytes += f.payload.len() as u64;
                let line = format_event(elapsed, &f.payload);
                self.events.push((f.mono_ns, line));
            }
            // InputMeta / extra Resize frames → metadata only, no visual event
            _ => {}
        }
    }

    fn tip_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.tip_hash {
            use std::fmt::Write as FmtWrite;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn duration_secs(&self) -> f64 {
        match self.base_ns {
            Some(base) => self.last_ns.saturating_sub(base) as f64 / 1_000_000_000.0,
            None => 0.0,
        }
    }
}

// ── public API ──────────────────────────────────────────────────────────────────

/// Convert an APCAP stream to asciicast v2, writing to `out`.
///
/// Returns the number of `"o"` event lines emitted. Width/height come from the
/// first `Resize` frame (payload = cols u16 LE ++ rows u16 LE), defaulting to
/// 80×24. The whole chain is verified before writing begins — a tampered or
/// truncated file returns `Err` and `out` is not written.
pub fn to_asciicast<R: Read, W: Write>(apcap: R, mut out: W) -> Result<u64, ReplayError> {
    let mut c = Collected::new();
    verify(apcap, |f| c.ingest(f))?;

    write_header(&mut out, c.width, c.height)?;
    let n = c.events.len() as u64;
    for (_, line) in &c.events {
        out.write_all(line.as_bytes())?;
    }
    Ok(n)
}

/// Summary of a verified APCAP stream.
#[derive(Debug)]
pub struct ReplaySummary {
    /// Total verified frame count.
    pub frames: u64,
    /// Hex of the final verified frame's `frame_hash` (64 lowercase hex chars).
    pub tip_hex: String,
    /// Total PtyOutput payload bytes.
    pub output_bytes: u64,
    /// Duration = (last frame mono_ns − first frame mono_ns) as seconds.
    pub duration_secs: f64,
    /// Terminal width (from first Resize frame, default 80).
    pub width: u16,
    /// Terminal height (from first Resize frame, default 24).
    pub height: u16,
    /// SessionStart payload as a string (the agent command).
    pub command: String,
    /// SessionEnd payload as a string (e.g. `"exit=0"`).
    pub exit: String,
}

/// Verify the chain and return a summary suitable for display.
pub fn summarize<R: Read>(apcap: R) -> Result<ReplaySummary, ReplayError> {
    let mut c = Collected::new();
    verify(apcap, |f| c.ingest(f))?;
    Ok(ReplaySummary {
        frames: c.frames,
        tip_hex: c.tip_hex(),
        output_bytes: c.output_bytes,
        duration_secs: c.duration_secs(),
        width: c.width,
        height: c.height,
        command: c.command,
        exit: c.exit,
    })
}

/// Export asciicast for only the frames whose `mono_ns` falls in `[start_ns, end_ns)`.
///
/// The **entire** chain is verified first. A tampered file returns `Err` without
/// writing. Returns the number of `"o"` event lines emitted in the window.
/// Timestamps in the output are relative to the first frame in the full stream
/// (the original timeline is preserved), not to `start_ns`.
pub fn to_asciicast_range<R: Read, W: Write>(
    apcap: R,
    mut out: W,
    start_ns: u64,
    end_ns: u64,
) -> Result<u64, ReplayError> {
    let mut c = Collected::new();
    verify(apcap, |f| c.ingest(f))?;

    write_header(&mut out, c.width, c.height)?;
    let mut emitted = 0u64;
    for (mono_ns, line) in &c.events {
        if *mono_ns >= start_ns && *mono_ns < end_ns {
            out.write_all(line.as_bytes())?;
            emitted += 1;
        }
    }
    Ok(emitted)
}

// ── tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use agentprov_capture_format::{FrameType, Writer};

    /// Build a small in-memory APCAP with:
    ///   seq 0  SessionStart  "claude"
    ///   seq 1  Resize        100×30
    ///   seq 2  PtyOutput     "hi\x1b[31m\"quote\"\n"   @ mono_ns=100_000_000
    ///   seq 3  PtyOutput     "second line\n"             @ mono_ns=500_000_000
    ///   seq 4  SessionEnd    "exit=0"
    fn sample() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        // cols=100, rows=30 in LE
        let resize_payload = {
            let mut p = [0u8; 4];
            p[0..2].copy_from_slice(&100u16.to_le_bytes());
            p[2..4].copy_from_slice(&30u16.to_le_bytes());
            p
        };
        w.write(FrameType::SessionStart, 0, 0, b"claude").unwrap();
        w.write(FrameType::Resize, 50_000_000, 50_000_000, &resize_payload).unwrap();
        w.write(FrameType::PtyOutput, 100_000_000, 100_000_000, b"hi\x1b[31m\"quote\"\n").unwrap();
        w.write(FrameType::PtyOutput, 500_000_000, 500_000_000, b"second line\n").unwrap();
        w.write(FrameType::SessionEnd, 600_000_000, 600_000_000, b"exit=0").unwrap();
        buf
    }

    // ── test 1: asciicast output is valid ────────────────────────────────────

    #[test]
    fn to_asciicast_produces_valid_output() {
        let apcap = sample();
        let mut out = Vec::new();
        let n = to_asciicast(&apcap[..], &mut out).unwrap();
        assert_eq!(n, 2, "should have emitted 2 PtyOutput event lines");

        let text = std::str::from_utf8(&out).expect("output must be UTF-8");
        let mut lines = text.lines();

        // First line: JSON header
        let header = lines.next().expect("header line must exist");
        assert!(
            header.contains("\"version\":2"),
            "header must contain \"version\":2, got: {header}"
        );
        assert!(
            header.contains("\"width\":100"),
            "header must contain \"width\":100, got: {header}"
        );
        assert!(
            header.contains("\"height\":30"),
            "header must contain \"height\":30, got: {header}"
        );

        // Collect remaining event lines
        let event_lines: Vec<&str> = lines.collect();
        assert_eq!(event_lines.len(), 2, "should have 2 event lines");

        // First event must contain the escaped payload
        let first = event_lines[0];
        assert!(
            first.contains("\\\""),
            "escaped double-quote must appear as \\\" in: {first}"
        );
        assert!(
            first.contains("\\u001b"),
            "ESC byte must appear as \\u001b in: {first}"
        );
        // Raw ESC byte must NOT be present
        assert!(
            !first.contains('\x1b'),
            "raw ESC byte (0x1b) must not appear in: {first}"
        );
        assert!(
            first.contains("\\n"),
            "newline must be escaped as \\n in: {first}"
        );
    }

    // ── test 2: summarize ────────────────────────────────────────────────────

    #[test]
    fn summarize_returns_expected_fields() {
        let apcap = sample();
        let s = summarize(&apcap[..]).unwrap();
        assert_eq!(s.frames, 5, "5 frames in sample");
        assert_eq!(s.width, 100);
        assert_eq!(s.height, 30);
        assert_eq!(s.command, "claude");
        assert_eq!(s.exit, "exit=0");
        assert_eq!(s.output_bytes, b"hi\x1b[31m\"quote\"\n".len() as u64
            + b"second line\n".len() as u64);
        assert!(!s.tip_hex.is_empty(), "tip_hex must be non-empty");
        assert_eq!(s.tip_hex.len(), 64, "sha256 hex is 64 chars");
    }

    // ── test 3: tampered APCAP returns Err ──────────────────────────────────

    #[test]
    fn tampered_apcap_returns_err() {
        let mut apcap = sample();
        // Flip a byte inside the PtyOutput payload without re-computing hashes.
        // Find the offset of 'h' in "hi\x1b..."
        let hi_pos = apcap.iter().position(|&b| b == b'h').unwrap();
        apcap[hi_pos] ^= 0xff;
        let mut out = Vec::new();
        let result = to_asciicast(&apcap[..], &mut out);
        assert!(result.is_err(), "tampered stream must return Err");
    }

    // ── test 4: range export returns fewer events ────────────────────────────

    #[test]
    fn range_export_returns_fewer_events() {
        let apcap = sample();

        // Full export
        let mut full_out = Vec::new();
        let full_n = to_asciicast(&apcap[..], &mut full_out).unwrap();
        assert_eq!(full_n, 2);

        // Window covering only the first PtyOutput (mono_ns=100_000_000)
        // but NOT the second (mono_ns=500_000_000).
        let mut range_out = Vec::new();
        let range_n = to_asciicast_range(
            &apcap[..],
            &mut range_out,
            0,
            200_000_000, // [0, 200ms) — includes first output, excludes second
        )
        .unwrap();

        assert!(
            range_n < full_n,
            "range ({range_n} events) must be fewer than full ({full_n} events)"
        );
        assert_eq!(range_n, 1, "exactly one PtyOutput in the window");
    }

    // ── extra: escape correctness ────────────────────────────────────────────

    #[test]
    fn escape_json_string_covers_all_cases() {
        // backslash, quote, control chars, ESC, tab, newline, carriage return, normal
        let input = b"\\\"\x01\x1b\t\n\rhello";
        let escaped = escape_json_string(input);
        assert!(escaped.contains("\\\\"), "backslash escaped");
        assert!(escaped.contains("\\\""), "double-quote escaped");
        assert!(escaped.contains("\\u0001"), "SOH → \\u0001");
        assert!(escaped.contains("\\u001b"), "ESC → \\u001b");
        assert!(escaped.contains("\\t"), "tab → \\t");
        assert!(escaped.contains("\\n"), "newline → \\n");
        assert!(escaped.contains("\\r"), "CR → \\r");
        assert!(escaped.ends_with("hello"), "plain chars pass through");
        // raw ESC byte must not appear
        assert!(!escaped.contains('\x1b'));
    }
}
