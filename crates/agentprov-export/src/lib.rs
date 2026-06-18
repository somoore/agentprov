//! agentprov-export — render an APCAP session to GIF or MP4.
//!
//! Pipeline: APCAP → (verify) → asciicast → (sanitize copy) → agg → gif → [ffmpeg → mp4].
//!
//! The signed APCAP and the derived `.cast` are **never modified**. We render
//! from a sanitized *copy* of the cast so the video looks right without altering
//! any evidence. See `sanitize_cast` for details.
//!
//! This is Tier-2 (optional convenience): a missing tool returns a friendly
//! `ExportError::ToolNotFound`, not a panic.

use agentprov_replay_core::{to_asciicast, ReplayError};
use std::{
    io,
    path::Path,
    process::Command,
};

// ── public types ────────────────────────────────────────────────────────────────

/// Output format requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Gif,
    Mp4,
}

/// All errors that can come out of [`render`].
#[derive(Debug)]
pub enum ExportError {
    /// APCAP verification or I/O error during the to_asciicast step.
    /// A tampered capture surfaces here — fail-closed by construction.
    Replay(ReplayError),
    /// A required external tool (`agg` or `ffmpeg`) was not found on PATH.
    ToolNotFound(String),
    /// A tool was found but returned a non-zero exit code.
    RenderFailed {
        tool: String,
        stderr: String,
    },
    /// General I/O error (temp file writes, etc.).
    Io(io::Error),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replay(e) => write!(f, "replay/verify failed: {e}"),
            Self::ToolNotFound(t) => write!(
                f,
                "{t} not found — install it to enable video export \
                 (brew install {t} on macOS)",
            ),
            Self::RenderFailed { tool, stderr } => {
                write!(f, "{tool} failed:\n{stderr}")
            }
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Replay(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ReplayError> for ExportError {
    fn from(e: ReplayError) -> Self {
        Self::Replay(e)
    }
}

impl From<io::Error> for ExportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── renderer availability ────────────────────────────────────────────────────────

/// Reports which optional rendering tools are on PATH.
#[derive(Debug)]
pub struct RenderersStatus {
    pub agg: bool,
    pub ffmpeg: bool,
}

/// Check whether each external renderer is available, for a `doctor`-style
/// preflight. Returns which of `agg` / `ffmpeg` can be found on PATH.
/// Never panics; a missing tool is simply `false`.
pub fn renderers_available() -> RenderersStatus {
    RenderersStatus {
        agg: tool_present("agg"),
        ffmpeg: tool_present("ffmpeg"),
    }
}

/// Probe for a tool by running `<tool> --version` and checking the result.
/// `NotFound` → false; any other exit (or success) → true (tool is present).
fn tool_present(tool: &str) -> bool {
    match Command::new(tool).arg("--version").output() {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

// ── sanitize ────────────────────────────────────────────────────────────────────

/// Replace every non-breaking space (U+00A0) with a regular space.
///
/// Invariant: the signed APCAP and its direct `.cast` derivative are NEVER
/// modified to improve render quality. This function is applied only to a
/// temporary render-only copy — the evidence is never touched.
///
/// Background: Claude Code's prompt emits U+00A0 (NBSP). The `agg` renderer
/// draws NBSP as a visible box glyph, producing noisy video. Replacing it with
/// a regular space in the render copy gives clean output without altering the
/// evidence chain. The Go version performs the exact same substitution on a
/// temp copy before calling agg.
pub fn sanitize_cast(s: &str) -> String {
    s.replace('\u{00A0}', " ")
}

// ── render ───────────────────────────────────────────────────────────────────────

/// Render the APCAP session at `apcap_path` to `out_path` in the requested format.
///
/// Pipeline:
///   1. [`to_asciicast`] verifies the full chain and produces a `.cast` (fail-closed:
///      a tampered APCAP returns [`ExportError::Replay`] before any rendering starts).
///   2. A sanitized copy of the cast (NBSP → space) is written to a temp file.
///      The original APCAP is opened read-only and never modified.
///   3. `agg` renders the sanitized cast to a GIF.
///   4. For `Format::Mp4`: `ffmpeg` converts the GIF to MP4.
///
/// Returns [`ExportError::ToolNotFound`] with a friendly message if `agg` (or
/// `ffmpeg` for MP4) are absent — this is an optional convenience feature.
pub fn render(apcap_path: &Path, out_path: &Path, format: Format) -> Result<(), ExportError> {
    // ── step 1: verify APCAP and produce a cast in memory ───────────────────
    let apcap_file = std::fs::File::open(apcap_path)?;
    let mut cast_buf: Vec<u8> = Vec::new();
    to_asciicast(apcap_file, &mut cast_buf)?;

    // ── step 2: sanitize into a temp cast copy — NEVER touch the signed evidence ──
    // Invariant: the APCAP and the raw `.cast` are evidence; we render from a
    // derived, cosmetically-cleaned copy only (ponytail: one Replace, no full parse).
    let cast_str = String::from_utf8_lossy(&cast_buf);
    let sanitized = sanitize_cast(&cast_str);

    let pid = std::process::id();
    let stem = out_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("render");
    let tmp_cast = std::env::temp_dir().join(format!("agentprov-{stem}-{pid}.cast"));
    std::fs::write(&tmp_cast, sanitized.as_bytes())?;

    // ── step 3: agg renders the sanitized cast → gif ─────────────────────────
    if !tool_present("agg") {
        let _ = std::fs::remove_file(&tmp_cast);
        return Err(ExportError::ToolNotFound("agg".into()));
    }

    // Gif destination: for Gif format use out_path directly; for Mp4 use a temp gif.
    let gif_path = match format {
        Format::Gif => out_path.to_path_buf(),
        Format::Mp4 => std::env::temp_dir().join(format!("agentprov-{stem}-{pid}.gif")),
    };

    // agg invocation — matches the Go version exactly:
    //   agg --fps-cap 30 --idle-time-limit 2 --font-size 16 <cast> <gif>
    let agg_out = Command::new("agg")
        .args(["--fps-cap", "30", "--idle-time-limit", "2", "--font-size", "16"])
        .arg(&tmp_cast)
        .arg(&gif_path)
        .output()?;
    let _ = std::fs::remove_file(&tmp_cast);

    if !agg_out.status.success() {
        if format == Format::Mp4 {
            let _ = std::fs::remove_file(&gif_path);
        }
        return Err(ExportError::RenderFailed {
            tool: "agg".into(),
            stderr: String::from_utf8_lossy(&agg_out.stderr).into_owned(),
        });
    }

    if format == Format::Gif {
        return Ok(());
    }

    // ── step 4: ffmpeg converts gif → mp4 ────────────────────────────────────
    // ffmpeg invocation — matches the Go version exactly:
    //   ffmpeg -y -i <gif> -movflags +faststart -pix_fmt yuv420p
    //          -vf scale=trunc(iw/2)*2:trunc(ih/2)*2 <mp4>
    if !tool_present("ffmpeg") {
        let _ = std::fs::remove_file(&gif_path);
        return Err(ExportError::ToolNotFound("ffmpeg".into()));
    }

    let ff_out = Command::new("ffmpeg")
        .args(["-y", "-i"])
        .arg(&gif_path)
        .args([
            "-movflags", "+faststart",
            "-pix_fmt", "yuv420p",
            "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
        ])
        .arg(out_path)
        .output()?;
    let _ = std::fs::remove_file(&gif_path);

    if !ff_out.status.success() {
        return Err(ExportError::RenderFailed {
            tool: "ffmpeg".into(),
            stderr: String::from_utf8_lossy(&ff_out.stderr).into_owned(),
        });
    }

    Ok(())
}

// ── tests ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── test 1: renderers_available never panics and returns well-defined bools ──

    #[test]
    fn renderers_available_runs_without_panic() {
        let s = renderers_available();
        // The exact values depend on what's installed in CI; just assert the type
        // is usable and the fields are well-defined booleans.
        let _agg: bool = s.agg;
        let _ffmpeg: bool = s.ffmpeg;
        // No assertion on values — we're proving it runs cleanly, not what's installed.
    }

    // ── test 2: sanitize_cast replaces U+00A0 and leaves normal text untouched ──

    #[test]
    fn sanitize_cast_replaces_nbsp() {
        // U+00A0 (NBSP) — the char Claude Code's prompt emits that agg renders as a box.
        let input = "a\u{00A0}b";
        let got = sanitize_cast(input);
        assert_eq!(got, "a b", "NBSP must become a regular space");
        assert!(!got.contains('\u{00A0}'), "output must contain no NBSP");
    }

    #[test]
    fn sanitize_cast_leaves_normal_text_untouched() {
        let input = "hello world\nno nbsp here";
        let got = sanitize_cast(input);
        assert_eq!(got, input, "plain text must pass through unchanged");
    }

    #[test]
    fn sanitize_cast_handles_multiple_nbsp() {
        let input = "\u{00A0}x\u{00A0}y\u{00A0}";
        let got = sanitize_cast(input);
        assert_eq!(got, " x y ", "all NBSP chars must be replaced");
    }

    // ── test 3: render either succeeds (agg present) or returns ToolNotFound ──
    //    (never panics regardless of which tools are installed)

    #[test]
    fn render_is_fail_closed_on_valid_apcap() {
        use agentprov_capture_format::{FrameType, Writer};

        // Build a minimal valid APCAP in memory.
        let mut apcap_buf = Vec::new();
        let mut w = Writer::new(&mut apcap_buf);
        let resize_payload = {
            let mut p = [0u8; 4];
            p[0..2].copy_from_slice(&80u16.to_le_bytes());
            p[2..4].copy_from_slice(&24u16.to_le_bytes());
            p
        };
        w.write(FrameType::SessionStart, 0, 0, b"claude").unwrap();
        w.write(FrameType::Resize, 1_000_000, 1_000_000, &resize_payload).unwrap();
        // Include a NBSP to exercise the sanitize path.
        w.write(FrameType::PtyOutput, 2_000_000, 2_000_000, "hello\u{00A0}world\r\n".as_bytes()).unwrap();
        w.write(FrameType::SessionEnd, 3_000_000, 3_000_000, b"exit=0").unwrap();

        // Write the APCAP to a temp file.
        let pid = std::process::id();
        let tmp_apcap = std::env::temp_dir().join(format!("agentprov-test-{pid}.apcap"));
        let tmp_gif = std::env::temp_dir().join(format!("agentprov-test-{pid}.gif"));
        std::fs::write(&tmp_apcap, &apcap_buf).unwrap();

        let status = renderers_available();
        let result = render(&tmp_apcap, &tmp_gif, Format::Gif);

        // Clean up regardless of outcome.
        let _ = std::fs::remove_file(&tmp_apcap);
        let _ = std::fs::remove_file(&tmp_gif);

        if status.agg {
            // agg is present: render must succeed.
            assert!(
                result.is_ok(),
                "render should succeed when agg is present: {result:?}"
            );
        } else {
            // agg is absent: must get a friendly ToolNotFound, not a panic.
            match result {
                Err(ExportError::ToolNotFound(t)) => {
                    assert_eq!(t, "agg", "ToolNotFound must name agg");
                }
                other => panic!(
                    "expected ToolNotFound(\"agg\") when agg is absent, got: {other:?}"
                ),
            }
        }
    }

    // ── test 4: render on a tampered APCAP returns Replay error ──────────────

    #[test]
    fn render_on_tampered_apcap_returns_replay_error() {
        use agentprov_capture_format::{FrameType, Writer};

        let mut apcap_buf = Vec::new();
        let mut w = Writer::new(&mut apcap_buf);
        w.write(FrameType::SessionStart, 0, 0, b"claude").unwrap();
        w.write(FrameType::PtyOutput, 1_000_000, 1_000_000, b"hello").unwrap();
        w.write(FrameType::SessionEnd, 2_000_000, 2_000_000, b"exit=0").unwrap();

        // Tamper: flip a byte inside the PtyOutput payload without updating hashes.
        let h_pos = apcap_buf.iter().position(|&b| b == b'h').unwrap();
        apcap_buf[h_pos] ^= 0xff;

        let pid = std::process::id();
        let tmp = std::env::temp_dir().join(format!("agentprov-tamper-test-{pid}.apcap"));
        let tmp_out = std::env::temp_dir().join(format!("agentprov-tamper-out-{pid}.gif"));
        std::fs::write(&tmp, &apcap_buf).unwrap();

        let result = render(&tmp, &tmp_out, Format::Gif);
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&tmp_out);

        assert!(
            matches!(result, Err(ExportError::Replay(_))),
            "a tampered APCAP must return ExportError::Replay, got: {result:?}"
        );
    }
}
