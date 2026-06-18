//! APCAP v0 — the native tamper-evident capture format.
//!
//! This crate is the *contract* the whole trusted path hashes against, so its
//! byte layout is frozen: change it and every existing capture fails to verify.
//! It has exactly one third-party dependency (`sha2`) and does no I/O of its own
//! beyond what the caller hands it via `Read`/`Write`.
//!
//! Frame wire layout (all integers little-endian):
//!
//! ```text
//! magic      : [u8; 4] = b"APC0"   (per-frame, so a truncated file is detectable)
//! version    : u8      = 0
//! frame_type : u8
//! seq        : u64
//! mono_ns    : u64     monotonic ns since capture start
//! wall_ns    : u64     wall-clock ns since capture start (for absolute timing)
//! payload_len: u32
//! payload    : [u8; payload_len]
//! payload_hash : [u8; 32]  sha256(payload)
//! prev_hash    : [u8; 32]  hash of the previous frame (zero for the first)
//! frame_hash   : [u8; 32]  sha256(everything above, prev_hash included)
//! ```
//!
//! `frame_hash` chains into the next frame's `prev_hash`, giving an append-only
//! integrity chain: altering any byte of any frame breaks every frame after it.
//!
//! # Threat model — read before trusting this
//!
//! This is a *keyless* hash chain. It detects **accidental corruption and naive
//! edits**, not a motivated adversary. There is no secret in the format, so
//! anyone with write access to the file (including the agent we claim to
//! distrust) can edit a frame, recompute its `payload_hash`/`frame_hash`, and
//! re-forge every downstream `prev_hash` — and [`verify`] will pass. Real
//! tamper-*evidence* requires signing the tip `frame_hash` with a key the
//! editor does not hold (ed25519, as the Go chain does). That signature lives
//! *outside* this frame stream (a `.sig`/manifest over the final hash), so it
//! can be added later without changing this frozen layout.
//!
//! Two consequences until the signed tip exists:
//!   1. The chain proves *consistency*, not *authenticity*.
//!   2. End-truncation is undetectable: chopping the last N frames leaves a
//!      valid prefix that still verifies (this is by design for crash
//!      resilience — a crash mid-capture must leave a verifiable file — so it
//!      can only be closed by anchoring the signed tip, not by the format).

use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAGIC: [u8; 4] = *b"APC0";
pub const VERSION: u8 = 0;
pub type Hash = [u8; 32];
pub const ZERO_HASH: Hash = [0u8; 32];

/// ponytail: bound every length we read from a file. Hostile-input rule from the
/// doc — a corrupt/malicious capture must not be able to make us allocate 4 GiB.
pub const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    SessionStart = 1,
    PtyOutput = 2,
    Resize = 3,
    InputMeta = 4,
    SessionEnd = 5,
}

impl FrameType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::SessionStart,
            2 => Self::PtyOutput,
            3 => Self::Resize,
            4 => Self::InputMeta,
            5 => Self::SessionEnd,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub seq: u64,
    pub mono_ns: u64,
    pub wall_ns: u64,
    pub payload: Vec<u8>,
    pub prev_hash: Hash,
    pub frame_hash: Hash,
}

impl Frame {
    /// Compute the frame hash over the canonical header + payload + prev_hash.
    /// Must match exactly between writer and verifier, so it's the one source.
    fn compute_hash(
        frame_type: FrameType,
        seq: u64,
        mono_ns: u64,
        wall_ns: u64,
        payload: &[u8],
        payload_hash: &Hash,
        prev_hash: &Hash,
    ) -> Hash {
        let mut h = Sha256::new();
        h.update(MAGIC);
        h.update([VERSION, frame_type as u8]);
        h.update(seq.to_le_bytes());
        h.update(mono_ns.to_le_bytes());
        h.update(wall_ns.to_le_bytes());
        h.update((payload.len() as u32).to_le_bytes());
        h.update(payload);
        h.update(payload_hash);
        h.update(prev_hash);
        h.finalize().into()
    }
}

fn sha256(b: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

/// Append-only writer. Holds only the running `prev_hash` and `seq` — no buffering,
/// so a crash mid-capture leaves a valid prefix of frames on disk.
pub struct Writer<W: Write> {
    w: W,
    prev_hash: Hash,
    seq: u64,
}

impl<W: Write> Writer<W> {
    pub fn new(w: W) -> Self {
        Self { w, prev_hash: ZERO_HASH, seq: 0 }
    }

    /// Write one frame, advancing the chain. Returns the frame's seq.
    pub fn write(
        &mut self,
        frame_type: FrameType,
        mono_ns: u64,
        wall_ns: u64,
        payload: &[u8],
    ) -> io::Result<u64> {
        if payload.len() as u64 > MAX_PAYLOAD as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload too large"));
        }
        let seq = self.seq;
        let payload_hash = sha256(payload);
        let frame_hash = Frame::compute_hash(
            frame_type, seq, mono_ns, wall_ns, payload, &payload_hash, &self.prev_hash,
        );

        self.w.write_all(&MAGIC)?;
        self.w.write_all(&[VERSION, frame_type as u8])?;
        self.w.write_all(&seq.to_le_bytes())?;
        self.w.write_all(&mono_ns.to_le_bytes())?;
        self.w.write_all(&wall_ns.to_le_bytes())?;
        self.w.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.w.write_all(payload)?;
        self.w.write_all(&payload_hash)?;
        self.w.write_all(&self.prev_hash)?;
        self.w.write_all(&frame_hash)?;
        self.w.flush()?;

        self.prev_hash = frame_hash;
        self.seq += 1;
        Ok(seq)
    }
}

#[derive(Debug)]
pub enum VerifyError {
    Io(io::Error),
    BadMagic(u64),
    BadVersion(u64),
    BadType(u64),
    PayloadTooLarge(u64),
    PayloadHashMismatch(u64),
    ChainBreak { seq: u64 },
    SeqGap { expected: u64, got: u64 },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::BadMagic(s) => write!(f, "frame {s}: bad magic"),
            Self::BadVersion(s) => write!(f, "frame {s}: bad version"),
            Self::BadType(s) => write!(f, "frame {s}: unknown frame type"),
            Self::PayloadTooLarge(s) => write!(f, "frame {s}: payload exceeds bound"),
            Self::PayloadHashMismatch(s) => write!(f, "frame {s}: payload hash mismatch"),
            Self::ChainBreak { seq } => write!(f, "frame {seq}: hash chain broken (tampered)"),
            Self::SeqGap { expected, got } => write!(f, "seq gap: expected {expected}, got {got}"),
        }
    }
}
impl std::error::Error for VerifyError {}

fn read_exact_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) if n == 0 => return Ok(false), // clean EOF on a frame boundary
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(k) => n += k,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Read + verify the whole stream, calling `each` with every valid frame in order.
/// Returns the frame count. Any tamper, truncation, or out-of-bound field is a hard
/// error with the offending seq — fail-closed verification, per the doc.
pub fn verify<R: Read>(mut r: R, mut each: impl FnMut(&Frame)) -> Result<u64, VerifyError> {
    let mut prev_hash = ZERO_HASH;
    let mut expected_seq = 0u64;
    let mut header = [0u8; 4 + 1 + 1 + 8 + 8 + 8 + 4];

    loop {
        match read_exact_eof(&mut r, &mut header) {
            Ok(false) => return Ok(expected_seq),
            Ok(true) => {}
            Err(e) => return Err(VerifyError::Io(e)),
        }
        let seq = expected_seq;
        if header[0..4] != MAGIC {
            return Err(VerifyError::BadMagic(seq));
        }
        if header[4] != VERSION {
            return Err(VerifyError::BadVersion(seq));
        }
        let frame_type = FrameType::from_u8(header[5]).ok_or(VerifyError::BadType(seq))?;
        // `header` is a fixed-size buffer filled by read_exact above; every
        // `header[a..b].try_into()` below converts a constant-width slice into a
        // constant-width array, so the unwraps are infallible (not input-dependent).
        let got_seq = u64::from_le_bytes(header[6..14].try_into().unwrap());
        if got_seq != expected_seq {
            return Err(VerifyError::SeqGap { expected: expected_seq, got: got_seq });
        }
        let mono_ns = u64::from_le_bytes(header[14..22].try_into().unwrap());
        let wall_ns = u64::from_le_bytes(header[22..30].try_into().unwrap());
        let payload_len = u32::from_le_bytes(header[30..34].try_into().unwrap());
        if payload_len > MAX_PAYLOAD {
            return Err(VerifyError::PayloadTooLarge(seq));
        }

        let mut payload = vec![0u8; payload_len as usize];
        read_exact_eof(&mut r, &mut payload)
            .map_err(VerifyError::Io)?
            .then_some(())
            .ok_or(VerifyError::Io(io::ErrorKind::UnexpectedEof.into()))?;

        let mut tail = [0u8; 96]; // payload_hash + prev_hash + frame_hash
        read_exact_eof(&mut r, &mut tail)
            .map_err(VerifyError::Io)?
            .then_some(())
            .ok_or(VerifyError::Io(io::ErrorKind::UnexpectedEof.into()))?;
        let stored_payload_hash: Hash = tail[0..32].try_into().unwrap();
        let stored_prev_hash: Hash = tail[32..64].try_into().unwrap();
        let stored_frame_hash: Hash = tail[64..96].try_into().unwrap();

        if sha256(&payload) != stored_payload_hash {
            return Err(VerifyError::PayloadHashMismatch(seq));
        }
        if stored_prev_hash != prev_hash {
            return Err(VerifyError::ChainBreak { seq });
        }
        let computed = Frame::compute_hash(
            frame_type, seq, mono_ns, wall_ns, &payload, &stored_payload_hash, &prev_hash,
        );
        if computed != stored_frame_hash {
            return Err(VerifyError::ChainBreak { seq });
        }

        each(&Frame {
            frame_type, seq, mono_ns, wall_ns, payload,
            prev_hash, frame_hash: stored_frame_hash,
        });

        prev_hash = stored_frame_hash;
        expected_seq += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write(FrameType::SessionStart, 0, 0, b"claude").unwrap();
        w.write(FrameType::PtyOutput, 100, 100, b"hello\r\n").unwrap();
        w.write(FrameType::Resize, 200, 200, &[0, 80, 0, 24]).unwrap();
        w.write(FrameType::SessionEnd, 300, 300, b"exit=0").unwrap();
        buf
    }

    #[test]
    fn roundtrip_verifies() {
        let buf = sample();
        let mut seen = Vec::new();
        let n = verify(&buf[..], |f| seen.push((f.frame_type, f.seq))).unwrap();
        assert_eq!(n, 4);
        assert_eq!(seen[0], (FrameType::SessionStart, 0));
        assert_eq!(seen[3], (FrameType::SessionEnd, 3));
    }

    #[test]
    fn naive_edit_breaks_chain() {
        let mut buf = sample();
        // flip a payload byte without recomputing hashes; chain must catch it.
        let i = buf.iter().position(|&b| b == b'h').unwrap();
        buf[i] ^= 0xff;
        let err = verify(&buf[..], |_| {}).unwrap_err();
        assert!(matches!(err, VerifyError::PayloadHashMismatch(_) | VerifyError::ChainBreak { .. }));
    }

    #[test]
    fn re_forged_chain_passes_documenting_the_limit() {
        // An adversary who edits a frame AND re-runs the writer produces a file
        // that verifies. This is the keyless-chain limitation, not a bug — it's
        // why the tip must be signed. This test pins that reality so nobody
        // mistakes `verify` passing for authenticity.
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.write(FrameType::SessionStart, 0, 0, b"claude").unwrap();
        w.write(FrameType::PtyOutput, 100, 100, b"EVIL OUTPUT").unwrap();
        w.write(FrameType::SessionEnd, 300, 300, b"exit=0").unwrap();
        assert_eq!(verify(&buf[..], |_| {}).unwrap(), 3); // forgery verifies
    }

    #[test]
    fn end_truncation_is_silently_accepted() {
        // Dropping whole trailing frames leaves a valid prefix (by design for
        // crash resilience). Documented limitation — closed only by a signed tip.
        let buf = sample();
        // Find the byte offset of the end of frame 0 by re-verifying with a stop.
        let mut frame0_end = 0usize;
        verify(&buf[..], |f| {
            if f.seq == 0 {
                // header(34) + payload(6 "claude") + 96 tail
                frame0_end = 34 + f.payload.len() + 96;
            }
        })
        .unwrap();
        // Truncate to just frame 0 — still verifies as a 1-frame file.
        assert_eq!(verify(&buf[..frame0_end], |_| {}).unwrap(), 1);
    }

    #[test]
    fn truncation_is_clean_at_boundary_else_error() {
        let buf = sample();
        // cut mid-frame → must error, not silently accept a short read.
        let err = verify(&buf[..buf.len() - 10], |_| {}).unwrap_err();
        assert!(matches!(err, VerifyError::Io(_)));
    }

    #[test]
    fn oversize_payload_len_rejected() {
        // hand-craft a header claiming a huge payload; must reject before alloc.
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(FrameType::PtyOutput as u8);
        buf.extend_from_slice(&0u64.to_le_bytes()); // seq
        buf.extend_from_slice(&0u64.to_le_bytes()); // mono
        buf.extend_from_slice(&0u64.to_le_bytes()); // wall
        buf.extend_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        let err = verify(&buf[..], |_| {}).unwrap_err();
        assert!(matches!(err, VerifyError::PayloadTooLarge(0)));
    }
}
