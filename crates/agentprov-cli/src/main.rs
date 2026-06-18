use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process;

use agentprov_capture_format::{verify, FrameType};
use agentprov_integrity::{self as integrity, KeySource, Signing, VerifyTip};
use agentprov_pty_core::CaptureSession;

/// Re-walk an APCAP file and return (frame_count, tip_frame_hash). The tip is
/// the last frame's frame_hash — signing it commits to the whole chain incl.
/// frame count, so truncation and forgery both break the signature.
fn read_tip(path: &Path) -> Result<(u64, [u8; 32]), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {path:?}: {e}"))?;
    let mut tip = [0u8; 32];
    let n = verify(BufReader::new(file), |f| tip = f.frame_hash)
        .map_err(|e| format!("{e}"))?;
    if n == 0 {
        return Err("empty capture (no frames)".into());
    }
    Ok((n, tip))
}

/// Sidecar paths: `<capture>.pub` and `<capture>.sig` (outside the frame stream,
/// so the frozen format is untouched).
fn sidecars(apcap: &Path) -> (PathBuf, PathBuf) {
    let mut p = apcap.as_os_str().to_owned();
    p.push(".pub");
    let mut s = apcap.as_os_str().to_owned();
    s.push(".sig");
    (PathBuf::from(p), PathBuf::from(s))
}

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

struct RunArgs {
    out: PathBuf,
    command: PathBuf,
    args: Vec<String>,
}

/// Parse the argv slice for the `run` subcommand.
///
/// Expected shapes:
///   run [--out <path>] -- <command> [args...]
///
/// Everything after `--` is the child command + its args.
/// Returns `Err(msg)` for any bad input (missing `--`, empty command, etc.).
fn parse_run_args(argv: &[String]) -> Result<RunArgs, String> {
    // argv[0] is "run" — skip it.
    let rest = &argv[1..];

    // Find the `--` separator.
    let dash_pos = rest
        .iter()
        .position(|s| s == "--")
        .ok_or_else(|| "run: missing `--` before command".to_string())?;

    // Parse our flags (everything before `--`).
    let our_flags = &rest[..dash_pos];
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < our_flags.len() {
        match our_flags[i].as_str() {
            "--out" => {
                i += 1;
                let val = our_flags
                    .get(i)
                    .ok_or_else(|| "--out requires a value".to_string())?;
                out = Some(PathBuf::from(val));
            }
            other => {
                return Err(format!("run: unknown flag `{other}`"));
            }
        }
        i += 1;
    }

    // Everything after `--` is the child command.
    let child = &rest[dash_pos + 1..];
    if child.is_empty() {
        return Err("run: no command specified after `--`".to_string());
    }

    Ok(RunArgs {
        out: out.unwrap_or_else(|| PathBuf::from("session.apcap")),
        command: PathBuf::from(&child[0]),
        args: child[1..].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Subcommand: run
// ---------------------------------------------------------------------------

fn cmd_run(argv: &[String]) {
    let run_args = match parse_run_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("agentprov-rs: {e}");
            usage();
            process::exit(2);
        }
    };

    let out_path = run_args.out.clone();
    let session = CaptureSession::new(run_args.command, run_args.args, run_args.out);
    let result = match session.run() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agentprov-rs: failed to run capture session: {e}");
            process::exit(1);
        }
    };

    eprintln!(
        "agentprov-rs: captured {} frames to {} (exit {})",
        result.frames_written,
        out_path.display(),
        result.exit_code,
    );

    // Sign the chain tip — this is what makes the capture tamper-EVIDENT rather
    // than merely consistency-checked. Best-effort: a signing failure must not
    // change the child's exit code or lose the capture (the frames are already
    // on disk). We warn and continue.
    match read_tip(&out_path) {
        Ok((_, tip)) => {
            let signer = Signing::load_or_create();
            let (pub_path, sig_path) = sidecars(&out_path);
            let sig = signer.sign_tip(&tip);
            let pub_hex = integrity::to_hex(&signer.public_key());
            let sig_hex = integrity::to_hex(&sig);
            let w1 = std::fs::write(&pub_path, &pub_hex);
            let w2 = std::fs::write(&sig_path, &sig_hex);
            match (w1, w2) {
                (Ok(()), Ok(())) => {
                    let src = match signer.source {
                        KeySource::Keychain => "keychain-bound",
                        KeySource::Ephemeral => "EPHEMERAL (not non-repudiable — keychain unavailable)",
                    };
                    eprintln!("agentprov-rs: signed tip with {src} key → {}", sig_path.display());
                }
                _ => eprintln!("agentprov-rs: warning: could not write signature sidecars"),
            }
        }
        Err(e) => eprintln!("agentprov-rs: warning: could not sign capture: {e}"),
    }

    process::exit(result.exit_code);
}

// ---------------------------------------------------------------------------
// Subcommand: verify
// ---------------------------------------------------------------------------

fn cmd_verify(argv: &[String]) {
    // argv = ["verify", [--pubkey <hex>], <path>]
    // --pubkey pins the trusted signing key for off-machine (responder) verify,
    // obtained out-of-band. Without it, on-machine verify falls back to the
    // keychain key. The bundled .pub is NEVER trusted on its own.
    let mut pinned_pub: Option<Vec<u8>> = None;
    let mut path: Option<PathBuf> = None;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--pubkey" => {
                i += 1;
                match argv.get(i).and_then(|h| integrity::from_hex(h)) {
                    Some(b) => pinned_pub = Some(b),
                    None => {
                        eprintln!("agentprov-rs: --pubkey requires a valid hex key");
                        process::exit(2);
                    }
                }
            }
            other if other.starts_with("--") => {
                eprintln!("agentprov-rs: verify: unknown flag `{other}`");
                process::exit(2);
            }
            p => path = Some(PathBuf::from(p)),
        }
        i += 1;
    }
    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("agentprov-rs: verify requires a path argument");
            usage();
            process::exit(2);
        }
    };

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("agentprov-rs: cannot open {:?}: {e}", path);
            process::exit(1);
        }
    };
    let reader = BufReader::new(file);

    // Accumulators — declared before the closure so the borrow checker is happy.
    let mut counts = [0u64; 6]; // indexed by FrameType discriminant (1-based → subtract 1)
    let mut session_start_payload: Option<Vec<u8>> = None;
    let mut session_end_payload: Option<Vec<u8>> = None;
    let mut pty_output_bytes: u64 = 0;
    let mut tip = [0u8; 32];

    let total = verify(reader, |frame| {
        tip = frame.frame_hash;
        let idx = (frame.frame_type as u8).saturating_sub(1) as usize;
        if idx < counts.len() {
            counts[idx] += 1;
        }
        match frame.frame_type {
            FrameType::SessionStart => {
                if session_start_payload.is_none() {
                    session_start_payload = Some(frame.payload.clone());
                }
            }
            FrameType::PtyOutput => {
                pty_output_bytes += frame.payload.len() as u64;
            }
            FrameType::SessionEnd => {
                session_end_payload = Some(frame.payload.clone());
            }
            _ => {}
        }
    });

    match total {
        Err(e) => {
            eprintln!("agentprov-rs: verify failed: {e}");
            process::exit(1);
        }
        Ok(n) => {
            println!("OK: {} verified — {} frames, {} output bytes", path.display(), n, pty_output_bytes);
            println!();
            println!("Frame counts:");
            let type_names = ["SessionStart", "PtyOutput", "Resize", "InputMeta", "SessionEnd"];
            for (i, &c) in counts[..5].iter().enumerate() {
                if c > 0 {
                    println!("  {}: {}", type_names[i], c);
                }
            }
            println!();
            if let Some(payload) = session_start_payload {
                println!("SessionStart: {}", String::from_utf8_lossy(&payload));
            } else {
                println!("SessionStart: (none)");
            }
            if let Some(payload) = session_end_payload {
                println!("SessionEnd:   {}", String::from_utf8_lossy(&payload));
            } else {
                println!("SessionEnd:   (none)");
            }

            // Signature check. The chain alone is keyless (consistency only);
            // the signed tip catches re-forging and truncation. CRITICAL: the
            // trust anchor is NOT the bundled .pub — an attacker writes that
            // file. We verify against a TRUSTED key: the --pubkey pin (responder,
            // out-of-band) or this machine's keychain key. The bundled .pub alone
            // is never enough to say VALID.
            println!();
            let (pub_path, sig_path) = sidecars(&path);
            let bundled_pub = std::fs::read_to_string(&pub_path).ok().and_then(|h| integrity::from_hex(&h));
            let sig = std::fs::read_to_string(&sig_path).ok().and_then(|h| integrity::from_hex(&h));

            let sig = match sig {
                Some(s) => s,
                None => {
                    println!("SIGNATURE: UNSIGNED — chain is consistent but not authenticated (no .sig)");
                    process::exit(0);
                }
            };

            // Resolve the trusted key, in priority order.
            let (trusted_pub, anchor) = match pinned_pub {
                Some(p) => (Some(p), "pinned --pubkey"),
                None => match integrity::keychain_public_key() {
                    Some(k) => (Some(k.to_vec()), "machine keychain"),
                    None => (None, ""),
                },
            };

            let trusted_pub = match trusted_pub {
                None => {
                    // No trusted anchor available: we cannot authenticate. Report
                    // UNTRUSTED — never VALID off a bundled key alone.
                    println!("SIGNATURE: UNTRUSTED — capture is signed but no trusted key to check it");
                    println!("  pass --pubkey <hex> (obtained out-of-band) to authenticate off-machine");
                    process::exit(0);
                }
                Some(k) => k,
            };

            // If a .pub is bundled, it must match the trusted key — a mismatch
            // means the capture was signed by someone other than the trusted
            // recorder (the re-sign attack).
            if let Some(bp) = &bundled_pub {
                if bp != &trusted_pub {
                    eprintln!("SIGNATURE: INVALID — bundled key does not match trusted {anchor} (re-signed by another key)");
                    process::exit(1);
                }
            }

            match integrity::verify_tip(&tip, &trusted_pub, &sig) {
                VerifyTip::Valid => {
                    println!("SIGNATURE: VALID — tip signed by trusted {anchor}; chain is tamper-evident");
                    process::exit(0);
                }
                VerifyTip::BadSignature => {
                    eprintln!("SIGNATURE: INVALID — tip does not match trusted {anchor} (forged, truncated, or re-signed)");
                    process::exit(1);
                }
                VerifyTip::BadKeyOrSig => {
                    eprintln!("SIGNATURE: malformed key or signature");
                    process::exit(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Help / usage
// ---------------------------------------------------------------------------

fn usage() {
    eprintln!("Usage:");
    eprintln!("  agentprov-rs run [--out <path>] -- <command> [args...]");
    eprintln!("      Capture a terminal session to an APCAP file.");
    eprintln!("      Default --out is session.apcap in the current directory.");
    eprintln!("      Exits with the child's exit code.");
    eprintln!();
    eprintln!("  agentprov-rs verify [--pubkey <hex>] <path>");
    eprintln!("      Verify the APCAP hash chain and the signed tip.");
    eprintln!("      Trust anchor: --pubkey (out-of-band) > machine keychain.");
    eprintln!("      The bundled .pub is never trusted on its own.");
    eprintln!();
    eprintln!("  agentprov-rs help");
    eprintln!("      Show this message.");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // argv[0] is the binary name.
    match argv.get(1).map(String::as_str) {
        Some("run") => cmd_run(&argv[1..]),
        Some("verify") => cmd_verify(&argv[1..]),
        Some("help") => {
            usage();
            process::exit(0);
        }
        Some(other) => {
            eprintln!("agentprov-rs: unknown subcommand `{other}`");
            usage();
            process::exit(2);
        }
        None => {
            eprintln!("agentprov-rs: no subcommand given");
            usage();
            process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the `--` splitter correctly separates our flags from the child command.
    #[test]
    fn run_arg_split() {
        let argv: Vec<String> = ["run", "--out", "x.apcap", "--", "claude", "-p", "hi"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let parsed = parse_run_args(&argv).expect("should parse");
        assert_eq!(parsed.out, PathBuf::from("x.apcap"));
        assert_eq!(parsed.command, PathBuf::from("claude"));
        assert_eq!(parsed.args, vec!["-p".to_string(), "hi".to_string()]);
    }

    #[test]
    fn run_default_out() {
        let argv: Vec<String> = ["run", "--", "echo", "hello"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let parsed = parse_run_args(&argv).expect("should parse");
        assert_eq!(parsed.out, PathBuf::from("session.apcap"));
        assert_eq!(parsed.command, PathBuf::from("echo"));
        assert_eq!(parsed.args, vec!["hello".to_string()]);
    }

    #[test]
    fn run_missing_double_dash() {
        let argv: Vec<String> = ["run", "--out", "x.apcap", "claude"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&argv).is_err());
    }

    #[test]
    fn run_empty_command_after_dash() {
        let argv: Vec<String> = ["run", "--"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(parse_run_args(&argv).is_err());
    }
}
