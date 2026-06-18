mod install;

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

/// The authenticity verdict for a capture — the SAME check `verify` runs, so
/// every surface that displays content (cast/view/export) agrees with `verify`
/// instead of trusting the keyless chain alone. Without this, a re-forged
/// capture renders cleanly in the viewer while `verify` rejects it.
enum Auth {
    /// Signed tip matches a trusted key (keychain or --pubkey).
    Valid,
    /// Signed but no trusted key on hand to check it (off-machine, no pin).
    Untrusted,
    /// No signature sidecar at all.
    Unsigned,
    /// Signature present but does not match the trusted key — forged/re-signed.
    Invalid(String),
}

/// Resolve trust and authenticate the capture's signed tip. `pinned_pub` is the
/// optional `--pubkey` (responder, out-of-band); otherwise the machine keychain
/// is the anchor. The bundled `.pub` is never trusted on its own.
fn authenticate(path: &Path, pinned_pub: Option<Vec<u8>>) -> Auth {
    let (_, tip) = match read_tip(path) {
        Ok(t) => t,
        Err(e) => return Auth::Invalid(e),
    };
    let (pub_path, sig_path) = sidecars(path);
    let sig = match std::fs::read_to_string(&sig_path).ok().and_then(|h| integrity::from_hex(&h)) {
        Some(s) => s,
        None => return Auth::Unsigned,
    };
    let trusted = match pinned_pub {
        Some(p) => p,
        None => match integrity::keychain_public_key() {
            Some(k) => k.to_vec(),
            None => return Auth::Untrusted,
        },
    };
    let bundled = std::fs::read_to_string(&pub_path).ok().and_then(|h| integrity::from_hex(&h));
    if let Some(bp) = &bundled {
        if bp != &trusted {
            return Auth::Invalid("bundled key does not match trusted key (re-signed)".into());
        }
    }
    match integrity::verify_tip(&tip, &trusted, &sig) {
        VerifyTip::Valid => Auth::Valid,
        VerifyTip::BadSignature => Auth::Invalid("tip does not match trusted key (forged or truncated)".into()),
        VerifyTip::BadKeyOrSig => Auth::Invalid("malformed key or signature".into()),
    }
}

/// Gate a content-displaying surface (cast/export) on authentication. Refuses to
/// render an INVALID capture outright; refuses UNSIGNED/UNTRUSTED unless the
/// caller passed `--allow-unsigned` (and then prints a loud warning). This keeps
/// cast/export honest about what they're showing.
fn gate_or_exit(path: &Path, pinned_pub: Option<Vec<u8>>, allow_unsigned: bool) {
    match authenticate(path, pinned_pub) {
        Auth::Valid => {}
        Auth::Invalid(why) => {
            eprintln!("agentprov-rs: REFUSING — capture failed authentication: {why}");
            process::exit(1);
        }
        Auth::Unsigned if allow_unsigned => {
            eprintln!("agentprov-rs: WARNING — capture is unsigned (consistency only, not authenticated)");
        }
        Auth::Untrusted if allow_unsigned => {
            eprintln!("agentprov-rs: WARNING — capture signed but no trusted key to check it");
        }
        Auth::Unsigned | Auth::Untrusted => {
            eprintln!("agentprov-rs: REFUSING — capture is not authenticated; pass --allow-unsigned to view anyway");
            process::exit(1);
        }
    }
}

/// Pull `--pubkey <hex>` and `--allow-unsigned` out of a subcommand's args,
/// returning (pin, allow_unsigned, positional_args).
fn split_auth_flags(argv: &[String]) -> (Option<Vec<u8>>, bool, Vec<String>) {
    let mut pin = None;
    let mut allow = false;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--pubkey" => {
                i += 1;
                pin = argv.get(i).and_then(|h| integrity::from_hex(h));
                if pin.is_none() {
                    eprintln!("agentprov-rs: --pubkey requires a valid hex key");
                    process::exit(2);
                }
            }
            "--allow-unsigned" => allow = true,
            other => rest.push(other.to_string()),
        }
        i += 1;
    }
    (pin, allow, rest)
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
    match capture_and_sign(&run_args.command, &run_args.args, &run_args.out, false) {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("agentprov-rs: failed to run capture session: {e}");
            process::exit(1);
        }
    }
}

/// Capture `command` under a PTY into `out`, then sign the chain tip. Returns the
/// child's exit code. Used by both `run` and the install shim. Signing is
/// best-effort — a signing failure never changes the child's exit code or loses
/// the capture (the frames are already on disk). Returns Err only if the PTY
/// capture itself couldn't start.
pub(crate) fn capture_and_sign(
    command: &Path,
    args: &[String],
    out: &Path,
    quiet: bool,
) -> Result<i32, String> {
    let session = CaptureSession::new(command.to_path_buf(), args.to_vec(), out.to_path_buf());
    let result = session.run().map_err(|e| e.to_string())?;

    if !quiet {
        eprintln!(
            "agentprov-rs: captured {} frames to {} (exit {})",
            result.frames_written, out.display(), result.exit_code,
        );
    }

    match read_tip(out) {
        Ok((_, tip)) => {
            let signer = Signing::load_or_create();
            let (pub_path, sig_path) = sidecars(out);
            let sig = signer.sign_tip(&tip);
            let w1 = std::fs::write(&pub_path, integrity::to_hex(&signer.public_key()));
            let w2 = std::fs::write(&sig_path, integrity::to_hex(&sig));
            match (w1, w2) {
                (Ok(()), Ok(())) if !quiet => {
                    let src = match signer.source {
                        KeySource::Keychain => "keychain-bound",
                        KeySource::Ephemeral => "EPHEMERAL (not non-repudiable — keychain unavailable)",
                    };
                    eprintln!("agentprov-rs: signed tip with {src} key → {}", sig_path.display());
                }
                (Ok(()), Ok(())) => {}
                _ => eprintln!("agentprov-rs: warning: could not write signature sidecars"),
            }
        }
        Err(e) if !quiet => eprintln!("agentprov-rs: warning: could not sign capture: {e}"),
        Err(_) => {}
    }
    Ok(result.exit_code)
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
    let path = match path.or_else(install::latest_apcap) {
        Some(p) => p,
        None => {
            eprintln!("agentprov-rs: verify [--pubkey <hex>] [<path>] (no sessions recorded yet)");
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
// Subcommand: cast  (APCAP -> asciicast v2 on stdout; chain-verified)
// ---------------------------------------------------------------------------

fn cmd_cast(argv: &[String]) {
    let (pin, allow_unsigned, rest) = split_auth_flags(&argv[1..]);
    let path = match rest.first() {
        Some(p) => PathBuf::from(p),
        None => match install::latest_apcap() {
            Some(p) => p,
            None => {
                eprintln!("agentprov-rs: cast [--pubkey <hex>] [--allow-unsigned] [<path>]");
                process::exit(2);
            }
        },
    };
    gate_or_exit(&path, pin, allow_unsigned);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("agentprov-rs: cannot open {path:?}: {e}");
            process::exit(1);
        }
    };
    let stdout = std::io::stdout();
    match agentprov_replay_core::to_asciicast(BufReader::new(file), stdout.lock()) {
        Ok(_) => process::exit(0),
        Err(e) => {
            eprintln!("agentprov-rs: cast failed (capture may be tampered): {e}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand: view  (serve the capture in a hardened loopback viewer)
// ---------------------------------------------------------------------------

fn cmd_view(argv: &[String]) {
    let (pin, allow_unsigned, rest) = split_auth_flags(&argv[1..]);
    let path = match rest.first() {
        Some(p) => PathBuf::from(p),
        None => match install::latest_apcap() {
            Some(p) => p,
            None => {
                eprintln!("agentprov: view [--pubkey <hex>] [--allow-unsigned] [<path>]");
                eprintln!("  (no path given and no recorded sessions found)");
                process::exit(2);
            }
        },
    };
    // Authenticate the signed tip BEFORE serving — the viewer must agree with
    // `verify`, not just the keyless chain. A re-forged capture is refused here.
    gate_or_exit(&path, pin, allow_unsigned);
    // serve() binds, prints the URL, and blocks. We open the browser to that URL
    // a moment after it binds so the user doesn't copy/paste (and risk grabbing a
    // stale viewer's URL). serve() owns the URL print; we add nothing else.
    if let Err(e) = agentprov_viewer::serve_and_open(path) {
        eprintln!("agentprov: viewer failed: {e}");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Subcommand: export  (APCAP -> gif/mp4 via agg/ffmpeg; chain-verified)
// ---------------------------------------------------------------------------

fn cmd_export(argv: &[String]) {
    // export [--pubkey <hex>] [--allow-unsigned] <gif|mp4> <apcap> <out>
    let (pin, allow_unsigned, rest) = split_auth_flags(&argv[1..]);
    let (fmt, apcap, out) = match (rest.first(), rest.get(1), rest.get(2)) {
        (Some(f), Some(a), Some(o)) => (f.as_str(), PathBuf::from(a), PathBuf::from(o)),
        _ => {
            eprintln!("agentprov-rs: export [--pubkey <hex>] [--allow-unsigned] <gif|mp4> <apcap> <out>");
            process::exit(2);
        }
    };
    gate_or_exit(&apcap, pin, allow_unsigned);
    let format = match fmt {
        "gif" => agentprov_export::Format::Gif,
        "mp4" => agentprov_export::Format::Mp4,
        other => {
            eprintln!("agentprov-rs: export format must be gif or mp4, got `{other}`");
            process::exit(2);
        }
    };
    match agentprov_export::render(&apcap, &out, format) {
        Ok(()) => {
            eprintln!("agentprov-rs: rendered {} -> {}", apcap.display(), out.display());
            process::exit(0);
        }
        Err(e) => {
            eprintln!("agentprov-rs: export failed: {e}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand: flows  (normalize agentsnitch events -> flows.jsonl overlay)
// ---------------------------------------------------------------------------

fn cmd_flows(argv: &[String]) {
    // flows <agentsnitch-events.jsonl> [out-dir]
    let events = match argv.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("agentprov-rs: flows <events.jsonl> [out-dir]");
            process::exit(2);
        }
    };
    let file = match std::fs::File::open(&events) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("agentprov-rs: cannot open {events:?}: {e}");
            process::exit(1);
        }
    };
    let flows = agentprov_collectors::parse_flows(BufReader::new(file));
    eprintln!("agentprov-rs: normalized {} outbound flow(s)", flows.len());
    if let Some(dir) = argv.get(2) {
        use agentprov_collectors::EvidenceSink;
        let mut sink = agentprov_collectors::LocalDirectorySink::new(PathBuf::from(dir));
        if let Err(e) = sink.write_flows(&flows).and_then(|()| sink.finalize()) {
            eprintln!("agentprov-rs: writing overlay failed: {e}");
            process::exit(1);
        }
        eprintln!("agentprov-rs: wrote flows.jsonl + flows.hash to {dir}");
    } else {
        // No out-dir: print the hash so the overlay can be committed to the chain.
        println!("overlay_hash: {}", agentprov_collectors::overlay_hash(&flows));
    }
    process::exit(0);
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
    eprintln!("  agentprov-rs cast [--pubkey <hex>] [--allow-unsigned] <path>");
    eprintln!("      Convert an authenticated APCAP to asciicast v2 on stdout.");
    eprintln!();
    eprintln!("  agentprov-rs view [--pubkey <hex>] [--allow-unsigned] <path>");
    eprintln!("      Serve an authenticated capture in a hardened loopback viewer.");
    eprintln!();
    eprintln!("  agentprov-rs export [--pubkey <hex>] [--allow-unsigned] <gif|mp4> <apcap> <out>");
    eprintln!("      Render an authenticated capture to gif/mp4 (needs agg/ffmpeg).");
    eprintln!();
    eprintln!("      cast/view/export refuse a forged or unauthenticated capture;");
    eprintln!("      --allow-unsigned downgrades unsigned/untrusted to a warning.");
    eprintln!();
    eprintln!("  agentprov-rs flows <events.jsonl> [out-dir]");
    eprintln!("      Normalize agentsnitch network events into a flow overlay.");
    eprintln!();
    eprintln!("  agentprov-rs install | uninstall");
    eprintln!("      Shim (or un-shim) claude on PATH so every session is auto-recorded.");
    eprintln!();
    eprintln!("  agentprov-rs sessions");
    eprintln!("      List auto-recorded sessions under ~/.agentprov/sessions/.");
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
        Some("cast") => cmd_cast(&argv[1..]),
        Some("view") => cmd_view(&argv[1..]),
        Some("export") => cmd_export(&argv[1..]),
        Some("flows") => cmd_flows(&argv[1..]),
        Some("install") => match install::install() {
            Ok(()) => process::exit(0),
            Err(e) => { eprintln!("agentprov-rs: install failed: {e}"); process::exit(1); }
        },
        Some("uninstall") => match install::uninstall() {
            Ok(()) => process::exit(0),
            Err(e) => { eprintln!("agentprov-rs: uninstall failed: {e}"); process::exit(1); }
        },
        // __shim is the runtime entry the installed shim execs; it records the
        // session and exits with claude's exit code.
        Some("__shim") => process::exit(install::shim(&argv[2..])),
        Some("sessions") => { install::list_sessions(); process::exit(0); }
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

    /// Regression: cast/view/export gate on `authenticate`, which must REFUSE a
    /// re-forged capture (the milestone-2 hole, one layer out). An honest signed
    /// capture authenticates against the pinned key; a re-forged + re-signed one
    /// is rejected because the bundled key no longer matches the trusted key.
    #[test]
    fn authenticate_refuses_reforged_capture() {
        use agentprov_capture_format::{FrameType, Writer};
        use agentprov_integrity::Signing;

        let dir = std::env::temp_dir().join(format!("apcap-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let honest = dir.join("honest.apcap");

        // Build + sign an honest capture with the "real recorder" key.
        let recorder = Signing::from_seed([1u8; 32]);
        let mut tip = [0u8; 32];
        {
            let f = std::fs::File::create(&honest).unwrap();
            let mut w = Writer::new(f);
            w.write(FrameType::SessionStart, 0, 0, b"claude").unwrap();
            w.write(FrameType::PtyOutput, 1, 1, b"real").unwrap();
            w.write(FrameType::SessionEnd, 2, 2, b"exit=0").unwrap();
        }
        verify(BufReader::new(std::fs::File::open(&honest).unwrap()), |fr| tip = fr.frame_hash).unwrap();
        let (pp, sp) = sidecars(&honest);
        std::fs::write(&pp, integrity::to_hex(&recorder.public_key())).unwrap();
        std::fs::write(&sp, integrity::to_hex(&recorder.sign_tip(&tip))).unwrap();

        let recorder_pub = recorder.public_key().to_vec();
        // Honest capture authenticates against the recorder's pinned key.
        assert!(matches!(authenticate(&honest, Some(recorder_pub.clone())), Auth::Valid));

        // Attacker re-forges: same bytes but re-signs with their OWN key and
        // overwrites the bundled sidecars.
        let forged = dir.join("forged.apcap");
        std::fs::copy(&honest, &forged).unwrap();
        let attacker = Signing::from_seed([9u8; 32]);
        let mut ftip = [0u8; 32];
        verify(BufReader::new(std::fs::File::open(&forged).unwrap()), |fr| ftip = fr.frame_hash).unwrap();
        let (fpp, fsp) = sidecars(&forged);
        std::fs::write(&fpp, integrity::to_hex(&attacker.public_key())).unwrap();
        std::fs::write(&fsp, integrity::to_hex(&attacker.sign_tip(&ftip))).unwrap();

        // Against the trusted recorder key, the re-signed forgery is rejected.
        assert!(matches!(authenticate(&forged, Some(recorder_pub)), Auth::Invalid(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
