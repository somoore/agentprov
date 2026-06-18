//! Auto-capture install: shim `claude` on PATH so every `claude` / `claude -p`
//! session is PTY-recorded + signed by agentprov-rs. A hook can't do this — it
//! runs inside the already-started claude and can't read a PTY it doesn't
//! parent. Transparent-parent shim is the only stock path to full capture.
//!
//! Ported from the Go install.go: shim at the STABLE PATH NAME (so a claude
//! self-update can't bypass it), save the original as `<name>.agentprov-real`,
//! and make the shim FAIL-OPEN — if agentprov is missing it execs real claude,
//! so claude never breaks because of the recorder.

use std::path::{Path, PathBuf};
use std::process::Command;

// Distinct from the Go recorder's `# agentprov-claude-shim` marker so we can
// tell OUR shim apart from a stale Go one and replace it instead of no-op'ing.
const SHIM_MARKER: &str = "# agentprov-rs-claude-shim";
// Any agentprov shim (Go or Rust) contains this substring — used to detect a
// foreign/old shim we should replace.
const ANY_SHIM_MARKER: &str = "agentprov";

struct ClaudeState {
    path_name: PathBuf,  // the file on PATH the user invokes
    real_saved: PathBuf, // where we save the original: <path>.agentprov-real
    is_our_shim: bool,   // path_name is already OUR (rust) shim
    is_any_shim: bool,   // path_name is some agentprov shim (incl. a stale Go one)
}

fn inspect_claude() -> Result<ClaudeState, String> {
    // Use the PATH entry itself, NOT its canonicalized target — we shim the
    // stable name the user types so a version bump can't slip past us.
    let out = Command::new("sh")
        .args(["-c", "command -v claude"])
        .output()
        .map_err(|e| format!("looking up claude: {e}"))?;
    let path_name = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    if path_name.as_os_str().is_empty() {
        return Err("claude not found on PATH".into());
    }
    let mut real_saved = path_name.clone().into_os_string();
    real_saved.push(".agentprov-real");
    let real_saved = PathBuf::from(real_saved);

    let contents = std::fs::read_to_string(&path_name).unwrap_or_default();
    // A shim is a small shell script; the real claude is a binary/symlink that
    // won't read as a script containing our marker. is_any_shim catches a stale
    // Go shim (whose marker line mentions "agentprov ... shim").
    let is_our_shim = contents.contains(SHIM_MARKER);
    let is_any_shim = contents.contains(ANY_SHIM_MARKER) && contents.contains("claude-shim");
    Ok(ClaudeState { path_name, real_saved, is_our_shim, is_any_shim })
}

fn self_path() -> Result<PathBuf, String> {
    let p = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(std::fs::canonicalize(&p).unwrap_or(p))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// FAIL-OPEN shim: try agentprov, fall through to real claude if it's missing.
fn shim_script(agentprov: &Path, real_claude: &Path) -> String {
    let ap = shell_quote(&agentprov.to_string_lossy());
    let rc = shell_quote(&real_claude.to_string_lossy());
    // FAIL-OPEN: a `[ -x ]` check passes for a PRESENT-BUT-BROKEN binary
    // (corrupt, panicking, or SIGKILLed — e.g. a bad codesign). Since `exec`
    // replaces this shell, if we exec'd a dead agentprov the fallback line would
    // never run and claude would never launch. So we PROBE first: run
    // `agentprov __probe` (exits 0 if the binary is alive); only if that
    // succeeds do we hand off. A dead binary fails the probe and falls through
    // to running the real claude directly. Costs one fast spawn per launch.
    format!(
        "#!/bin/sh\n{SHIM_MARKER}\n\
         # Transparent agentprov recorder for claude. Fail-open. Reverse: agentprov-rs uninstall\n\
         if [ -x {ap} ] && {ap} __probe >/dev/null 2>&1; then\n  exec {ap} __shim {rc} \"$@\"\nfi\n\
         # recorder unavailable or unhealthy — never break claude:\nexec {rc} \"$@\"\n"
    )
}

pub fn install() -> Result<(), String> {
    let st = inspect_claude()?;
    if st.is_our_shim {
        // Already our shim — refresh it so it points at the current binary path
        // (e.g. after the binary moved), but report it as already-active.
        println!("agentprov-rs: claude is already wrapped by agentprov-rs.");
        println!("  (refreshing the shim to the current binary path.)");
    } else if st.is_any_shim {
        // A FOREIGN shim (e.g. a stale Go agentprov). The real claude lives in
        // its .agentprov-real, NOT in the shim file. Restore it, then re-shim.
        println!("agentprov-rs: found a non-agentprov-rs shim — replacing it.");
        if std::fs::symlink_metadata(&st.real_saved).is_ok() {
            // remove the foreign shim, restore the real claude it saved.
            std::fs::remove_file(&st.path_name)
                .map_err(|e| format!("could not remove foreign shim: {e}"))?;
            std::fs::rename(&st.real_saved, &st.path_name)
                .map_err(|e| format!("could not restore real claude from {}: {e}", st.real_saved.display()))?;
        } else {
            return Err(format!(
                "found a foreign shim at {} but no saved real claude at {} — refusing to touch it; uninstall the other recorder first",
                st.path_name.display(), st.real_saved.display()
            ));
        }
    }
    let self_exe = self_path()?;

    // Move the PATH entry (symlink or binary) aside, preserving it.
    if std::fs::symlink_metadata(&st.real_saved).is_err() {
        std::fs::rename(&st.path_name, &st.real_saved)
            .map_err(|e| format!("could not move claude aside (need write to its dir): {e}"))?;
    }

    let shim = shim_script(&self_exe, &st.real_saved);
    if let Err(e) = write_executable(&st.path_name, &shim) {
        let _ = std::fs::rename(&st.real_saved, &st.path_name); // roll back
        return Err(format!("could not write shim at {}: {e}", st.path_name.display()));
    }

    println!("agentprov: auto-recording installed.");
    println!("  shim        -> {}", st.path_name.display());
    println!("  real claude -> {}", st.real_saved.display());
    println!("  every 'claude' / 'claude -p' session is now recorded + signed.");
    println!("  reverse: agentprov-rs uninstall");
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let st = inspect_claude()?;
    if !st.is_our_shim {
        println!("agentprov: claude is not wrapped by agentprov-rs — nothing to uninstall.");
        // Still offer to clean a stale saved-original left by a prior install.
        if std::fs::symlink_metadata(&st.real_saved).is_ok() {
            println!("  note: a stale {} exists; remove it manually if unwanted.", st.real_saved.display());
        }
        return Ok(());
    }
    if std::fs::symlink_metadata(&st.real_saved).is_err() {
        return Err(format!(
            "found shim at {} but no saved real claude at {} — refusing to delete the shim without the original",
            st.path_name.display(), st.real_saved.display()
        ));
    }
    std::fs::remove_file(&st.path_name).map_err(|e| format!("could not remove shim: {e}"))?;
    std::fs::rename(&st.real_saved, &st.path_name)
        .map_err(|e| format!("could not restore real claude (saved at {}): {e}", st.real_saved.display()))?;
    println!("agentprov: auto-recording removed — claude restored to normal.");
    Ok(())
}

fn write_executable(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

/// Runtime entry the shim execs: `agentprov-rs __shim <real-claude> <args...>`.
/// Records into ~/.agentprov/sessions/<id>/ and returns claude's exit code.
pub fn shim(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("agentprov-rs: __shim requires the real claude path");
        return 2;
    }
    let real = PathBuf::from(&args[0]);
    // ORIGINAL claude args, exactly as the user typed them. This is what we run
    // on ANY fail-open fallback — never the --session-id-injected version, so a
    // bad injection can't taint the fallback.
    let orig_args: Vec<String> = args[1..].to_vec();

    // Session dir under ~/.agentprov/sessions/<id>. Fail-open: if we can't even
    // make the dir, run claude raw.
    let root = sessions_root();
    let id = session_id();
    let dir = root.join(&id);
    if std::fs::create_dir_all(&dir).is_err() {
        return exec_real(&real, &orig_args);
    }
    let apcap = dir.join("session.apcap");

    // Pin the transcript: inject --session-id <uuid> so we can find the EXACT
    // transcript claude writes and build the signed semantic chain.jsonl. Skip
    // if the user already passed a session flag (don't override --resume etc).
    let mut claude_args = orig_args.clone();
    let session_uuid = if looks_like_claude(&real) && !has_session_flag(&claude_args) {
        let u = new_uuid();
        claude_args.insert(0, format!("--session-id={u}"));
        Some(u)
    } else {
        None
    };

    // FAIL-OPEN: if PTY capture can't even START (capture_and_sign Err is
    // PRE-fork only — pty-core never returns Err once the child started, so this
    // can't double-run claude), run claude RAW with the ORIGINAL args so the
    // user's claude never fails to launch because of the recorder OR a bad
    // --session-id injection.
    let code = match crate::capture_and_sign(&real, &claude_args, &apcap, true) {
        Ok(code) => code,
        Err(_) => return exec_real(&real, &orig_args),
    };

    // --session-id guard: if WE injected the flag and claude exited nonzero
    // having produced almost no output, claude likely rejected --session-id
    // (e.g. a future version dropped it). Re-run ONCE with the original args so
    // the user's command still works. The tiny-output guard prevents re-running
    // on a legitimate nonzero exit (where claude actually ran and produced a
    // real session) — that would be a double-run. apcap_output_bytes reads the
    // capture's recorded output size.
    if session_uuid.is_some() && code != 0 && apcap_output_bytes(&apcap) < 64 {
        return exec_real(&real, &orig_args);
    }

    // Write session.cast (apcap → asciicast) for the viewer's "Real recording"
    // tab + video render. Best-effort, silent.
    let cast = dir.join("session.cast");
    if let Ok(apcap_f) = std::fs::File::open(&apcap) {
        if let Ok(cast_f) = std::fs::File::create(&cast) {
            let _ = agentprov_replay_core::to_asciicast(
                std::io::BufReader::new(apcap_f),
                std::io::BufWriter::new(cast_f),
            );
        }
    }

    // Build the signed semantic chain from the transcript, binding the cast in
    // (so the viewer shows both tabs). Best-effort, silent.
    if let Some(uuid) = session_uuid {
        if let Some(transcript) = find_transcript(&uuid) {
            let cast_arg = cast.exists().then_some(cast.as_path());
            let _ = agentprov_chain::record_transcript_with_cast(&transcript, &dir, cast_arg);
        }
    }
    code
}

/// True if `path` is (a renamed) claude — handles claude.agentprov-real etc.
fn looks_like_claude(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("claude"))
        .unwrap_or(false)
}

/// Don't inject a session id if the user already chose one.
fn has_session_flag(args: &[String]) -> bool {
    args.iter().any(|a| {
        matches!(a.as_str(), "--session-id" | "--resume" | "-r" | "--continue" | "-c" | "--fork-session")
            || a.starts_with("--session-id=")
            || a.starts_with("--resume=")
    })
}

/// Random v4 UUID, no external dep.
fn new_uuid() -> String {
    let mut b = [0u8; 16];
    // getrandom would be a dep; use the OS via /dev/urandom-equivalent: std has
    // no RNG, but agentprov-integrity already pulls rand_core/getrandom. Reuse it.
    // (capture_and_sign already links it; this keeps the dep surface flat.)
    if getrandom_fill(&mut b).is_err() {
        // fail-open: a non-random id still pins a unique-enough path via pid+time.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let p = std::process::id();
        return format!("agentprov-{t:x}-{p:x}");
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]
    )
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    // Read from /dev/urandom — std-only, no dep.
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|_| ())
}

/// Find the transcript claude wrote for `uuid`. Claude encodes the cwd into the
/// projects dir name (slashes → dashes), so we scan ~/.claude/projects/*/ for
/// <uuid>.jsonl rather than reconstruct the exact encoding.
fn find_transcript(uuid: &str) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let projects = PathBuf::from(home).join(".claude").join("projects");
    let target = format!("{uuid}.jsonl");
    for entry in std::fs::read_dir(&projects).ok()?.flatten() {
        let cand = entry.path().join(&target);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Captured terminal-output bytes in an apcap (0 if it can't be read/verified).
/// Used by the --session-id guard to tell "claude bailed immediately" from "real
/// session that happened to exit nonzero".
fn apcap_output_bytes(apcap: &Path) -> u64 {
    std::fs::File::open(apcap)
        .ok()
        .and_then(|f| agentprov_replay_core::summarize(std::io::BufReader::new(f)).ok())
        .map(|s| s.output_bytes)
        .unwrap_or(0)
}

fn exec_real(real: &Path, args: &[String]) -> i32 {
    // Last-resort fail-open: run claude unrecorded, preserve exit code.
    Command::new(real)
        .args(args)
        .status()
        .map(|s| s.code().unwrap_or(0))
        .unwrap_or(0)
}

pub fn sessions_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".agentprov").join("sessions")
}

fn session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}-{}", std::process::id())
}

/// Launch the original two-tab flight-recorder viewer on `chain`. That UI
/// (viewer.html) is served by the Go `agentprov` binary, which serves
/// /chain + /cast + /video the page expects. We shell to it rather than
/// re-implement a working viewer. Looks for the Go binary next to ours.
pub fn launch_flight_recorder(chain: &Path) -> Result<(), String> {
    let self_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    // Candidate names for the Go viewer binary.
    let candidates = [
        self_dir.join("agentprov.go-old"),
        self_dir.join("agentprov-go"),
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("github/agentprov/agentprov"),
    ];
    let go = candidates.iter().find(|p| p.is_file()).ok_or_else(|| {
        format!(
            "the flight-recorder viewer (Go binary) was not found.\n  Looked in: {}\n  Build it: cd <agentprov repo> && go build -o ~/.local/bin/agentprov.go-old .",
            candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        )
    })?;
    // Exec `<go> view <chain>` — it serves viewer.html, binds loopback, opens the
    // browser, and blocks. Inherit stdio so its URL print reaches the user.
    let status = Command::new(go)
        .arg("view")
        .arg(chain)
        .status()
        .map_err(|e| format!("launching viewer: {e}"))?;
    if !status.success() {
        return Err(format!("viewer exited with status {status}"));
    }
    Ok(())
}

/// Newest recorded session's `session.apcap`, if any. Lets `view`/`verify`/`cast`
/// default to "the session I just recorded" with no path argument.
pub fn latest_apcap() -> Option<PathBuf> {
    let rd = std::fs::read_dir(sessions_root()).ok()?;
    let mut dirs: Vec<_> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("session.apcap").exists())
        .collect();
    dirs.sort();
    dirs.pop().map(|d| d.join("session.apcap"))
}

/// List recorded sessions, newest first.
pub fn list_sessions() {
    let root = sessions_root();
    let Ok(rd) = std::fs::read_dir(&root) else {
        println!("agentprov: no sessions yet ({})", root.display());
        return;
    };
    let mut dirs: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    dirs.reverse();
    if dirs.is_empty() {
        println!("agentprov: no sessions yet ({})", root.display());
        return;
    }
    println!("recorded sessions ({}):", root.display());
    for d in dirs {
        let apcap = d.join("session.apcap");
        let mark = if apcap.exists() { "✓" } else { "·" };
        println!("  {mark} {}", d.file_name().unwrap_or_default().to_string_lossy());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_script_probes_before_handoff() {
        // The shim MUST probe the binary's health before `exec`ing it — a
        // present-but-dead binary (corrupt/SIGKILLed) would otherwise break
        // claude with no fallback (exec doesn't return).
        let s = shim_script(Path::new("/bin/agentprov"), Path::new("/bin/claude.real"));
        assert!(s.contains("__probe"), "shim must probe before handoff:\n{s}");
        // The fallback exec of real claude must still be present for when the
        // probe (or -x) fails.
        assert!(s.contains("exec '/bin/claude.real'"), "shim must fall through to real claude");
        // Probe must gate the handoff with && (short-circuit), not run regardless.
        assert!(s.contains("__probe >/dev/null 2>&1; then"), "probe must gate the exec");
    }

    #[test]
    fn session_flag_detection() {
        // We must NOT inject --session-id when the user already chose a session.
        assert!(has_session_flag(&["--resume".into()]));
        assert!(has_session_flag(&["-c".into()]));
        assert!(has_session_flag(&["--session-id=abc".into()]));
        assert!(has_session_flag(&["--continue".into()]));
        // A plain prompt run has no session flag → injection is allowed.
        assert!(!has_session_flag(&["-p".into(), "hello".into()]));
        assert!(!has_session_flag(&[]));
    }
}
