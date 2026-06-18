//! agentprov-pty-core — trusted PTY capture core.
//!
//! Spawns a child process under a PTY, transparently proxies stdin/stdout so
//! the user interacts normally, and records child output as APCAP frames via
//! `agentprov-capture-format`. Fail-open philosophy: if the PTY cannot be set
//! up, return a clear `Err`; once running, best-effort I/O errors are logged
//! but do not terminate the session.
//!
//! Only runs on Unix. Callers should `#[cfg(unix)]`-gate at a higher layer.

#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime};

use agentprov_capture_format::{FrameType, Writer};
use rustix::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use rustix::process::{waitpid, Pid, WaitOptions};
use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
use rustix::termios::{
    isatty, tcgetattr, tcgetwinsize, tcsetattr, tcsetwinsize, OptionalActions, Termios, Winsize,
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Configuration for a single capture session.
pub struct CaptureSession {
    command: PathBuf,
    args: Vec<String>,
    apcap_out: PathBuf,
}

/// The result returned from a successful capture run.
pub struct CaptureResult {
    /// The child process's exit code. Signal-killed children are mapped to
    /// `128 + signal_number`, mirroring shell convention.
    pub exit_code: i32,
    /// Total number of APCAP frames written (SessionStart + outputs + SessionEnd, etc.)
    pub frames_written: u64,
}

impl CaptureSession {
    /// Create a new session descriptor. Does not spawn anything yet.
    pub fn new(command: PathBuf, args: Vec<String>, apcap_out: PathBuf) -> Self {
        Self { command, args, apcap_out }
    }

    /// Spawn `command` under a PTY, proxy I/O, record frames, return exit code.
    pub fn run(self) -> io::Result<CaptureResult> {
        let session_start_mono = Instant::now();
        let session_start_wall = SystemTime::now();

        // ── helper: elapsed nanoseconds ──────────────────────────────────────
        let mono_ns = |now: Instant| -> u64 {
            now.duration_since(session_start_mono).as_nanos() as u64
        };
        let wall_ns = |now: SystemTime| -> u64 {
            now.duration_since(session_start_wall).unwrap_or_default().as_nanos() as u64
        };

        // ── open PTY master ──────────────────────────────────────────────────
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)
            .map_err(rustix_to_io)?;
        grantpt(&master).map_err(rustix_to_io)?;
        unlockpt(&master).map_err(rustix_to_io)?;

        // ptsname allocates — must happen before fork (no alloc in child).
        let slave_name = ptsname(&master, Vec::new()).map_err(rustix_to_io)?;

        // ── get initial window size ──────────────────────────────────────────
        // tcgetwinsize uses TIOCGWINSZ; falls back to 80x24 if stdin is not a tty.
        let stdin_bfd = rustix::stdio::stdin();
        let stdin_is_tty = isatty(stdin_bfd);
        let initial_winsize: Winsize = if stdin_is_tty {
            tcgetwinsize(stdin_bfd)
                .unwrap_or(Winsize { ws_col: 80, ws_row: 24, ws_xpixel: 0, ws_ypixel: 0 })
        } else {
            Winsize { ws_col: 80, ws_row: 24, ws_xpixel: 0, ws_ypixel: 0 }
        };
        // propagate initial size to PTY master
        let _ = tcsetwinsize(&master, initial_winsize);

        // ── open output file + Writer ────────────────────────────────────────
        let out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.apcap_out)?;
        let mut writer = Writer::new(out_file);
        let mut frames_written: u64 = 0;

        // ── prepare argv strings before fork (no allocation in child) ────────
        let cmd_cstr = std::ffi::CString::new(self.command.as_os_str().as_encoded_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let basename: String = self
            .command
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into());
        // SessionStart payload carries the session metadata the replay header
        // needs (a true superset of the Go cast): cmd, TERM, SHELL, and the
        // absolute wall-clock epoch (frame wall_ns is relative to capture start,
        // so we stamp the real start time here). key=value lines, opaque to the
        // frozen format. Newlines/`=` don't appear in these values in practice;
        // the parser is tolerant if they do (splits on first `=`).
        let epoch = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let term = std::env::var("TERM").unwrap_or_default();
        let shell = std::env::var("SHELL").unwrap_or_default();
        let start_meta = format!(
            "cmd={basename}\nterm={term}\nshell={shell}\nepoch={epoch}\n"
        );
        let basename_bytes = start_meta.into_bytes();
        let mut arg_cstrings: Vec<std::ffi::CString> = Vec::with_capacity(self.args.len() + 1);
        arg_cstrings.push(cmd_cstr.clone());
        for a in &self.args {
            arg_cstrings.push(
                std::ffi::CString::new(a.as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            );
        }
        let mut argv_ptrs: Vec<*const libc::c_char> =
            arg_cstrings.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        // ── write SessionStart ───────────────────────────────────────────────
        writer.write(
            FrameType::SessionStart,
            mono_ns(Instant::now()),
            wall_ns(SystemTime::now()),
            &basename_bytes,
        )?;
        frames_written += 1;

        // ── emit initial Resize frame ─────────────────────────────────────────
        // ponytail: We emit exactly one Resize at session start using the current
        // terminal size. Live SIGWINCH handling would require a self-pipe or a
        // signal crate, violating the dep-minimal constraint. A renderer that
        // needs to reflow can use this initial size as the canonical viewport.
        {
            let cols = initial_winsize.ws_col;
            let rows = initial_winsize.ws_row;
            let mut payload = [0u8; 4];
            payload[0..2].copy_from_slice(&cols.to_le_bytes());
            payload[2..4].copy_from_slice(&rows.to_le_bytes());
            writer.write(
                FrameType::Resize,
                mono_ns(Instant::now()),
                wall_ns(SystemTime::now()),
                &payload,
            )?;
            frames_written += 1;
        }

        // ── install raw-mode guard on our stdin ──────────────────────────────
        let raw_guard = RawModeGuard::new(stdin_is_tty);

        // ── master fd integer for libc calls ─────────────────────────────────
        let master_raw_fd = master.as_fd().as_raw_fd();

        // ── fork ─────────────────────────────────────────────────────────────
        // SAFETY: fork() is used correctly:
        //   - No Rust allocator calls happen in the child between fork and exec.
        //   - All CStrings for argv were prepared in the parent before fork.
        //   - The child calls only async-signal-safe operations (setsid, open,
        //     ioctl, dup2, execvp, _exit) after fork.
        //   - The child's copy of master fd is closed immediately in the child,
        //     so there is no double-close with the parent's OwnedFd Drop.
        // ASSUMPTION (load-bearing): the process is single-threaded at this
        //   point. fork() in a multithreaded process duplicates only the calling
        //   thread, leaving locks (incl. the allocator's) possibly held by a
        //   dead thread — making the post-fork code UB if it allocates. The CLI
        //   is single-threaded; if a future caller spawns threads before run(),
        //   this child path must be revisited (posix_spawn or a pre-forked helper).
        let child_pid = unsafe { libc::fork() };
        if child_pid < 0 {
            return Err(io::Error::last_os_error());
        }

        if child_pid == 0 {
            // ── CHILD ────────────────────────────────────────────────────────
            // Close master in child — we use the slave directly.
            // SAFETY: master_raw_fd is a valid fd that the fork copied; closing
            // it here does not affect the parent's OwnedFd.
            unsafe { libc::close(master_raw_fd) };

            // Create a new session; PTY slave will become the controlling terminal.
            // setsid() is async-signal-safe.
            unsafe { libc::setsid() };

            // Open slave PTY by name.
            // SAFETY: slave_name is a NUL-terminated CString from ptsname; the
            // path is valid for the lifetime of this process.
            let slave_fd = unsafe { libc::open(slave_name.as_ptr(), libc::O_RDWR) };
            if slave_fd < 0 {
                unsafe { libc::_exit(1) };
            }

            // Set slave as controlling terminal for this session.
            // SAFETY: TIOCSCTTY with 0 is correct POSIX usage.
            unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0i32) };

            // dup2 slave to stdin/stdout/stderr and close the extra copy.
            // SAFETY: slave_fd is a valid open fd; dup2 is async-signal-safe.
            unsafe {
                libc::dup2(slave_fd, 0);
                libc::dup2(slave_fd, 1);
                libc::dup2(slave_fd, 2);
                if slave_fd > 2 {
                    libc::close(slave_fd);
                }
            }

            // exec — replaces the process image.
            // SAFETY: cmd_cstr is a valid NUL-terminated path; argv_ptrs is a
            // NULL-sentinel-terminated array of valid NUL-terminated strings
            // pointing into arg_cstrings, which is alive on the (copied) stack.
            unsafe { libc::execvp(cmd_cstr.as_ptr(), argv_ptrs.as_ptr()) };

            // exec failed — exit with 127 (command not found convention).
            unsafe { libc::_exit(127) };
        }

        // ── PARENT ───────────────────────────────────────────────────────────
        // The parent must NOT hold an open slave fd, otherwise the master never
        // gets EIO/EOF when the child closes its session. We never opened the
        // slave in the parent (only the child did), so we're clean here.
        //
        // Note: the parent's OwnedFd `master` remains open; that's correct —
        // we read from it in the proxy loop below.

        // ── proxy loop ───────────────────────────────────────────────────────
        let stdin_raw_fd: i32 = 0; // fd 0
        let mut buf = vec![0u8; 65536]; // well under MAX_PAYLOAD (16 MiB)
        let mut stdin_open = stdin_is_tty; // only include stdin when it's a real tty

        loop {
            // Build pollfd set: always include master; include stdin only when
            // it is a tty (macOS poll can misbehave on /dev/null/pipes).
            let mut fds: [libc::pollfd; 2] = [
                libc::pollfd { fd: master_raw_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: stdin_raw_fd, events: libc::POLLIN, revents: 0 },
            ];
            let nfds: libc::nfds_t = if stdin_open { 2 } else { 1 };

            // SAFETY: fds is a valid array of pollfd; nfds <= fds.len().
            let ret =
                unsafe { libc::poll(fds.as_mut_ptr(), nfds, -1 /* block */) };
            if ret < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue; // EINTR — retry
                }
                break;
            }

            // ── master readable ───────────────────────────────────────────────
            if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                // SAFETY: master_raw_fd is open; buf is a valid writable slice.
                let n = unsafe {
                    libc::read(
                        master_raw_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n > 0 {
                    let data = &buf[..n as usize];
                    // Mirror to our stdout (best effort — ignore errors).
                    let _ = io::stdout().write_all(data);
                    let _ = io::stdout().flush();
                    // Record PtyOutput frame.
                    if writer
                        .write(
                            FrameType::PtyOutput,
                            mono_ns(Instant::now()),
                            wall_ns(SystemTime::now()),
                            data,
                        )
                        .is_ok()
                    {
                        frames_written += 1;
                    }
                } else if n == 0 {
                    // Clean EOF on master (Linux).
                    break;
                } else {
                    // n < 0: check errno.
                    // On macOS/BSD, EIO means the slave side closed — treat as
                    // end-of-stream, not a fatal error.
                    let raw_err = io::Error::last_os_error().raw_os_error();
                    if raw_err == Some(libc::EIO) || raw_err == Some(libc::EINVAL) {
                        break;
                    }
                    // Any other error: stop proxying, reap the child.
                    break;
                }
            }

            // ── stdin readable ────────────────────────────────────────────────
            if stdin_open && fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                // SAFETY: stdin is fd 0 (valid open fd); buf is writable.
                let n = unsafe {
                    libc::read(
                        stdin_raw_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n > 0 {
                    // Forward to PTY master (= child's stdin).
                    // SAFETY: master_raw_fd is open; buf[..n] is initialised.
                    let _ = unsafe {
                        libc::write(
                            master_raw_fd,
                            buf.as_ptr() as *const libc::c_void,
                            n as usize,
                        )
                    };
                } else {
                    // stdin EOF — stop forwarding; keep draining master.
                    stdin_open = false;
                }
            }
        }

        // ── restore terminal ──────────────────────────────────────────────────
        drop(raw_guard);

        // ── reap child ───────────────────────────────────────────────────────
        // child_pid > 0 is guaranteed by the fork() > 0 branch above.
        let child_pid_obj = Pid::from_raw(child_pid as i32)
            .expect("child_pid is positive after successful fork");

        let exit_code = match waitpid(Some(child_pid_obj), WaitOptions::empty()) {
            Ok(Some(status)) => {
                if let Some(code) = status.exit_status() {
                    code as i32
                } else if let Some(sig) = status.terminating_signal() {
                    128 + sig as i32
                } else {
                    1
                }
            }
            _ => 1,
        };

        // ── write SessionEnd ─────────────────────────────────────────────────
        let end_payload = format!("exit={exit_code}");
        writer.write(
            FrameType::SessionEnd,
            mono_ns(Instant::now()),
            wall_ns(SystemTime::now()),
            end_payload.as_bytes(),
        )?;
        frames_written += 1;

        Ok(CaptureResult { exit_code, frames_written })
    }
}

// ── Raw-mode guard ────────────────────────────────────────────────────────────

/// RAII guard that puts fd 0 into raw mode on construction and restores the
/// original `Termios` on drop. If fd 0 is not a tty, construction is a no-op.
struct RawModeGuard {
    saved: Option<(OwnedFd, Termios)>,
}

impl RawModeGuard {
    fn new(stdin_is_tty: bool) -> Self {
        if !stdin_is_tty {
            return Self { saved: None };
        }
        // Duplicate fd 0 into an OwnedFd so we can call rustix termios functions
        // that require AsFd, and so Drop can restore it even if fd 0 is later
        // remapped.
        // SAFETY: libc::dup(0) on a valid stdin fd produces a new owned fd.
        let owned = unsafe {
            let new_fd = libc::dup(0);
            if new_fd < 0 {
                return Self { saved: None };
            }
            OwnedFd::from_raw_fd(new_fd)
        };
        match tcgetattr(&owned) {
            Ok(old) => {
                let mut raw = old.clone();
                raw.make_raw();
                if tcsetattr(&owned, OptionalActions::Flush, &raw).is_err() {
                    return Self { saved: None };
                }
                Self { saved: Some((owned, old)) }
            }
            Err(_) => Self { saved: None },
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if let Some((ref fd, ref termios)) = self.saved {
            let _ = tcsetattr(fd, OptionalActions::Flush, termios);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rustix_to_io(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use agentprov_capture_format::{verify, FrameType as FT};

    /// End-to-end proof: spawn `/bin/sh -c 'printf hello'` under PTY capture,
    /// verify the resulting APCAP file, and assert the chain and content.
    #[test]
    fn echo_hello_captures_and_verifies() {
        let dir = std::env::temp_dir();
        let out_path = dir.join(format!("apcap_test_{}.apcap", std::process::id()));

        let session = CaptureSession::new(
            PathBuf::from("/bin/sh"),
            vec!["-c".to_string(), "printf hello".to_string()],
            out_path.clone(),
        );

        let result = session.run().expect("capture session should succeed");
        assert_eq!(result.exit_code, 0, "child should exit 0");
        assert!(
            result.frames_written >= 3,
            "need at least SessionStart + PtyOutput + SessionEnd, got {}",
            result.frames_written
        );

        // Read the captured file and verify the hash chain.
        let f = std::fs::File::open(&out_path).expect("output file should exist");
        let mut frames: Vec<(FT, Vec<u8>)> = Vec::new();
        let frame_count = verify(f, |frame| {
            frames.push((frame.frame_type, frame.payload.clone()));
        })
        .expect("verify should succeed — chain must be intact");

        assert!(frame_count >= 3, "expected >= 3 frames, got {frame_count}");

        // First frame is SessionStart.
        assert_eq!(frames[0].0, FT::SessionStart, "first frame must be SessionStart");
        // SessionStart payload is `key=value` metadata; it carries the command.
        let start = String::from_utf8_lossy(&frames[0].1);
        assert!(start.contains("cmd=sh"), "SessionStart should carry cmd=sh, got {start:?}");
        assert!(start.contains("epoch="), "SessionStart should carry an epoch");

        // Last frame is SessionEnd.
        let last = frames.last().expect("must have frames");
        assert_eq!(last.0, FT::SessionEnd, "last frame must be SessionEnd");
        assert!(
            last.1.starts_with(b"exit="),
            "SessionEnd payload should start with 'exit=', got {:?}",
            String::from_utf8_lossy(&last.1)
        );

        // Concatenated PtyOutput payloads must contain b"hello".
        let output_bytes: Vec<u8> = frames
            .iter()
            .filter(|(ft, _)| *ft == FT::PtyOutput)
            .flat_map(|(_, p)| p.iter().copied())
            .collect();
        assert!(
            output_bytes.windows(5).any(|w| w == b"hello"),
            "captured output should contain 'hello', got: {:?}",
            String::from_utf8_lossy(&output_bytes)
        );

        // Clean up.
        let _ = std::fs::remove_file(&out_path);
    }
}
