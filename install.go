package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Auto-capture install: agentprov transparently parents `claude` so every
// interactive `claude` and scripted `claude -p` session is recorded — the user
// runs claude exactly as before. We cannot read a PTY we don't parent (proven:
// the master fd is held by the terminal emulator), so transparent-parent is the
// only stock-macOS path to full session capture. One-time `agentprov install`
// (e.g. an MDM post-install script); `agentprov uninstall` reverses it.
//
// Mechanism: the real `claude` on PATH is a symlink/binary at some absolute
// path. We move it aside to `<dir>/claude.real` and replace `claude` with a
// shim that execs `agentprov __shim <claude.real> <args...>`. The shim resolves
// the real claude by ABSOLUTE path baked at install time, so there's no PATH
// ambiguity and no risk of the shim invoking itself.

const shimMarker = "# agentprov-claude-shim" // identifies our shim file

// resolveClaude returns the absolute path `claude` resolves to on PATH, plus
// whether it's already our shim.
func resolveClaude() (path string, isShim bool, err error) {
	p, err := exec.LookPath("claude")
	if err != nil {
		return "", false, fmt.Errorf("claude not found on PATH: %w", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false, err
	}
	// follow symlinks to the real target so we move the actual binary, not a link.
	if resolved, e := filepath.EvalSymlinks(abs); e == nil {
		abs = resolved
	}
	if data, e := os.ReadFile(abs); e == nil && strings.Contains(string(data), shimMarker) {
		return abs, true, nil
	}
	return abs, false, nil
}

func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func cmdInstall() error {
	claudePath, isShim, err := resolveClaude()
	if err != nil {
		return err
	}
	if isShim {
		fmt.Println("agentprov: claude is already wrapped — auto-recording is active.")
		fmt.Println("  (run 'agentprov uninstall' to remove it.)")
		return nil
	}
	self, err := selfPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(claudePath)
	realDest := filepath.Join(dir, "claude.real")
	// move the real claude aside (idempotent: if claude.real exists, keep it).
	if _, e := os.Stat(realDest); e != nil {
		if e := os.Rename(claudePath, realDest); e != nil {
			return fmt.Errorf("could not move real claude aside (need write to %s): %w", dir, e)
		}
	}

	// write the shim where `claude` was, pointing at the absolute real path.
	shim := shimScript(self, realDest)
	if e := os.WriteFile(claudePath, []byte(shim), 0o755); e != nil {
		_ = os.Rename(realDest, claudePath) // roll back the move
		return fmt.Errorf("could not write shim: %w", e)
	}

	fmt.Printf("agentprov: auto-recording installed.\n")
	fmt.Printf("  real claude   -> %s\n", realDest)
	fmt.Printf("  claude (shim) -> %s\n", claudePath)
	fmt.Printf("  every 'claude' and 'claude -p' session is now recorded transparently.\n")
	fmt.Printf("  artifacts: %s/<session-id>/\n", sessionsRoot())
	fmt.Printf("  reverse with: agentprov uninstall\n")
	return nil
}

func cmdUninstall() error {
	claudePath, isShim, err := resolveClaude()
	if err != nil {
		return err
	}
	dir := filepath.Dir(claudePath)
	realDest := filepath.Join(dir, "claude.real")
	if !isShim {
		// claude on PATH isn't our shim; maybe the shim is elsewhere — check the
		// dir that holds claude.real.
		if _, e := os.Stat(realDest); e != nil {
			fmt.Println("agentprov: no shim found — nothing to uninstall.")
			return nil
		}
	}
	if _, e := os.Stat(realDest); e != nil {
		return fmt.Errorf("found shim but not %s — refusing to delete claude without its real copy", realDest)
	}
	// remove the shim, restore the real claude to its original name.
	shimPath := filepath.Join(dir, "claude")
	if e := os.Remove(shimPath); e != nil {
		return fmt.Errorf("could not remove shim: %w", e)
	}
	if e := os.Rename(realDest, shimPath); e != nil {
		return fmt.Errorf("could not restore real claude: %w", e)
	}
	fmt.Println("agentprov: auto-recording removed — claude restored to normal.")
	return nil
}

// shimScript is a tiny shell shim: prints the monitored banner, then execs
// agentprov to transparently parent+record the real claude. It must pass every
// argument, stdin/stdout/tty, and the exit code through unchanged.
func shimScript(agentprovPath, realClaude string) string {
	return "#!/bin/sh\n" + shimMarker + "\n" +
		"# Transparent agentprov recorder for claude. Reverse: agentprov uninstall\n" +
		"exec " + shellQuote(agentprovPath) + " __shim " + shellQuote(realClaude) + " \"$@\"\n"
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// cmdShim is the runtime entry the shim execs: agentprov __shim <realclaude> <args...>
// It records the session via the existing PTY capture, transparently.
func cmdShim(args []string) error {
	if len(args) < 1 {
		return errors.New("__shim requires the real claude path")
	}
	// Hand off to the recording run, parenting the real claude with its args.
	return cmdRunRecorded(args)
}
