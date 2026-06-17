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
// We shim at the STABLE PATH NAME the user invokes (e.g. ~/.local/bin/claude),
// not the versioned binary it may symlink to — so a claude self-update that
// rewrites versions/ can't bypass the shim. We save the original (the symlink
// or binary) as <name>.agentprov-real and exec it from the shim.

const shimMarker = "# agentprov-claude-shim" // identifies our shim file

type claudeState struct {
	pathName string // the file on PATH the user invokes, e.g. ~/.local/bin/claude
	realSaved string // where we saved the original: <pathName>.agentprov-real
	isShim   bool   // pathName is already our shim
}

func inspectClaude() (claudeState, error) {
	p, err := exec.LookPath("claude")
	if err != nil {
		return claudeState{}, fmt.Errorf("claude not found on PATH: %w", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return claudeState{}, err
	}
	st := claudeState{pathName: abs, realSaved: abs + ".agentprov-real"}
	// Is the thing on PATH our shim? (read it if it's a regular file/script)
	if data, e := os.ReadFile(abs); e == nil && strings.Contains(string(data), shimMarker) {
		st.isShim = true
	}
	return st, nil
}

func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, e := filepath.EvalSymlinks(p); e == nil {
		return r, nil
	}
	return p, nil
}

func cmdInstall() error {
	st, err := inspectClaude()
	if err != nil {
		return err
	}
	if st.isShim {
		fmt.Println("agentprov: claude is already wrapped — auto-recording is active.")
		fmt.Println("  (run 'agentprov uninstall' to remove it.)")
		return nil
	}
	self, err := selfPath()
	if err != nil {
		return err
	}

	// Save the original claude (symlink OR binary) aside, preserving symlinks.
	// We move the PATH entry itself, then exec the saved copy from the shim.
	if _, e := os.Lstat(st.realSaved); e != nil { // don't clobber an existing save
		if e := os.Rename(st.pathName, st.realSaved); e != nil {
			return fmt.Errorf("could not move claude aside (need write to %s): %w",
				filepath.Dir(st.pathName), e)
		}
	}

	shim := shimScript(self, st.realSaved)
	if e := os.WriteFile(st.pathName, []byte(shim), 0o755); e != nil {
		_ = os.Rename(st.realSaved, st.pathName) // roll back
		return fmt.Errorf("could not write shim at %s: %w", st.pathName, e)
	}

	fmt.Printf("agentprov: auto-recording installed.\n")
	fmt.Printf("  shim          -> %s\n", st.pathName)
	fmt.Printf("  real claude   -> %s\n", st.realSaved)
	fmt.Printf("  every 'claude' and 'claude -p' session is now recorded transparently.\n")
	fmt.Printf("  artifacts: %s/<session-id>/\n", sessionsRoot())
	fmt.Printf("  list:  agentprov sessions      ·  reverse:  agentprov uninstall\n")
	return nil
}

func cmdUninstall() error {
	st, err := inspectClaude()
	if err != nil {
		// claude may not resolve if the shim is broken; try the known save path
		// relative to common locations isn't reliable, so just report.
		return fmt.Errorf("could not locate claude on PATH: %w", err)
	}
	if !st.isShim {
		fmt.Println("agentprov: claude is not wrapped — nothing to uninstall.")
		return nil
	}
	if _, e := os.Lstat(st.realSaved); e != nil {
		return fmt.Errorf("found shim at %s but no saved real claude at %s — refusing to delete the shim without the original",
			st.pathName, st.realSaved)
	}
	// remove the shim, restore the saved original to the PATH name.
	if e := os.Remove(st.pathName); e != nil {
		return fmt.Errorf("could not remove shim: %w", e)
	}
	if e := os.Rename(st.realSaved, st.pathName); e != nil {
		return fmt.Errorf("could not restore real claude (saved copy is at %s): %w", st.realSaved, e)
	}
	fmt.Println("agentprov: auto-recording removed — claude restored to normal.")
	return nil
}

// shimScript builds a FAIL-OPEN shim: it tries to record via agentprov, but if
// agentprov is missing or won't run, it falls through to the real claude so the
// user's claude NEVER breaks because of the recorder. A security tool that can
// take down the thing it watches is a non-starter for a fleet.
//
// Implementation: if agentprov is executable, exec it (it parents claude and
// records). Otherwise exec the real claude directly. We check executability
// with a cheap `[ -x ]` rather than running agentprov twice.
func shimScript(agentprovPath, realClaude string) string {
	ap := shellQuote(agentprovPath)
	rc := shellQuote(realClaude)
	return "#!/bin/sh\n" + shimMarker + "\n" +
		"# Transparent agentprov recorder for claude. Fail-open. Reverse: agentprov uninstall\n" +
		"if [ -x " + ap + " ]; then\n" +
		"  exec " + ap + " __shim " + rc + " \"$@\"\n" +
		"fi\n" +
		"# recorder unavailable — never break claude:\n" +
		"exec " + rc + " \"$@\"\n"
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// cmdShim is the runtime entry the shim execs: agentprov __shim <realclaude> <args...>
func cmdShim(args []string) error {
	if len(args) < 1 {
		return errors.New("__shim requires the real claude path")
	}
	return cmdRunRecorded(args)
}
