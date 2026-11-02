package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestChain writes a signed, clean-exit chain into dir. If withPub, it also
// writes the matching chain.pub beside it (the shape a recorder leaves behind).
func buildTestChain(t *testing.T, dir string, priv ed25519.PrivateKey, withPub bool) string {
	t.Helper()
	path := filepath.Join(dir, "chain.jsonl")
	f, err := createEvidenceFile(path)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}
	rec := newRecorder(bufio.NewWriter(f), priv)
	rec.emit(Node{Op: "heartbeat", Summary: "recorder start", Attrs: map[string]string{"key": "test"}})
	rec.emit(Node{Op: "prompt", Summary: "prompt", Detail: "hello", Trust: "trusted"})
	rec.emit(Node{Op: "heartbeat", Summary: "recorder end (clean exit)"})
	rec.w.Flush()
	if err := f.Close(); err != nil {
		t.Fatalf("close chain: %v", err)
	}
	if withPub {
		pub := priv.Public().(ed25519.PublicKey)
		if err := os.WriteFile(filepath.Join(dir, "chain.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0o600); err != nil {
			t.Fatalf("write pub: %v", err)
		}
	}
	return path
}

func testKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

// captureStdout runs fn with stdout redirected so tests can assert on what a
// security CLI actually claimed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	ferr := fn()
	w.Close()
	os.Stdout = old
	return <-done, ferr
}

// TestForgedChainRejectedByTrustedAnchor is the regression for the forge: a
// chain re-hashed and re-signed with a fresh key, with its own chain.pub sitting
// beside it, must NOT verify against the real recorder key.
func TestForgedChainRejectedByTrustedAnchor(t *testing.T) {
	dir := t.TempDir()
	attacker := testKey(0xAA)
	victim := testKey(0xBB)
	path := buildTestChain(t, dir, attacker, true)

	victimHex := hex.EncodeToString(victim.Public().(ed25519.PublicKey))
	out, err := captureStdout(t, func() error {
		return cmdVerifyWith(path, victimHex, false)
	})
	if err == nil {
		t.Fatal("forged chain verified against the trusted key — fail-open regression")
	}
	if strings.Contains(out, "signatures valid") {
		t.Fatalf("verify claimed signatures valid for a forged chain: %q", out)
	}
}

// TestNoAnchorFailsClosed: with no --pubkey the only anchor is the keychain. A
// test key cannot match it, so verification must fail and must never print
// "signatures valid". This is the default `verify <session>/chain.jsonl` path
// that used to skip signing entirely when ./chain.pub was absent.
func TestNoAnchorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := buildTestChain(t, dir, testKey(0xCC), false)

	out, err := captureStdout(t, func() error {
		return cmdVerifyWith(path, "", false)
	})
	if err == nil {
		t.Fatal("verify succeeded without a trust anchor — fail-open regression")
	}
	if strings.Contains(out, "signatures valid") {
		t.Fatalf("verify claimed signatures valid without checking any anchor: %q", out)
	}
}

// TestCWDPubIsNotTheAnchor: a chain.pub in the current directory must not become
// the trust anchor. The old code loaded "./chain.pub" from CWD.
func TestCWDPubIsNotTheAnchor(t *testing.T) {
	chainDir := t.TempDir()
	key := testKey(0xDD)
	path := buildTestChain(t, chainDir, key, false) // no pub next to the chain

	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "chain.pub"), []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)

	out, err := captureStdout(t, func() error {
		return cmdVerifyWith(path, "", false)
	})
	if err == nil {
		t.Fatal("CWD chain.pub was trusted as the verification anchor")
	}
	if strings.Contains(out, "signatures valid") {
		t.Fatalf("verify claimed signatures valid from a CWD pub: %q", out)
	}
}

// TestExplicitAnchorVerifies proves the documented escape hatch works: a
// responder-supplied --pubkey authenticates a clean chain off-machine.
func TestExplicitAnchorVerifies(t *testing.T) {
	dir := t.TempDir()
	key := testKey(0xEE)
	path := buildTestChain(t, dir, key, true)
	keyHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))

	out, err := captureStdout(t, func() error {
		return cmdVerifyWith(path, keyHex, false)
	})
	if err != nil {
		t.Fatalf("explicit anchor should verify a clean chain: %v (out=%q)", err, out)
	}
	if !strings.Contains(out, "signatures verified") {
		t.Fatalf("expected an authenticated verdict, got %q", out)
	}
}

// TestVerifyNeutralizesTerminalEscapes: chain-supplied text (net/summary/file)
// is attacker-authored. An OSC 52 sequence must not reach the terminal.
func TestVerifyNeutralizesTerminalEscapes(t *testing.T) {
	dir := t.TempDir()
	key := testKey(0x44)
	path := filepath.Join(dir, "chain.jsonl")
	f, err := createEvidenceFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder(bufio.NewWriter(f), key)
	rec.emit(Node{Op: "heartbeat", Summary: "recorder start"})
	rec.emit(Node{Op: "tool_call", Tool: "Bash", Net: "\x1b]52;c;QUJD\x07https://evil.example"})
	rec.emit(Node{Op: "heartbeat", Summary: "recorder end (clean exit)"})
	rec.w.Flush()
	f.Close()

	keyHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	out, verr := captureStdout(t, func() error { return cmdVerifyWith(path, keyHex, false) })
	if verr != nil {
		t.Fatalf("verify failed: %v", verr)
	}
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("terminal control characters escaped into verify output: %q", out)
	}
	if !strings.Contains(out, `\x1b]52`) {
		t.Fatalf("expected the payload to be shown inertly, got %q", out)
	}
}

// TestAtomicWriteDoesNotFollowSymlink is the regression for QA-F02: a planted
// symlink must not redirect an evidence write.
func TestAtomicWriteDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "session.cast")
	if err := os.Symlink(victim, dest); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(dest, []byte("new"), 0o600); err != nil {
		t.Fatalf("atomic write: %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", got)
	}
	if fi, err := os.Lstat(dest); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("destination should be a regular file after rename: %v", err)
	}

	// The streaming chain writer refuses a symlink outright.
	if err := os.Symlink(victim, filepath.Join(dir, "chain.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := createEvidenceFile(filepath.Join(dir, "chain.jsonl")); err == nil {
		t.Fatal("createEvidenceFile followed a symlink")
	}
}

// TestMalformedPubDoesNotPanic is the regression for the panic: a truncated or
// non-hex .pub used to reach ed25519.Verify with a short key and crash.
func TestMalformedPubDoesNotPanic(t *testing.T) {
	for _, body := range []string{"abcd", "", "zzzz", "00", strings.Repeat("a", 60)} {
		dir := t.TempDir()
		p := filepath.Join(dir, "bad.pub")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPub(p); err == nil {
			t.Errorf("loadPub accepted malformed key %q", body)
		}
	}
}

func TestParsePubHexValidatesLength(t *testing.T) {
	if _, err := parsePubHex(hex.EncodeToString(make([]byte, ed25519.PublicKeySize))); err != nil {
		t.Fatalf("32-byte key rejected: %v", err)
	}
	if _, err := parsePubHex(hex.EncodeToString(make([]byte, 31))); err == nil {
		t.Fatal("31-byte key accepted")
	}
}

// TestSanitizeTermNeutralizesOSC52: chain fields are attacker-authored; an
// OSC 52 sequence must not reach the terminal as an escape.
func TestSanitizeTermNeutralizesOSC52(t *testing.T) {
	in := "\x1b]52;c;QUJD\x07 https://evil.example"
	out := sanitizeTerm(in)
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("control characters survived sanitization: %q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected a visible escape marker, got %q", out)
	}
	// Benign text keeps its shape.
	if sanitizeTerm("a/b?c=d") != "a/b?c=d" {
		t.Fatal("sanitizer mangled ordinary text")
	}
}

// TestSafeEvidencePathRejectsTraversal: attrs.file from a hostile chain must not
// make verify read outside the chain's directory or block on a non-regular file.
func TestSafeEvidencePathRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "session.cast")
	if err := os.WriteFile(ok, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := safeEvidencePath(dir, "session.cast"); err != nil {
		t.Fatalf("plain local file rejected: %v", err)
	}
	// Back-compat: older chains recorded an absolute path for a file that is
	// genuinely beside the chain. That is still safe and must be accepted.
	if _, err := safeEvidencePath(dir, ok); err != nil {
		t.Fatalf("absolute path inside the chain dir rejected: %v", err)
	}
	for _, bad := range []string{"/etc/passwd", "../x", "a/b", "..", ".", ""} {
		if _, err := safeEvidencePath(dir, bad); err == nil {
			t.Errorf("safeEvidencePath accepted %q", bad)
		}
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := safeEvidencePath(dir, "sub"); err == nil {
		t.Error("safeEvidencePath accepted a directory")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	if _, err := safeEvidencePath(dir, "link"); err == nil {
		t.Error("safeEvidencePath accepted a symlink")
	}
}

func TestEvidenceFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	f, err := createEvidenceFile(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Fatalf("evidence mode = %o, want 600", mode)
	}
}

func TestValidSessionID(t *testing.T) {
	for _, ok := range []string{"abc", "0f3c-4a2b", "hook-123", "a.b_c-d"} {
		if !validSessionID(ok) {
			t.Errorf("valid id %q rejected", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "../x", "a/b", `a\b`, strings.Repeat("a", 129), "a b"} {
		if validSessionID(bad) {
			t.Errorf("invalid id %q accepted", bad)
		}
	}
}

// TestMutateMissingArgsDoesNotPanic: `agentprov tamper` used to index args[1]/[2]
// and crash.
func TestMutateMissingArgsDoesNotPanic(t *testing.T) {
	for _, cmd := range []string{"tamper", "drop"} {
		if err := run([]string{cmd}); err == nil {
			t.Errorf("%s with no args returned nil, want usage error", cmd)
		}
		if err := run([]string{cmd, "chain.jsonl"}); err == nil {
			t.Errorf("%s with one arg returned nil, want usage error", cmd)
		}
	}
}
