// agentprov — a tamper-evident black box for an AI coding agent run.
//
// It records an agent's activity into a hash-chained, signed record that survives
// the agent/container exiting, so afterward you can PROVE what happened and prove
// the record wasn't altered. This is the part a plain log file / SIEM dump cannot do.
//
// Three properties make it a flight recorder, not a log file:
//   (1) TAMPER detection — alter or drop any recorded event and `verify` catches it.
//   (2) GAP detection    — if the agent goes dark mid-run, the record shows the
//                          discontinuity (missing recorder heartbeats) instead of
//                          looking clean. The "agent shook its harness" signal.
//   (3) NON-REPUDIATION  — the chain is signed by a key in the macOS keychain that
//                          the agent process can't reach, so a popped agent can't
//                          forge a chain that verifies.
//
// Commands:
//   agentprov run -- <agent...>          # launch a real agent, record it LIVE, verify on exit
//   agentprov record <transcript.jsonl>  # record a past transcript (claude/codex)
//   agentprov verify <chain.jsonl>       # integrity + signatures + liveness + coverage
//   agentprov tamper <chain.jsonl> <seq> # demo: alter one node  -> verify must fail
//   agentprov drop   <chain.jsonl> <seq> # demo: delete one node -> verify must fail
//
// COVERAGE BOUNDARY (stated, not hidden): v1 records what the agent self-reports via
// its transcript — prompts, tool calls, tool results. It does NOT see what bypasses
// that surface (raw subprocess egress, off-transcript file writes). Those blind spots
// are LABELED in verify output; closing them is the privileged ES/eBPF tier (later).
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentprov:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: agentprov <run|record|verify|tamper|drop> ...")
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "record":
		if len(args) < 2 {
			return errors.New("usage: agentprov record <transcript.jsonl>")
		}
		return cmdRecord(args[1])
	case "verify":
		if len(args) < 2 {
			return errors.New("usage: agentprov verify <chain.jsonl>")
		}
		return cmdVerify(args[1])
	case "analyze":
		if len(args) < 2 {
			return errors.New("usage: agentprov analyze <chain.jsonl>")
		}
		return cmdAnalyze(args[1])
	case "tamper":
		return cmdMutate(args[1], args[2], false)
	case "drop":
		return cmdMutate(args[1], args[2], true)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// ── chain model ────────────────────────────────────────────────────────────

// Node is one link. Op="heartbeat" nodes are emitted by the RECORDER (not the
// agent) on a cadence; their absence is how a gap becomes visible. Hash binds
// content+PrevHash; Sig signs Hash with the keychain key the agent can't reach.
type Node struct {
	Seq        int               `json:"seq"`
	Op         string            `json:"op"` // heartbeat | prompt | tool_call | tool_result | assistant | other
	SpanID     string            `json:"span_id,omitempty"`
	ParentSpan string            `json:"parent_span_id,omitempty"`
	Tool       string            `json:"tool,omitempty"`
	Trust      string            `json:"trust,omitempty"` // trusted | untrusted | unknown
	Summary    string            `json:"summary,omitempty"`
	Time       string            `json:"time,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	PrevHash   string            `json:"prev_hash"`
	Hash       string            `json:"hash"`
	Sig        string            `json:"sig"`
}

func contentHash(prev string, n Node) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		n.Seq, prev, n.Op, n.SpanID, n.ParentSpan, n.Tool, n.Trust, n.Summary, n.Time)
	for _, k := range sortedKeys(n.Attrs) {
		fmt.Fprintf(h, "\x00%s=%s", k, n.Attrs[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// recorder appends signed, hash-chained nodes to a chain file. The signing key
// lives in the keychain; the recorder holds it for its lifetime but it never
// touches disk or the agent's environment.
type recorder struct {
	w    *bufio.Writer
	priv ed25519.PrivateKey
	prev string
	seq  int
}

func newRecorder(w *bufio.Writer, priv ed25519.PrivateKey) *recorder {
	return &recorder{w: w, priv: priv, prev: "GENESIS"}
}

func (r *recorder) emit(n Node) {
	n.Seq = r.seq
	n.PrevHash = r.prev
	n.Hash = contentHash(r.prev, n)
	n.Sig = hex.EncodeToString(ed25519.Sign(r.priv, []byte(n.Hash)))
	r.prev = n.Hash
	b, _ := json.Marshal(n)
	r.w.Write(b)
	r.w.WriteByte('\n')
	r.w.Flush() // flush each node: the record must survive an abrupt exit
	r.seq++
}

const heartbeatEvery = 25 // one recorder heartbeat per N agent events

// ── keychain-backed signing key ────────────────────────────────────────────

const keychainService = "agentprov-signing-key"

// loadOrCreateSigningKey returns an ed25519 private key whose seed is stored in
// the macOS keychain. The agent process never sees it. Falls back to an ephemeral
// in-memory key on non-macOS or if `security` is unavailable (still tamper-evident,
// just not keychain-bound) — and says so.
func loadOrCreateSigningKey() (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	seedHex, err := keychainGet(keychainService)
	if err == nil && len(seedHex) == ed25519.SeedSize*2 {
		seed, derr := hex.DecodeString(seedHex)
		if derr == nil {
			priv := ed25519.NewKeyFromSeed(seed)
			return priv, priv.Public().(ed25519.PublicKey), "keychain", nil
		}
	}
	// generate a fresh key
	pub, priv, gerr := ed25519.GenerateKey(nil)
	if gerr != nil {
		return nil, nil, "", gerr
	}
	seed := priv.Seed()
	if err := keychainSet(keychainService, hex.EncodeToString(seed)); err != nil {
		// keychain unavailable — fall back, but be honest about the weaker property
		return priv, pub, "ephemeral", nil
	}
	return priv, pub, "keychain", nil
}

func keychainGet(service string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-a", "agentprov", "-s", service, "-w").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func keychainSet(service, secret string) error {
	// -U updates if present. Stderr suppressed; we only care about exit status.
	cmd := exec.Command("security", "add-generic-password", "-a", "agentprov", "-s", service, "-w", secret, "-U")
	cmd.Stderr = nil
	return cmd.Run()
}

func writePubFile(pub ed25519.PublicKey) error {
	return os.WriteFile("chain.pub", []byte(hex.EncodeToString(pub)), 0o644)
}

// ── live run: wrap a real agent ────────────────────────────────────────────

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: agentprov run -- <agent command...>   e.g. agentprov run -- codex exec 'add a test'")
	}
	priv, pub, keySource, err := loadOrCreateSigningKey()
	if err != nil {
		return err
	}
	if err := writePubFile(pub); err != nil {
		return err
	}

	// Watch the agent's transcript dir; the file it creates after launch is ours.
	watchDir, ok := transcriptDirFor(args[0])
	if !ok {
		return fmt.Errorf("don't know the transcript location for %q (supported: claude, codex)", args[0])
	}
	before := snapshotJSONL(watchDir)

	out, err := os.Create("chain.jsonl")
	if err != nil {
		return err
	}
	defer out.Close()
	rec := newRecorder(bufio.NewWriter(out), priv)
	rec.emit(Node{Op: "heartbeat", Summary: "recorder start", Attrs: map[string]string{"key": keySource, "agent": args[0]}})

	fmt.Printf("agentprov: recording live (%s key). launching: %s\n\n", keySource, strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch failed: %w", err)
	}

	// Forward Ctrl-C to the child but keep recording through it.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		for s := range sigc {
			_ = cmd.Process.Signal(s)
		}
	}()

	// Find the transcript the run created (poll briefly), then tail it live.
	transcript := awaitNewTranscript(watchDir, before, 10*time.Second)
	done := make(chan struct{})
	agentEvents := 0
	if transcript != "" {
		go tailInto(transcript, rec, &agentEvents, done)
	} else {
		fmt.Fprintln(os.Stderr, "agentprov: warning — no new transcript appeared; recording exit only")
		close(done)
	}

	waitErr := cmd.Wait()
	time.Sleep(300 * time.Millisecond) // let the tail drain final lines
	close(done)
	signal.Stop(sigc)

	exitNote := "clean exit"
	if waitErr != nil {
		exitNote = "agent exited with error: " + waitErr.Error()
	}
	rec.emit(Node{Op: "heartbeat", Summary: "recorder end (" + exitNote + ")"})
	rec.w.Flush()

	fmt.Printf("\nagentprov: recorded %d nodes (%d agent events) -> chain.jsonl\n", rec.seq, agentEvents)
	fmt.Printf("verify with: agentprov verify chain.jsonl\n")
	return nil
}

// transcriptDirFor returns the dir an agent writes its session JSONL into.
func transcriptDirFor(agent string) (string, bool) {
	home, _ := os.UserHomeDir()
	switch filepath.Base(agent) {
	case "claude":
		return filepath.Join(home, ".claude", "projects"), true
	case "codex":
		return filepath.Join(home, ".codex", "sessions"), true
	}
	return "", false
}

func snapshotJSONL(dir string) map[string]bool {
	seen := map[string]bool{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".jsonl") {
			seen[p] = true
		}
		return nil
	})
	return seen
}

// awaitNewTranscript polls for a .jsonl that appeared after `before`.
func awaitNewTranscript(dir string, before map[string]bool, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var newest string
		var newestMod time.Time
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") || before[p] {
				return nil
			}
			info, ierr := d.Info()
			if ierr == nil && info.ModTime().After(newestMod) {
				newest, newestMod = p, info.ModTime()
			}
			return nil
		})
		if newest != "" {
			return newest
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ""
}

// tailInto follows a transcript file, recording each new line until done closes.
func tailInto(path string, rec *recorder, count *int, done <-chan struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	var buf strings.Builder
	for {
		select {
		case <-done:
			drainLines(reader, &buf, rec, count)
			return
		default:
		}
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			buf.WriteString(line)
			if strings.HasSuffix(line, "\n") {
				recordLine(strings.TrimSpace(buf.String()), rec, count)
				buf.Reset()
			}
		}
		if err != nil { // EOF: wait for more appends
			time.Sleep(150 * time.Millisecond)
		}
	}
}

func drainLines(reader *bufio.Reader, buf *strings.Builder, rec *recorder, count *int) {
	for {
		line, err := reader.ReadString('\n')
		buf.WriteString(line)
		if strings.HasSuffix(line, "\n") {
			recordLine(strings.TrimSpace(buf.String()), rec, count)
			buf.Reset()
		}
		if err != nil {
			return
		}
	}
}

func recordLine(line string, rec *recorder, count *int) {
	if line == "" {
		return
	}
	var raw map[string]any
	if json.Unmarshal([]byte(line), &raw) != nil {
		return
	}
	for _, n := range normalize(raw) {
		rec.emit(n)
		*count++
		if *count%heartbeatEvery == 0 {
			rec.emit(Node{Op: "heartbeat", Summary: "recorder alive"})
		}
	}
}

// ── record a past transcript ───────────────────────────────────────────────

func cmdRecord(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	priv, pub, keySource, err := loadOrCreateSigningKey()
	if err != nil {
		return err
	}
	if err := writePubFile(pub); err != nil {
		return err
	}
	out, err := os.Create("chain.jsonl")
	if err != nil {
		return err
	}
	defer out.Close()
	rec := newRecorder(bufio.NewWriter(out), priv)
	rec.emit(Node{Op: "heartbeat", Summary: "recorder start", Attrs: map[string]string{"key": keySource}})

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	count := 0
	for sc.Scan() {
		recordLine(strings.TrimSpace(sc.Text()), rec, &count)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	rec.emit(Node{Op: "heartbeat", Summary: "recorder end (clean exit)"})
	rec.w.Flush()
	fmt.Printf("recorded %d nodes (%d agent events) -> chain.jsonl (%s key)\nhead: %s\n",
		rec.seq, count, keySource, short(rec.prev))
	return nil
}

// normalize maps one raw transcript line (Claude OR Codex) to provenance node(s).
// tool_result is where untrusted content enters (file/web/MCP) — labeled untrusted.
func normalize(raw map[string]any) []Node {
	if uuid, ok := raw["uuid"].(string); ok { // Claude Code
		parent, _ := raw["parentUuid"].(string)
		ts, _ := raw["timestamp"].(string)
		typ, _ := raw["type"].(string)
		base := Node{SpanID: uuid, ParentSpan: parent, Time: ts, Trust: "unknown"}
		msg, _ := raw["message"].(map[string]any)
		content, _ := msg["content"].([]any)
		var nodes []Node
		for _, c := range content {
			b, _ := c.(map[string]any)
			switch b["type"] {
			case "tool_use":
				n := base
				n.Op, n.Trust = "tool_call", "trusted"
				n.Tool, _ = b["name"].(string)
				n.Summary = "tool_use " + n.Tool
				// detail = the command/path/url the tool acts on; the taint pass reads it.
				n.Attrs = detailAttr(flatten(b["input"]))
				nodes = append(nodes, n)
			case "tool_result":
				n := base
				n.Op, n.Trust, n.Summary = "tool_result", "untrusted", "tool_result"
				n.Attrs = detailAttr(flatten(b["content"]))
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 0 {
			n := base
			switch typ {
			case "user":
				n.Op, n.Trust, n.Summary = "prompt", "untrusted", "user prompt"
			case "assistant":
				n.Op, n.Trust, n.Summary = "assistant", "trusted", "assistant turn"
			default:
				n.Op, n.Summary = "other", typ
			}
			nodes = append(nodes, n)
		}
		return nodes
	}
	// Codex: events nest the real kind under payload.type. The outer "type" is
	// the envelope (response_item / event_msg / session_meta / turn_context).
	if outer, ok := raw["type"].(string); ok {
		ts, _ := raw["timestamp"].(string)
		payload, _ := raw["payload"].(map[string]any)
		ptype, _ := payload["type"].(string)
		n := Node{Op: "other", Time: ts, Trust: "unknown", Summary: outer + "/" + ptype}
		switch ptype {
		case "message", "user_message":
			// role distinguishes prompt (user) from assistant turn.
			role, _ := payload["role"].(string)
			if role == "assistant" {
				n.Op, n.Trust, n.Summary = "assistant", "trusted", "assistant turn"
			} else {
				n.Op, n.Trust, n.Summary = "prompt", "untrusted", "user prompt"
			}
		case "function_call", "custom_tool_call":
			n.Op, n.Trust = "tool_call", "trusted"
			n.Tool, _ = payload["name"].(string)
			n.Summary = "tool_call " + n.Tool
			n.Attrs = detailAttr(flatten(payload["arguments"]) + " " + flatten(payload["input"]))
		case "function_call_output", "custom_tool_call_output", "patch_apply_end":
			// tool RESULTS are where untrusted content (file/web/MCP) enters.
			n.Op, n.Trust, n.Summary = "tool_result", "untrusted", "tool_result"
			n.Attrs = detailAttr(flatten(payload["output"]) + " " + flatten(payload["input"]))
		case "agent_message":
			n.Op, n.Trust, n.Summary = "assistant", "trusted", "assistant message"
		}
		return []Node{n}
	}
	return nil
}

// flatten reduces an arbitrary transcript value (string / map / list) to a single
// lowercased string the taint pass can pattern-match. Bounded so the chain stays small.
func flatten(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(x any) {
		if b.Len() > 600 {
			return
		}
		switch t := x.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte(' ')
		case map[string]any:
			for _, k := range sortedAnyKeys(t) {
				walk(t[k])
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	// Rune-safe truncate: a byte-slice cut can split a multi-byte UTF-8 rune, which
	// json.Marshal then re-encodes as U+FFFD — making the stored JSON differ from
	// what was hashed and breaking verify. Always cut on rune boundaries.
	return truncRunes(strings.ToLower(strings.TrimSpace(b.String())), 400)
}

// truncRunes returns at most n runes of s, never splitting a multi-byte rune.
func truncRunes(s string, n int) string {
	if len(s) <= n { // fast path: byte len <= n implies rune count <= n
		return s
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func detailAttr(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return map[string]string{"detail": s}
}

func sortedAnyKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j-1] > ks[j]; j-- {
			ks[j-1], ks[j] = ks[j], ks[j-1]
		}
	}
	return ks
}

// ── analyze: information-flow taint over the chain ──────────────────────────
//
// A clean-room re-implementation of the IFC model from `sir` (somoore/sir): the
// MODEL, not its code — session-level taint propagation, detection only, no
// enforcement, no hooks, no oracle. It walks the recorded chain and propagates a
// session taint state across three lethal-trifecta legs:
//
//   1. UNTRUSTED INPUT  — an untrusted source entered the session (tool_result,
//      prompt) carrying potential injection content.
//   2. SENSITIVE READ   — the session touched secret-bearing material (.env, creds,
//      keys, tokens) via a tool call/result detail.
//   3. EXFIL SINK       — an egress-capable action appeared (curl/POST/push/socket).
//
// When a single session has assembled all three, that's the lethal trifecta
// (Willison) / a Rule-of-Two violation (Meta): flagged with the seq that closed it.
// This is detection over the durable record — the analytic layer the raw flight
// recorder lacks. It never blocks anything.

type taintState struct {
	untrustedAt int // seq where untrusted input entered (-1 = not yet)
	sensitiveAt int
	exfilAt     int
}

// signal keyword sets. Deliberately conservative: this is a detector that flags
// for human review, not an enforcer, so false positives are cheap and misses are
// the cost. Tune against real runs, not in the abstract.
var (
	// Sensitive hints are intentionally specific filenames/paths/phrases, not loose
	// substrings — "token" alone matches "max_output_tokens" (a real false positive
	// caught on a benign run). Match credential ARTIFACTS, not the word.
	sensitiveHints = []string{
		".env", "credentials", "id_rsa", ".ssh/", ".aws/", "aws_secret_access_key",
		"private_key", "/etc/shadow", ".npmrc", ".netrc", "secret_key",
		"api_key=", "apikey=", "authorization: bearer", "-----begin",
	}
	exfilHints = []string{
		"curl ", "wget ", "http://", "https://", "nc ", "ncat", "/dev/tcp",
		" post ", "fetch(", "urllib", "requests.post", "requests.get",
		"git push", "scp ", "rsync ", "base64", "| sh", "webhook",
	}
)

func cmdAnalyze(path string) error {
	nodes, err := loadChain(path)
	if err != nil {
		return err
	}
	st := taintState{untrustedAt: -1, sensitiveAt: -1, exfilAt: -1}
	var findings []string
	tripped := false

	for _, n := range nodes {
		detail := n.Summary + " " + n.Attrs["detail"] + " " + n.Tool

		// Leg 1: untrusted input entered the session.
		if st.untrustedAt < 0 && n.Trust == "untrusted" && (n.Op == "tool_result" || n.Op == "prompt") {
			st.untrustedAt = n.Seq
		}
		// Leg 2: the session touched sensitive material.
		if st.sensitiveAt < 0 && matchesAny(detail, sensitiveHints) {
			st.sensitiveAt = n.Seq
			findings = append(findings, fmt.Sprintf("seq %d: SENSITIVE access — %s", n.Seq, clip(detail)))
		}
		// Leg 3: an egress-capable sink appeared.
		if matchesAny(detail, exfilHints) && n.Op == "tool_call" {
			st.exfilAt = n.Seq
			// Trifecta closes only if both prior legs are present AND ordered
			// before this sink — the dangerous causal sequence, not mere co-occurrence.
			if st.untrustedAt >= 0 && st.sensitiveAt >= 0 &&
				st.untrustedAt <= n.Seq && st.sensitiveAt <= n.Seq {
				tripped = true
				findings = append(findings, fmt.Sprintf(
					"seq %d: ⚠ LETHAL TRIFECTA ASSEMBLED — egress sink (%s) after untrusted input (seq %d) and sensitive read (seq %d)",
					n.Seq, clip(detail), st.untrustedAt, st.sensitiveAt))
			} else {
				findings = append(findings, fmt.Sprintf("seq %d: egress sink — %s", n.Seq, clip(detail)))
			}
		}
	}

	fmt.Printf("analyze: %d nodes. taint legs — untrusted@%s sensitive@%s exfil@%s\n",
		len(nodes), seqStr(st.untrustedAt), seqStr(st.sensitiveAt), seqStr(st.exfilAt))
	for _, f := range findings {
		fmt.Println("  " + f)
	}
	if tripped {
		fmt.Println("VERDICT: ⚠ lethal trifecta detected — this session assembled untrusted-input + sensitive-data + exfil-path. Review before trusting its output.")
		return errors.New("lethal trifecta detected")
	}
	if len(findings) == 0 {
		fmt.Println("VERDICT: clean — no sensitive-then-exfil flow observed.")
	} else {
		fmt.Println("VERDICT: no full trifecta, but flagged flows above warrant a look.")
	}
	return nil
}

func matchesAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func clip(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if t := truncRunes(s, 90); t != s {
		return t + "…"
	}
	return s
}

func seqStr(i int) string {
	if i < 0 {
		return "—"
	}
	return strconv.Itoa(i)
}

// ── verify ─────────────────────────────────────────────────────────────────

func cmdVerify(path string) error {
	nodes, err := loadChain(path)
	if err != nil {
		return err
	}
	pub, _ := loadPub("chain.pub")

	prev := "GENESIS"
	heartbeats := 0
	cleanExit := false
	keySource := "unknown"
	for _, n := range nodes {
		if n.PrevHash != prev {
			return fmt.Errorf("CHAIN BROKEN at seq %d: prev_hash=%s expected %s — a node was DROPPED, inserted, or reordered",
				n.Seq, short(n.PrevHash), short(prev))
		}
		if want := contentHash(prev, n); want != n.Hash {
			return fmt.Errorf("CHAIN BROKEN at seq %d: content ALTERED (recomputed %s != stored %s)",
				n.Seq, short(want), short(n.Hash))
		}
		if pub != nil {
			sig, derr := hex.DecodeString(n.Sig)
			if derr != nil || !ed25519.Verify(pub, []byte(n.Hash), sig) {
				return fmt.Errorf("SIGNATURE INVALID at seq %d: not signed by the recorder key (forged, or re-hashed by something without the key)", n.Seq)
			}
		}
		if n.Op == "heartbeat" {
			heartbeats++
			if k := n.Attrs["key"]; k != "" {
				keySource = k
			}
			if strings.Contains(n.Summary, "clean exit") {
				cleanExit = true
			}
		}
		prev = n.Hash
	}

	fmt.Printf("integrity:  OK — %d nodes, chain intact, signatures valid. head: %s\n", len(nodes), short(prev))
	if keySource == "keychain" {
		fmt.Printf("provenance: signed by keychain key (non-repudiable: the agent process can't reach it)\n")
	} else {
		fmt.Printf("provenance: signed by %s key (tamper-evident; keychain unavailable -> not bound away from the agent)\n", keySource)
	}
	printCoverage()
	if !cleanExit {
		fmt.Printf("liveness:   ⚠ GAP DETECTED — no clean-exit heartbeat. The run was truncated or the recorder\n")
		fmt.Printf("            was silenced mid-run. A plain log would look complete here; this does not.\n")
		return errors.New("record incomplete: missing recorder clean-exit (possible evasion)")
	}
	fmt.Printf("liveness:   OK — %d recorder heartbeats, clean exit observed.\n", heartbeats)
	return nil
}

// printCoverage states, honestly, what this tier of the recorder can and cannot
// see. Honest coverage map > false completeness — the credibility move.
func printCoverage() {
	fmt.Println("coverage:")
	fmt.Println("  ✓ covered  : prompts, tool calls, tool results, run start/end (agent self-reported transcript)")
	fmt.Println("  ✗ blindspot: off-transcript subprocess egress, raw sockets, file writes by spawned children")
	fmt.Println("               -> these require the privileged ES/eBPF tier; not observed at this tier.")
}

// ── tamper/drop demo harness ───────────────────────────────────────────────

func cmdMutate(path, seqStr string, drop bool) error {
	target, err := strconv.Atoi(seqStr)
	if err != nil {
		return fmt.Errorf("seq must be a number: %w", err)
	}
	nodes, err := loadChain(path)
	if err != nil {
		return err
	}
	out := make([]Node, 0, len(nodes))
	found := false
	for _, n := range nodes {
		if n.Seq == target {
			found = true
			if drop {
				continue
			}
			n.Summary += " [TAMPERED]"
		}
		out = append(out, n)
	}
	if !found {
		return fmt.Errorf("seq %d not found", target)
	}
	if err := writeChain(path, out); err != nil {
		return err
	}
	action := "altered"
	if drop {
		action = "dropped"
	}
	fmt.Printf("%s node seq %d in %s. Now run: agentprov verify %s\n", action, target, path, path)
	return nil
}

// ── io helpers ─────────────────────────────────────────────────────────────

func loadChain(path string) ([]Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var nodes []Node
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var n Node
		if err := json.Unmarshal([]byte(line), &n); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, sc.Err()
}

func writeChain(path string, nodes []Node) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	for _, n := range nodes {
		b, _ := json.Marshal(n)
		w.Write(b)
		w.WriteByte('\n')
	}
	return nil
}

func loadPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j-1] > ks[j]; j-- {
			ks[j-1], ks[j] = ks[j], ks[j-1]
		}
	}
	return ks
}
