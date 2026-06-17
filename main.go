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
//   agentprov view   [chain.jsonl]       # open the chain in a browser flight-recorder viewer
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
	"sort"
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
	case "view":
		path := "chain.jsonl"
		if len(args) > 1 {
			path = args[1]
		}
		return cmdView(path)
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
	Agent      string            `json:"agent,omitempty"` // which agent produced this: "main" or a subagent id
	SpanID     string            `json:"span_id,omitempty"`
	ParentSpan string            `json:"parent_span_id,omitempty"`
	Tool       string            `json:"tool,omitempty"`
	Trust      string            `json:"trust,omitempty"` // trusted | untrusted | unknown
	Summary    string            `json:"summary,omitempty"` // category label (op-derived)
	Detail     string            `json:"detail,omitempty"`  // the actual content: prompt text, command+args, tool output
	Time       string            `json:"time,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	PrevHash   string            `json:"prev_hash"`
	Hash       string            `json:"hash"`
	Sig        string            `json:"sig"`
}

func contentHash(prev string, n Node) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		n.Seq, prev, n.Op, n.Agent, n.SpanID, n.ParentSpan, n.Tool, n.Trust, n.Summary, n.Detail, n.Time)
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

func recordLine(line string, rec *recorder, count *int) { recordLineAs(line, "", rec, count) }

func recordLineAs(line, agent string, rec *recorder, count *int) {
	if line == "" {
		return
	}
	var raw map[string]any
	if json.Unmarshal([]byte(line), &raw) != nil {
		return
	}
	for _, n := range normalize(raw) {
		n.Agent = agent
		rec.emit(n)
		*count++
		if *count%heartbeatEvery == 0 {
			rec.emit(Node{Op: "heartbeat", Summary: "recorder alive"})
		}
	}
}

// recordFileAs folds one transcript file into rec, tagging every node with agent.
func recordFileAs(path, agent string, rec *recorder, count *int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		recordLineAs(strings.TrimSpace(sc.Text()), agent, rec, count)
	}
	return sc.Err()
}

// subagentFiles returns the subagent transcript paths for a main transcript at
// <project>/<sessionId>.jsonl — they live in <project>/<sessionId>/subagents/.
// Returns nil if there is no such dir (the common single-agent case).
func subagentFiles(mainPath string) []string {
	dir := strings.TrimSuffix(mainPath, ".jsonl")
	matches, _ := filepath.Glob(filepath.Join(dir, "subagents", "agent-*.jsonl"))
	sort.Strings(matches) // deterministic order
	return matches
}

// subagentID derives the short agent id from a subagents/agent-<id>.jsonl path.
func subagentID(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	return strings.TrimPrefix(base, "agent-")
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
	f.Close() // recordFileAs reopens; we only needed to validate existence above.
	rec := newRecorder(bufio.NewWriter(out), priv)
	rec.emit(Node{Op: "heartbeat", Summary: "recorder start", Attrs: map[string]string{"key": keySource}})

	count := 0
	if err := recordFileAs(path, "main", rec, &count); err != nil {
		return err
	}

	// Fold in any subagents the main session spawned. One signed chain covers
	// the whole tree: each subagent's nodes are tagged with its id, preceded by
	// a subagent marker. Tampering ANY node — main or sub — fractures verify.
	subs := subagentFiles(path)
	for _, sp := range subs {
		id := subagentID(sp)
		rec.emit(Node{Op: "subagent", Agent: id, Summary: "subagent spawned",
			Attrs: map[string]string{"id": id, "source": filepath.Base(sp)}})
		if err := recordFileAs(sp, id, rec, &count); err != nil {
			return err
		}
	}

	rec.emit(Node{Op: "heartbeat", Summary: "recorder end (clean exit)"})
	rec.w.Flush()
	subNote := ""
	if len(subs) > 0 {
		subNote = fmt.Sprintf(", %d subagent(s)", len(subs))
	}
	fmt.Printf("recorded %d nodes (%d agent events%s) -> chain.jsonl (%s key)\nhead: %s\n",
		rec.seq, count, subNote, keySource, short(rec.prev))
	return nil
}

// normalize maps one raw transcript line (Claude OR Codex) to provenance node(s).
// tool_result is where untrusted content enters (file/web/MCP) — labeled untrusted.
// truncRunes truncates on a rune boundary so we never split a multi-byte
// UTF-8 character — a byte slice can, and json.Marshal then re-encodes the
// broken byte as U+FFFD, making stored JSON differ from what was hashed and
// breaking verify on messy real transcripts.
func truncRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// flatten pulls human-readable text out of whatever a transcript packs into a
// content/input/output field: a string, a []block with text/content, or a map
// we JSON-encode. This is the "WHAT happened" — the prompt, the command, the
// tool output — that the category label alone can't convey.
func flatten(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var parts []string
		for _, e := range x {
			if s := flatten(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	case map[string]any:
		for _, k := range []string{"text", "content", "command", "output", "stdout"} {
			if s, ok := x[k]; ok {
				return flatten(s)
			}
		}
		b, _ := json.Marshal(x)
		return string(b)
	default:
		return ""
	}
}

const detailMax = 600

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
				n.Detail = truncRunes(flatten(b["input"]), detailMax)
				nodes = append(nodes, n)
			case "tool_result":
				n := base
				n.Op, n.Trust, n.Summary = "tool_result", "untrusted", "tool_result"
				n.Detail = truncRunes(flatten(b["content"]), detailMax)
				nodes = append(nodes, n)
			case "text":
				n := base
				n.Op, n.Trust, n.Summary = "assistant", "trusted", "assistant turn"
				n.Detail = truncRunes(flatten(b["text"]), detailMax)
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 0 {
			n := base
			switch typ {
			case "user":
				n.Op, n.Trust, n.Summary = "prompt", "untrusted", "user prompt"
				n.Detail = truncRunes(flatten(msg["content"]), detailMax)
			case "assistant":
				n.Op, n.Trust, n.Summary = "assistant", "trusted", "assistant turn"
				n.Detail = truncRunes(flatten(msg["content"]), detailMax)
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
			n.Detail = truncRunes(flatten(payload["content"]), detailMax)
		case "function_call", "custom_tool_call":
			n.Op, n.Trust = "tool_call", "trusted"
			n.Tool, _ = payload["name"].(string)
			n.Summary = "tool_call " + n.Tool
			n.Detail = truncRunes(flatten(payload["arguments"]), detailMax)
		case "function_call_output", "custom_tool_call_output", "patch_apply_end":
			// tool RESULTS are where untrusted content (file/web/MCP) enters.
			n.Op, n.Trust, n.Summary = "tool_result", "untrusted", "tool_result"
			n.Detail = truncRunes(flatten(payload["output"]), detailMax)
		case "agent_message":
			n.Op, n.Trust, n.Summary = "assistant", "trusted", "assistant message"
			n.Detail = truncRunes(flatten(payload["message"]), detailMax)
		}
		return []Node{n}
	}
	return nil
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
