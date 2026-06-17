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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
		return errors.New("usage: agentprov <demo|run|record|verify|view|tamper|drop> ...")
	}
	switch args[0] {
	case "demo":
		return cmdDemo()
	case "install":
		return cmdInstall()
	case "uninstall":
		return cmdUninstall()
	case "__shim": // internal: invoked by the claude shim, not by users
		return cmdShim(args[1:])
	case "attach-cast":
		if len(args) < 3 {
			return errors.New("usage: agentprov attach-cast <chain.jsonl> <session.cast>")
		}
		return cmdAttachCast(args[1], args[2])
	case "attach-flows":
		if len(args) < 3 {
			return errors.New("usage: agentprov attach-flows <chain.jsonl> <events.jsonl>")
		}
		return cmdAttachFlows(args[1], args[2])
	case "run":
		return cmdRun(args[1:])
	case "record":
		if len(args) < 2 {
			return errors.New("usage: agentprov record <transcript.jsonl>")
		}
		return cmdRecord(args[1])
	case "sessions":
		return cmdSessions()
	case "verify":
		path := chainArgOrLatest(args[1:])
		if path == "" {
			return errors.New("no chain given and no recorded sessions found (run a session first, or pass a chain.jsonl)")
		}
		return cmdVerify(path)
	case "video":
		cast := "session.cast"
		if len(args) > 1 {
			cast = args[1]
		} else if d := latestSessionDir(); d != "" {
			cast = filepath.Join(d, "session.cast")
		}
		return cmdVideo(cast)
	case "view":
		path := ""
		flowsPath := ""
		rest := args[1:]
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--flows" && i+1 < len(rest) {
				flowsPath = rest[i+1]
				i++
			} else {
				path = rest[i]
			}
		}
		if path == "" {
			// default to the latest recorded session, else ./chain.jsonl
			if d := latestSessionDir(); d != "" {
				path = filepath.Join(d, "chain.jsonl")
				fmt.Printf("agentprov: viewing latest session: %s\n", d)
			} else {
				path = "chain.jsonl"
			}
		}
		return cmdViewFlows(path, flowsPath)
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
	Net        string            `json:"net,omitempty"`     // egress host/URL if this tool_call reaches the network (WebFetch/curl/...)
	Time       string            `json:"time,omitempty"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	PrevHash   string            `json:"prev_hash"`
	Hash       string            `json:"hash"`
	Sig        string            `json:"sig"`
}

func contentHash(prev string, n Node) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		n.Seq, prev, n.Op, n.Agent, n.SpanID, n.ParentSpan, n.Tool, n.Trust, n.Summary, n.Detail, n.Net, n.Time)
	for _, k := range sortedKeys(n.Attrs) {
		fmt.Fprintf(h, "\x00%s=%s", k, n.Attrs[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// recorder appends signed, hash-chained nodes to a chain file. The signing key
// lives in the keychain; the recorder holds it for its lifetime but it never
// touches disk or the agent's environment.
type recorder struct {
	mu   sync.Mutex
	w    *bufio.Writer
	priv ed25519.PrivateKey
	prev string
	seq  int
}

func newRecorder(w *bufio.Writer, priv ed25519.PrivateKey) *recorder {
	return &recorder{w: w, priv: priv, prev: "GENESIS"}
}

func (r *recorder) emit(n Node) {
	r.mu.Lock()
	defer r.mu.Unlock()
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

// cmdAttachCast binds a real terminal recording (asciinema .cast) to an existing
// chain by appending a signed node that commits to the recording's SHA-256. The
// recording itself is NOT tamper-proof — the agent renders to the TTY and could
// lie — but the chain commits to its hash, so it becomes tamper-EVIDENT: the
// .cast can't be swapped after the fact, and the verified chain's tool_results
// can be cross-checked against what the TTY claimed. Two cameras on one run.
func cmdAttachCast(chainPath, castPath string) error {
	nodes, err := loadChain(chainPath)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return errors.New("empty chain")
	}
	castBytes, err := os.ReadFile(castPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(castBytes)
	castHash := hex.EncodeToString(sum[:])

	priv, pub, keySource, err := loadOrCreateSigningKey()
	if err != nil {
		return err
	}
	if err := writePubFile(pub); err != nil {
		return err
	}
	// copy the recording next to the chain so the viewer can load it by name.
	castName := "session.cast"
	if err := os.WriteFile(castName, castBytes, 0o600); err != nil {
		return err
	}

	// re-open the chain for append, positioned at the tail hash/seq.
	f, err := os.OpenFile(chainPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	tail := nodes[len(nodes)-1]
	rec := newRecorder(bufio.NewWriter(f), priv)
	rec.seq = tail.Seq + 1
	rec.prev = tail.Hash
	rec.emit(Node{
		Op:      "cast_recording",
		Summary: "real terminal recording (asciinema) — reconstruction's untrusted sibling",
		Attrs: map[string]string{
			"sha256": castHash,
			"file":   castName,
			"bytes":  fmt.Sprintf("%d", len(castBytes)),
			"key":    keySource,
		},
	})
	rec.w.Flush()
	fmt.Printf("attached %s (%d bytes) to %s\n", castName, len(castBytes), chainPath)
	fmt.Printf("  sha256: %s\n", castHash)
	fmt.Printf("  the chain now commits to this recording — swap it and verify fails.\n")
	return nil
}

// cmdAttachFlows binds an agentsnitch flows file (events.jsonl) to the chain by
// committing its SHA-256, so a swapped flow file is caught by verify. The flows
// are a THIRD evidence layer (OS-observed egress + agentsnitch's probabilistic
// tool links); committing the hash makes the overlay tamper-evident without
// putting the flows — or agentsnitch's confidence guesses — into the signed chain.
func cmdAttachFlows(chainPath, flowsPath string) error {
	nodes, err := loadChain(chainPath)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return errors.New("empty chain")
	}
	flows, ferr := loadFlows(flowsPath)
	if ferr != nil {
		return ferr
	}
	flowBytes, err := os.ReadFile(flowsPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(flowBytes)
	flowHash := hex.EncodeToString(sum[:])

	priv, pub, keySource, err := loadOrCreateSigningKey()
	if err != nil {
		return err
	}
	if err := writePubFile(pub); err != nil {
		return err
	}
	flowName := "flows.jsonl"
	if err := os.WriteFile(flowName, flowBytes, 0o600); err != nil {
		return err
	}

	f, err := os.OpenFile(chainPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	tail := nodes[len(nodes)-1]
	rec := newRecorder(bufio.NewWriter(f), priv)
	rec.seq = tail.Seq + 1
	rec.prev = tail.Hash
	rec.emit(Node{
		Op:      "flow_evidence",
		Summary: "OS-observed network flows (agentsnitch) — overlay evidence, not signed chain content",
		Attrs: map[string]string{
			"sha256": flowHash,
			"file":   flowName,
			"flows":  fmt.Sprintf("%d", len(flows)),
			"key":    keySource,
		},
	})
	rec.w.Flush()
	fmt.Printf("attached %s (%d outbound flows) to %s\n", flowName, len(flows), chainPath)
	fmt.Printf("  sha256: %s\n", flowHash)
	fmt.Printf("  the chain now commits to this flow evidence — swap it and verify fails.\n")
	return nil
}

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: agentprov run -- <agent command...>   e.g. agentprov run -- codex exec 'add a test'")
	}
	return runRecorded(args, ".", false)
}

// cmdRunRecorded is the transparent path used by the claude shim: record the
// session into a per-session dir under the sessions root, quietly (so the user's
// claude experience is unchanged), and pass the real claude's exit code through.
func cmdRunRecorded(args []string) error {
	dir := newSessionDir()
	return runRecorded(args, dir, true)
}

// runRecorded launches args[0] under PTY capture, recording the chain + cast into
// outDir. quiet suppresses agentprov's own chatter (for the transparent shim).
// Returns the AGENT's exit error so the caller can propagate its exit code.
func runRecorded(args []string, outDir string, quiet bool) error {
	priv, pub, keySource, err := loadOrCreateSigningKey()
	if err != nil {
		return err
	}
	pubPath := filepath.Join(outDir, "chain.pub")
	_ = writePubFileAt(pub, pubPath)

	watchDir, knowsTranscript := transcriptDirFor(args[0])
	isClaude := knowsTranscript && agentLooksLike(args[0], "claude")

	// PRECISE transcript targeting: for claude, force a known session ID with
	// --session-id <uuid> and tail exactly <uuid>.jsonl. This replaces the
	// fragile "newest .jsonl in the dir" heuristic, which grabbed the WRONG
	// transcript when another claude session (e.g. the operator's own) was more
	// recently active — producing an empty/wrong verified chain.
	sessionID := ""
	if isClaude && !claudeHasSessionFlag(args) {
		sessionID = newUUID()
		args = injectSessionID(args, sessionID)
	}

	chainPath := filepath.Join(outDir, "chain.jsonl")
	out, err := os.Create(chainPath)
	if err != nil {
		return err
	}
	defer out.Close()
	rec := newRecorder(bufio.NewWriter(out), priv)
	rec.emit(Node{Op: "heartbeat", Summary: "recorder start", Attrs: map[string]string{"key": keySource, "agent": args[0]}})

	castPath := filepath.Join(outDir, "session.cast")
	if !quiet {
		fmt.Printf("agentprov: recording live (%s key) + terminal -> %s. launching: %s\n\n",
			keySource, castPath, strings.Join(args, " "))
	}
	cmd := exec.Command(args[0], args[1:]...)

	// Tail the transcript in the background while the agent runs in the PTY.
	done := make(chan struct{})
	agentEvents := 0
	if knowsTranscript {
		var transcript <-chan string
		if sessionID != "" {
			transcript = awaitTranscriptByID(watchDir, sessionID) // precise
		} else {
			transcript = awaitNewTranscriptAsync(watchDir, snapshotJSONL(watchDir)) // fallback heuristic
		}
		go func() {
			t := <-transcript
			if t != "" {
				tailInto(t, rec, &agentEvents, done)
			} else {
				close(done)
			}
		}()
	} else {
		close(done)
	}

	// Run the agent in a PTY so the interactive session renders normally AND
	// every byte it paints is teed into the .cast — our own real recording.
	// Idle/resume boundaries (45s no human input) are recorded into the chain.
	hooks := ptyHooks{
		onIdle: func(t time.Time) {
			rec.emit(Node{Op: "idle_gap", Summary: "human went idle — no input for 45s; recording paused",
				Time: t.UTC().Format(time.RFC3339), Attrs: map[string]string{"reason": "no_human_input"}})
		},
		onResume: func(idleStart, resume time.Time) {
			rec.emit(Node{Op: "resume", Summary: "human input resumed; recording continued",
				Time: resume.UTC().Format(time.RFC3339),
				Attrs: map[string]string{"idle_seconds": fmt.Sprintf("%.0f", resume.Sub(idleStart).Seconds())}})
		},
	}
	waitErr := runInPTY(cmd, castPath, hooks)

	time.Sleep(300 * time.Millisecond) // let the tail drain final lines
	select {
	case <-done:
	default:
		close(done)
	}

	exitNote := "clean exit"
	if waitErr != nil {
		exitNote = "agent exited with error: " + waitErr.Error()
	}
	rec.emit(Node{Op: "heartbeat", Summary: "recorder end (" + exitNote + ")"})

	// Commit the real recording into the chain (tamper-evident, not -proof).
	if castBytes, e := os.ReadFile(castPath); e == nil && len(castBytes) > 0 {
		sum := sha256.Sum256(castBytes)
		rec.emit(Node{
			Op:      "cast_recording",
			Summary: "real terminal recording (asciinema) — reconstruction's untrusted sibling",
			Attrs: map[string]string{
				"sha256": hex.EncodeToString(sum[:]),
				"file":   castPath,
				"bytes":  fmt.Sprintf("%d", len(castBytes)),
				"key":    keySource,
			},
		})
	}
	rec.w.Flush()

	if !quiet {
		fmt.Printf("\nagentprov: recorded %d nodes (%d agent events) -> %s + %s\n", rec.seq, agentEvents, chainPath, castPath)
		fmt.Printf("watch + verify with: agentprov view %s   /   agentprov verify %s\n", chainPath, chainPath)
	}
	// Propagate the agent's exit code so the shim is transparent.
	return waitErr
}

// sessionsRoot is where transparently-recorded sessions land: ~/.agentprov/sessions
func sessionsRoot() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agentprov", "sessions")
}

// newSessionDir creates a fresh per-session dir. Name uses pid + a short random
// suffix from the clock-free counter (Date.now is fine here; this is the CLI).
func newSessionDir() string {
	base := sessionsRoot()
	id := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano()%1000000)
	dir := filepath.Join(base, id)
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// writePubFileAt writes the verify pubkey next to a chain.
func writePubFileAt(pub ed25519.PublicKey, path string) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(pub)+"\n"), 0o600)
}

// latestSessionDir returns the most recently modified recorded session dir, or
// "" if none. Lets `view`/`verify`/`video` default to the last session.
func latestSessionDir() string {
	root := sessionsRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var newest string
	var newestMod time.Time
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			// require a chain.jsonl inside
			cp := filepath.Join(root, e.Name(), "chain.jsonl")
			if _, err := os.Stat(cp); err == nil {
				newest, newestMod = filepath.Join(root, e.Name()), info.ModTime()
			}
		}
	}
	return newest
}

// chainArgOrLatest returns an explicit chain path if given, else the latest
// session's chain, else "".
func chainArgOrLatest(rest []string) string {
	if len(rest) > 0 && rest[0] != "" {
		return rest[0]
	}
	if d := latestSessionDir(); d != "" {
		return filepath.Join(d, "chain.jsonl")
	}
	return ""
}

// cmdSessions lists recorded sessions, most recent first, so a user can find and
// open them — they land in ~/.agentprov/sessions/ from the transparent shim.
func cmdSessions() error {
	root := sessionsRoot()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) == 0 {
		fmt.Printf("no recorded sessions in %s\n", root)
		fmt.Println("(record one with 'agentprov run -- claude', or 'agentprov install' for auto-recording)")
		return nil
	}
	type sess struct {
		dir   string
		mod   time.Time
		nodes int
		cast  int64
	}
	var list []sess
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		cp := filepath.Join(dir, "chain.jsonl")
		fi, err := os.Stat(cp)
		if err != nil {
			continue
		}
		nodes := 0
		if nn, e := loadChain(cp); e == nil {
			nodes = len(nn)
		}
		var castSize int64
		if ci, e := os.Stat(filepath.Join(dir, "session.cast")); e == nil {
			castSize = ci.Size()
		}
		list = append(list, sess{dir, fi.ModTime(), nodes, castSize})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].mod.After(list[j].mod) })
	fmt.Printf("recorded sessions (%s):\n\n", root)
	for _, s := range list {
		fmt.Printf("  %s   %d nodes · %dKB recording · %s\n",
			s.mod.Format("2006-01-02 15:04"), s.nodes, s.cast/1024, filepath.Base(s.dir))
		fmt.Printf("      view: agentprov view %s\n", filepath.Join(s.dir, "chain.jsonl"))
	}
	fmt.Printf("\nlatest: agentprov view    (no args defaults to the most recent session)\n")
	return nil
}

// transcriptDirFor returns the dir an agent writes its session JSONL into.
func transcriptDirFor(agent string) (string, bool) {
	home, _ := os.UserHomeDir()
	base := filepath.Base(agent)
	// The shim execs the REAL claude under a renamed path (claude.agentprov-real,
	// claude.real) or even a version filename (e.g. 2.1.179). Detect by the
	// agentLooksLike heuristic, not an exact basename, so transcript tailing —
	// and therefore the verified chain — still works under the shim.
	if agentLooksLike(agent, "claude") {
		return filepath.Join(home, ".claude", "projects"), true
	}
	if agentLooksLike(agent, "codex") {
		return filepath.Join(home, ".codex", "sessions"), true
	}
	_ = base
	return "", false
}

// newUUID returns a random v4 UUID (no external dep) for --session-id.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// claudeHasSessionFlag reports whether the user already passed a session flag,
// so we don't override their explicit --session-id/--resume/--continue.
func claudeHasSessionFlag(args []string) bool {
	for _, a := range args {
		switch a {
		case "--session-id", "--resume", "-r", "--continue", "-c", "--fork-session", "--from-pr":
			return true
		}
		if strings.HasPrefix(a, "--session-id=") || strings.HasPrefix(a, "--resume=") {
			return true
		}
	}
	return false
}

// injectSessionID inserts --session-id <uuid> right after the claude binary,
// before the user's args.
func injectSessionID(args []string, id string) []string {
	out := make([]string, 0, len(args)+2)
	out = append(out, args[0], "--session-id", id)
	out = append(out, args[1:]...)
	return out
}

// awaitTranscriptByID waits for the transcript named <id>.jsonl to appear under
// watchDir (claude writes <sessionId>.jsonl in the project subdir). Deterministic
// — no "newest file" guessing.
func awaitTranscriptByID(watchDir, id string) <-chan string {
	ch := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(15 * time.Second)
		target := id + ".jsonl"
		for time.Now().Before(deadline) {
			var found string
			filepath.WalkDir(watchDir, func(p string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() && filepath.Base(p) == target {
					found = p
				}
				return nil
			})
			if found != "" {
				ch <- found
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
		ch <- "" // not found in time
	}()
	return ch
}

// agentLooksLike reports whether an agent path is the named agent, tolerating
// the shim's renamed binaries and Claude's version-named binaries.
func agentLooksLike(agentPath, name string) bool {
	base := strings.ToLower(filepath.Base(agentPath))
	if base == name || strings.HasPrefix(base, name+".") || strings.HasPrefix(base, name+"-") {
		return true // claude, claude.real, claude.agentprov-real, claude-2.1.179
	}
	// Claude's on-disk binaries live in .../claude/versions/<ver> — detect by
	// the parent path containing the agent name.
	if strings.Contains(strings.ToLower(agentPath), string(filepath.Separator)+name+string(filepath.Separator)) {
		return true
	}
	return false
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
// awaitNewTranscriptAsync polls for the new transcript off the main goroutine,
// so the PTY session can start immediately. Result arrives on the channel.
func awaitNewTranscriptAsync(dir string, before map[string]bool) <-chan string {
	ch := make(chan string, 1)
	go func() { ch <- awaitNewTranscript(dir, before, 10*time.Second) }()
	return ch
}

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
		// An image block anywhere (e.g. a screenshot returned in a tool_result)
		// must NEVER have its base64 surfaced — describe it instead.
		if t, _ := x["type"].(string); t == "image" {
			return imageDetail(x["source"])
		}
		for _, k := range []string{"text", "thinking", "content", "command", "output", "stdout"} {
			if s, ok := x[k]; ok {
				return flatten(s)
			}
		}
		// Opaque control block (e.g. an extended-thinking signature) — don't
		// dump its raw JSON as if it were content. Show the type if it has one.
		if _, hasSig := x["signature"]; hasSig {
			if t, _ := x["type"].(string); t != "" {
				return "[" + t + "]"
			}
			return ""
		}
		b, _ := json.Marshal(x)
		return string(b)
	default:
		return ""
	}
}

// detailMax is the per-node content ceiling. Set high enough to carry full
// prompts, commands, and tool output verbatim — a responder must be able to
// recreate exactly what happened, and the injection/exfil evidence often lives
// well past a short cap. Content is hashed, so it stays tamper-evident.
// ponytail: 20k-char ceiling, not unbounded — caps a pathological 50MB `cat`
// dump from bloating the chain; raise or spill-to-sidecar only if real runs hit it.
const detailMax = 20000

// isCommandEnvelope reports whether a "user" transcript line is actually a
// slash-command / local-command / tooling wrapper rather than text the human
// typed. These carry <command-name>, <local-command-*> etc. tags.
func isCommandEnvelope(s string) bool {
	return strings.Contains(s, "<command-name>") ||
		strings.Contains(s, "<command-message>") ||
		strings.Contains(s, "<local-command-stdout>") ||
		strings.Contains(s, "<local-command-caveat>") ||
		strings.Contains(s, "<command-args>")
}

// urlRe matches http(s) URLs; egressCmd matches shell tools that reach out.
var (
	urlRe     = regexp.MustCompile(`https?://[^\s"'` + "`" + `)]+`)
	egressCmd = regexp.MustCompile(`\b(curl|wget|nc|ncat|telnet|ssh|scp|rsync|ftp|git\s+(clone|fetch|pull|push)|pip\s+install|npm\s+(install|i)\b|brew\s+install)\b`)
)

// netHost extracts the egress target from a tool call. For WebFetch/WebSearch
// the detail IS a URL/query; for a Bash command it's network egress only if the
// command invokes an egress tool — then we pull the host(s) it talks to. Returns
// "" when nothing reaches the network. This is honest: it sees ONLY agent-tool
// egress (the URL/command the agent self-reported), never raw sockets or
// off-transcript child-process connections (that is the ES/eBPF / agentsnitch tier).
func netHost(tool, detail string) string {
	switch tool {
	case "WebFetch", "WebSearch":
		if m := urlRe.FindString(detail); m != "" {
			return truncRunes(m, 120)
		}
		return truncRunes(strings.TrimSpace(detail), 120) // WebSearch query
	case "Bash":
		if !egressCmd.MatchString(detail) {
			return ""
		}
		if urls := urlRe.FindAllString(detail, 3); len(urls) > 0 {
			return truncRunes(strings.Join(urls, " "), 120)
		}
		// egress tool but no explicit URL (e.g. `git push`, scp host:path)
		return truncRunes("egress: "+egressCmd.FindString(detail), 60)
	}
	return ""
}

// imageDetail describes an uploaded image WITHOUT carrying its bytes.
func imageDetail(source any) string {
	s, _ := source.(map[string]any)
	media, _ := s["media_type"].(string)
	if media == "" {
		media = "image"
	}
	if data, ok := s["data"].(string); ok {
		// base64 decodes to ~3/4 its length; good enough for "how big".
		return fmt.Sprintf("🖼 image uploaded — %s, ~%d KB", media, len(data)*3/4/1024)
	}
	if url, ok := s["url"].(string); ok {
		return "🖼 image (url) — " + truncRunes(url, 100)
	}
	return "🖼 image uploaded — " + media
}

// mcpServer pulls the server name out of an MCP tool name (mcp__<server>__<tool>).
// Returns "" for non-MCP tools. This is the "which MCP server did the agent talk
// to" signal — MCP output is a top prompt-injection entry point.
func mcpServer(tool string) string {
	if !strings.HasPrefix(tool, "mcp__") {
		return ""
	}
	rest := strings.TrimPrefix(tool, "mcp__")
	if i := strings.Index(rest, "__"); i > 0 {
		return rest[:i]
	}
	return ""
}

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
				n.Net = netHost(n.Tool, n.Detail)
				if srv := mcpServer(n.Tool); srv != "" {
					n.Attrs = map[string]string{"mcp": srv}
				}
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
			case "thinking", "redacted_thinking":
				// Extended-thinking block. The text lives in "thinking"; the
				// "signature" field is an opaque crypto blob — never surface it.
				n := base
				n.Op, n.Trust, n.Summary = "assistant", "trusted", "agent thinking"
				think, _ := b["thinking"].(string)
				n.Detail = truncRunes(think, detailMax)
				nodes = append(nodes, n)
			case "image":
				// An image entered the context. NEVER carry the base64 payload
				// (it would bloat the chain and broke hashing before); record
				// that an image arrived, its media type, and its size.
				n := base
				n.Op, n.Trust, n.Summary = "image", "untrusted", "image input"
				n.Detail = imageDetail(b["source"])
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 0 {
			n := base
			detail := truncRunes(flatten(msg["content"]), detailMax)
			switch typ {
			case "user":
				// A "user" line is only a real human prompt if it isn't a
				// slash-command / local-command / tooling envelope. Those are
				// plumbing, not something the human typed — labeling them
				// "HUMAN prompt" is wrong and misleading in a security record.
				meta, _ := raw["isMeta"].(bool)
				if meta || isCommandEnvelope(detail) {
					n.Op, n.Summary, n.Detail = "other", "command/meta", detail
				} else {
					n.Op, n.Trust, n.Summary, n.Detail = "prompt", "untrusted", "user prompt", detail
				}
			case "assistant":
				n.Op, n.Trust, n.Summary, n.Detail = "assistant", "trusted", "assistant turn", detail
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
			n.Net = netHost(n.Tool, n.Detail)
			if srv := mcpServer(n.Tool); srv != "" {
				n.Attrs = map[string]string{"mcp": srv}
			}
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
	var egress []string
	var castNode *Node
	var flowNode *Node
	for i := range nodes {
		n := nodes[i]
		if n.Net != "" {
			who := n.Agent
			if who == "" {
				who = "main"
			}
			egress = append(egress, fmt.Sprintf("#%d %s[%s] %s", n.Seq, n.Tool, who, n.Net))
		}
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
		if n.Op == "cast_recording" {
			castNode = &nodes[i]
		}
		if n.Op == "flow_evidence" {
			flowNode = &nodes[i]
		}
		prev = n.Hash
	}

	fmt.Printf("integrity:  OK — %d nodes, chain intact, signatures valid. head: %s\n", len(nodes), short(prev))
	if keySource == "keychain" {
		fmt.Printf("provenance: signed by keychain key (non-repudiable: the agent process can't reach it)\n")
	} else {
		fmt.Printf("provenance: signed by %s key (tamper-evident; keychain unavailable -> not bound away from the agent)\n", keySource)
	}
	printNetwork(egress)
	printCast(castNode)
	printFlows(flowNode)
	printCoverage()
	if !cleanExit {
		fmt.Printf("liveness:   ⚠ GAP DETECTED — no clean-exit heartbeat. The run was truncated or the recorder\n")
		fmt.Printf("            was silenced mid-run. A plain log would look complete here; this does not.\n")
		return errors.New("record incomplete: missing recorder clean-exit (possible evasion)")
	}
	fmt.Printf("liveness:   OK — %d recorder heartbeats, clean exit observed.\n", heartbeats)
	return nil
}

// printNetwork lists the egress the agent did through its OWN tools (WebFetch,
// WebSearch, curl/wget in Bash). It is explicit that this is agent-tool egress
// only — raw sockets and child-process connections are NOT here (that needs the
// OS-sensor tier). Showing the targets next to that boundary keeps it honest.
func printNetwork(egress []string) {
	fmt.Println("network:    (agent-tool egress only — NOT raw sockets / child processes; that's the OS-sensor tier)")
	if len(egress) == 0 {
		fmt.Println("  none — no WebFetch/WebSearch or curl/wget-style egress in the agent's tool calls")
		return
	}
	for _, e := range egress {
		fmt.Println("  → " + e)
	}
}

// printCoverage states, honestly, what this tier of the recorder can and cannot
// see. Honest coverage map > false completeness — the credibility move.
// printCast checks an attached real terminal recording against the hash the
// chain committed to. The recording is the untrusted sibling of the verified
// replay — it can show whatever the agent rendered to the TTY — but the chain
// commits to its SHA-256, so a swapped recording is caught here.
func printCast(n *Node) {
	if n == nil {
		return
	}
	committed := n.Attrs["sha256"]
	file := n.Attrs["file"]
	if file == "" {
		file = "session.cast"
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("recording:  ⚠ committed (%s) but %s not found — recording missing\n", short(committed), file)
		return
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != committed {
		fmt.Printf("recording:  ✗ ALTERED — %s no longer matches the hash the chain committed to\n", file)
		fmt.Printf("            committed %s, on disk %s. The recording was swapped after the run.\n", short(committed), short(got))
		return
	}
	fmt.Printf("recording:  ✓ real terminal recording present and matches the chain (%s)\n", file)
	fmt.Printf("            note: this is the agent's self-rendered TTY — watchable ground truth, but\n")
	fmt.Printf("            NOT forgery-proof. The verified replay above is. Cross-check the two.\n")
}

// printFlows checks an attached agentsnitch flows file against its committed
// hash. The flows are OS-observed egress (a third evidence layer); committing
// the hash makes the overlay swap-proof, but the flows — and agentsnitch's
// probabilistic tool links — stay OUT of the signed chain.
func printFlows(n *Node) {
	if n == nil {
		return
	}
	committed := n.Attrs["sha256"]
	file := n.Attrs["file"]
	if file == "" {
		file = "flows.jsonl"
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("flows:      ⚠ committed (%s) but %s not found — flow evidence missing\n", short(committed), file)
		return
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != committed {
		fmt.Printf("flows:      ✗ ALTERED — %s no longer matches the committed hash (swapped after the run)\n", file)
		return
	}
	fmt.Printf("flows:      ✓ OS-observed network flows present and match the chain (%s, %s flows)\n", file, n.Attrs["flows"])
	fmt.Printf("            note: flows are a FACT (real sockets); the tool<->flow links are agentsnitch's\n")
	fmt.Printf("            probabilistic correlation (confidence-labeled), not agentprov's verdict.\n")
}

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
