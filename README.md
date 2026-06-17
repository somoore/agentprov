# agentprov

**A tamper-evident flight recorder for AI coding agents.**

Wrap any coding agent (Claude Code, Codex). `agentprov` records what it does into a
hash-chained, signed record that survives the agent — or the container — exiting. Afterward
you can prove what happened, and prove the record wasn't altered.

> The future of securing coding agents isn't preventing actions — it's making them recorded
> and verifiable. **Distrust the agent; trust the chain.**

## Why

Security teams are piping AI coding agent telemetry into their SIEM. But a SIEM dump and a log
file share a fatal weakness for this threat model: **if the agent is prompt-injected or
compromised, the telemetry it self-reports is exactly the data you can't trust** — it can be
altered, truncated, or silenced, and the gap looks identical to "the user went to lunch."

`agentprov` doesn't trust the agent. It makes the *record* trustworthy:

- **Tamper-evident** — every event is hash-chained. Alter or delete one and verification fails.
- **Gap-detecting** — the recorder emits its own heartbeats. If the agent goes dark mid-run,
  the record shows the discontinuity. *A plain log would look complete here; this doesn't.*
- **Non-repudiable** — the chain is signed by a key in the macOS keychain the agent process
  can't reach. A compromised agent can't forge a chain that verifies.

It's unprivileged, single-binary, and honest about its blind spots (see Coverage).

## Demo — the three proofs

Build it:

```bash
go build -o agentprov .
```

**Record a real agent run, live:**

```bash
$ agentprov run -- codex exec 'add a multiply function to calc.py'
agentprov: recording live (keychain key). launching: codex exec ...
... codex runs, edits files, exits ...
agentprov: recorded 25 nodes (23 agent events) -> chain.jsonl
```

**1. It verifies clean:**

```bash
$ agentprov verify chain.jsonl
integrity:  OK — 25 nodes, chain intact, signatures valid. head: 9fdb44aab62b
provenance: signed by keychain key (non-repudiable: the agent process can't reach it)
coverage:
  ✓ covered  : prompts, tool calls, tool results, run start/end (agent self-reported transcript)
  ✗ blindspot: off-transcript subprocess egress, raw sockets, file writes by spawned children
liveness:   OK — 2 recorder heartbeats, clean exit observed.
```

**2. Tamper with it → caught.** Alter any recorded event:

```bash
$ agentprov tamper chain.jsonl 7
$ agentprov verify chain.jsonl
agentprov: CHAIN BROKEN at seq 7: content ALTERED (recomputed e60c... != stored 293d...)
```

Or delete an event entirely — also caught:

```bash
$ agentprov drop chain.jsonl 5
$ agentprov verify chain.jsonl
agentprov: CHAIN BROKEN at seq 6: a node was DROPPED, inserted, or reordered
```

**3. The agent goes dark → caught.** The record still hashes correctly, but the recorder's
clean-exit heartbeat is missing — so `verify` flags it as a gap a plain log would have missed:

```bash
$ sed '$d' chain.jsonl > truncated.jsonl     # simulate the run being silenced
$ agentprov verify truncated.jsonl
integrity:  OK — chain intact, signatures valid.
liveness:   ⚠ GAP DETECTED — no clean-exit heartbeat. The run was truncated or the recorder
            was silenced mid-run. A plain log would look complete here; this does not.
```

## What it records

Each node is a provenance event with a **trust label**:

| op | trust | meaning |
|---|---|---|
| `prompt` | untrusted | a user/instruction prompt |
| `tool_call` | trusted | the agent invoking a tool (Bash, edit, exec) |
| `tool_result` | **untrusted** | a tool's output — where external content (file/web/MCP) enters |
| `assistant` | trusted | an agent turn |
| `heartbeat` | — | emitted by the recorder; absence = gap |

`tool_result` is labeled untrusted on purpose: it's the entry point for prompt-injection
content. The Claude transcript's `parentUuid`/`uuid` causal links are preserved, so the chain
is a causal record, not just a flat log.

## Coverage (the honest boundary)

v1 records what the agent **self-reports** through its transcript — prompts, tool calls, tool
results, run start/end. It does **not** see what bypasses that surface: raw sockets, off-
transcript subprocess egress, file writes by spawned grandchildren. Those require kernel-level
instrumentation (macOS Endpoint Security / Linux eBPF) and root — a deliberate later tier.
`verify` prints these blind spots every time rather than implying completeness.

## Usage

```
agentprov run -- <agent...>      live: wrap a real agent, record, verify on exit
agentprov record <transcript>    record a past Claude/Codex transcript JSONL
agentprov verify <chain.jsonl>   integrity + signatures + coverage + liveness
agentprov tamper <chain> <seq>   demo: alter a node so verify fails
agentprov drop   <chain> <seq>   demo: drop a node so verify fails
```

Supported agents: Claude Code (`claude`), Codex (`codex`). macOS for the keychain-bound key;
elsewhere it falls back to an ephemeral key and says so.

## Status

Experimental. A working proof of the thesis, not a product. No dependencies beyond the Go
standard library.
