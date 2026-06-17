# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`agentprov` is a tamper-evident **flight recorder** for AI coding agents. It wraps a real
agent run (Claude Code, Codex), records the agent's activity into a hash-chained, signed
record that survives the agent/container exiting, and lets you prove afterward what happened
and prove the record wasn't altered. Single Go file, no dependencies, unprivileged.

The thesis: *the future of securing coding agents isn't preventing actions — it's making
them recorded and verifiable. Distrust the agent; trust the chain.*

## The three properties that make it a flight recorder (not a log file)

Any change here must preserve all three — they ARE the product:

1. **Tamper detection** — `contentHash` chains each node to the previous (`prev_hash`), so
   altering or reordering any node breaks `verify`. Do not change the hash input fields in
   `contentHash` without updating `verify` identically.
2. **Gap detection** — the *recorder* (not the agent) emits `heartbeat` nodes on a cadence
   and a final `clean exit` heartbeat. A run that goes dark lacks the clean-exit heartbeat;
   `verify` flags it as possible evasion. A plain log would look complete; this doesn't.
3. **Non-repudiation** — nodes are signed with an ed25519 key whose seed lives in the macOS
   keychain (`keychainService`), unreachable by the agent process. A popped agent can't forge
   a chain that verifies. Falls back to an ephemeral key off-macOS and *says so* in `verify`.

## Architecture (one file: main.go)

- `Node` / `recorder` / `contentHash` — the signed hash chain. `emit` flushes per-node so the
  record survives an abrupt exit.
- `normalize` — maps a raw transcript line to provenance node(s). **Claude** carries the causal
  DAG (`uuid`/`parentUuid`) and `tool_use`/`tool_result` blocks; **Codex** nests the real kind
  under `payload.type` (envelope `type` is `response_item`/`event_msg`). `tool_result` is labeled
  `untrusted` — it's where external content (file/web/MCP) enters. This trust labeling is the
  provenance layer; keep it honest.
- `cmdRun` — the live path: launch the agent, find the new transcript in its dir
  (`transcriptDirFor` → `~/.claude/projects` or `~/.codex/sessions`), `tailInto` it, emit a
  clean-exit heartbeat on process exit.
- `cmdVerify` — integrity → signatures → coverage map → liveness. `printCoverage` states blind
  spots honestly (off-transcript subprocess egress needs the privileged ES/eBPF tier).
- `cmdMutate` (`tamper`/`drop`) — the demo harness that proves verify fails on a forged/dropped
  node. This is how the README demo and any test must exercise integrity.

## Commands

```bash
go build -o agentprov .
go vet ./...

./agentprov run -- codex exec 'add a test'   # live: wrap a real agent, record, verify on exit
./agentprov record <transcript.jsonl>        # record a past Claude/Codex transcript
./agentprov verify chain.jsonl               # integrity + signatures + coverage + liveness
./agentprov tamper chain.jsonl <seq>         # demo: alter a node -> verify fails
./agentprov drop chain.jsonl <seq>           # demo: drop a node -> verify fails
```

## Honest-boundaries discipline (do not violate)

This is a security tool; its credibility comes from stating what it does NOT do. v1 records
what the agent **self-reports** via its transcript. It does not see off-transcript actions
(raw sockets, subprocess egress, file writes by spawned children) — those are the privileged
ES/eBPF tier, explicitly out of scope for v1 and **labeled as blind spots** in `verify`. Never
make a completeness claim the transcript surface can't back. Over-claiming is the failure mode.

## Verify changes the way the spike does

Any non-trivial change should still pass the three live proofs: record a real run → `verify`
passes → `tamper`/`drop` a node → `verify` fails → truncate the clean-exit heartbeat →
`verify` flags the gap. That sequence is the regression test; keep it runnable.
