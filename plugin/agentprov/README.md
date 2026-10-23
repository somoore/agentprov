# agentprov — Claude Code plugin

Records every Claude Code session into a **signed, tamper-evident provenance
chain**, and tells the user the session is monitored. The provenance layer of
[agentprov](../../README.md), deployable as a one-time plugin install.

## What it does

- **SessionStart hook** → prints a "this session is recorded" banner to the user.
- **SessionEnd hook** → hands `agentprov hook-record` the session's exact
  `transcript_path`, which records the signed verified chain into
  `~/.agentprov/sessions/<session-id>/`. No transcript guessing — the hook gives
  us the precise path.
- **`agentprov-review` skill** → lets Claude verify + summarize a recorded
  session (integrity, what the agent did, untrusted-input entry points, network
  egress) as a forensic reviewer.

Once enabled, it applies to **all future sessions** on that machine — the fleet
deployment vehicle for the provenance chain.

## What it does NOT do

A plugin/hook runs **inside** the already-running Claude process, so it cannot
parent Claude — and therefore **cannot capture the terminal recording** (the
`.cast` real-replay). Proven: a non-parent process can't read the PTY output.
For the full terminal recording, use the transparent shim instead:

```
agentprov install     # wraps `claude` to also capture the real terminal
agentprov uninstall    # reverse
```

The two layer cleanly by trust tier:
- **plugin** = signed provenance chain + monitored banner, on every session
- **shim** = optional full terminal recording on top, where you deploy it

## Install (the binary)

The plugin invokes `bin/agentprov`. Build it for your platform:

```
cd ../..          # repo root
go build -o plugin/agentprov/bin/agentprov .
```

The build auto-selects the patched toolchain pinned in `go.mod` (`toolchain go1.27.3`),
which requires macOS 13+ (Go 1.27 dropped macOS 12). The committed `bin/agentprov`
has the same requirement.

(For fleet/MDM distribution, ship a Developer-ID-signed, notarized binary —
ad-hoc signing only works on the building machine.)

## Review a session

```
agentprov sessions                 # list recorded sessions
agentprov view                     # open the latest in the browser viewer
agentprov verify                   # verify the latest chain
```

Or ask Claude: *"review my last agentprov session"* → the `agentprov-review`
skill verifies and summarizes it.
