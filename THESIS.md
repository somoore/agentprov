# agentprov — tamper-evident provenance recorder for AI coding agents

**Thesis:** The future of securing coding agents isn't preventing actions — it's making
them recorded and verifiable. Distrust the agent; trust the chain.

## What it is

A tamper-evident, cryptographically-chained causal record of an AI coding agent's session:

    untrusted input (file / issue / MCP response)
      -> prompt -> tool call -> tool response
      -> spawned process -> file access -> network egress

Every node carries provenance (where did this come from, is the source trusted). Every
edge is the captured causal link. The whole chain is hash-linked, so it can't be silently
rewritten. Emits OTel-compatible records any SIEM can ingest. The flight recorder, the
forensic record, and the anomaly sensor in one structure.

## Why this, why Scott (founder-market-fit, with code)

- Lived the pain: shipped Claude Code OTel telemetry from 100+ engineer clients into
  CrowdStrike NG-SIEM as a production contractor deliverable. Full IP ownership.
- Proven the spine in production: capture -> decode OTLP -> redact PII/PAN -> normalize ->
  ship to security tooling. That half is DONE and battle-tested (knowledge + owned code).
- The product is the GENERALIZED, clean-room version of that engine. Build fresh in this
  repo; reuse the knowledge, keep client-specific config (their CrowdStrike/infra) out.

## The four things the product adds over the internal pipeline (the moat)

| Internal pipeline (proven) | Product (the moat) |
|---|---|
| Claude-only | Cross-agent (Codex, Cursor, aider) behind a `Source` seam |
| HEC / CrowdStrike-coupled | Vendor-neutral OTel emit; any SIEM ingests |
| Trusts the telemetry | Tamper-evident hash-chain (+ signed checkpoints) |
| Logs + metrics | Causal provenance chain with trust labels per node |

## Decisions locked (the day's research)

- Threat model v1: **honest-but-injectable agent.** Unprivileged, consumes native surfaces
  (Claude OTel spans, Codex events, on-disk JSONL transcripts, hooks, optional MCP proxy).
  Root-level ES/eBPF is a higher-assurance *backend tier*, pulled by demand — NOT v1.
- Tamper-evidence = **Merkle/hash chain** locally; **sign checkpoints** with a key the agent
  can't reach (keychain/TPM) = non-repudiation against a popped agent; OPTIONAL
  transparency-log anchoring (RFC3161 / Rekor-style) of Merkle roots for third-party-provable
  timestamps. **NO blockchain** — deliberately, and saying why is a credibility signal.
- Standard posture: **extend OTel** (`gen_ai.*`, `execute_tool`, MCP spans) for plumbing;
  **invent** the security/taint/provenance semantics as custom attributes + span links.
  Nothing in OTel does provenance/trust today — that layer is unclaimed.
- Honest boundary (state it in the README): v1 = tamper-evident record of everything
  observable at the unprivileged surfaces, with discontinuities flagged. NOT a complete
  record of everything a popped agent did off-record. Completeness is the root-tier upgrade.

## Capture feasibility (verified on Scott's machine)

- Claude Code transcript: rich causal DAG already present — `assistant(tool_use, uuid) ->
  user(tool_result, parentUuid=uuid)`. We consume the causality, not infer it.
- Claude Code native OTel: real prompt->tool->exec span hierarchy, `prompt.id` / `tool_use_id`
  correlation, TRACEPARENT into subprocesses. Scott has a deployed OTLP decoder for this.
- Codex: flat events (`type`/`payload`/`timestamp`) + on-disk JSONL rollouts. Chain by order.

## Competitive position (verified)

- Category A (Langfuse/Arize/LangSmith/OpenLLMetry/Datadog LLM): crowded, INTERIOR
  (instrument your own code), dev/cost-focused. Not us.
- AgentSight: closest concept (outside-in, eBPF, security) but RESEARCH, no OTel, no
  tamper-evidence, no provenance chain. We productize + add the security spine.
- Metoro: shipping eBPF outside-in, but targets your-own-deployed k8s agents, not third-party
  coding-agent CLIs. Different subject.
- The exact open cell: outside-in + security-grade + OTel-emitting + cross-coding-agent +
  tamper-evident provenance. Unoccupied.

## Build order

- v0 (clean-room spike, in progress): consume a real agent record -> normalize to provenance
  nodes -> hash-chain -> emit OTel-shaped -> `verify` proves tampering breaks the chain.
  Source-agnostic spine (`normalize`/`chainHash`/`verify` don't care if input is JSONL or OTel).
- v1: sign checkpoints (key outside the agent); cross-agent (add Codex `Source`); README
  with the honest boundary; the "inject an agent -> replay the tamper-evident causal chain ->
  show a forged event fails verify" demo.
- later (demand-pulled): MCP proxy source, behavioral fingerprinting/anomaly, transparency-log
  anchoring, root-tier ES/eBPF backend for the adversarial threat model.
