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

---

## Target architecture (backwards from the enterprise customer)

Designed from Scott's operational experience running Claude Code OTLP -> CrowdStrike for 100+
clients. The whole design is shaped by four buyer concerns, in priority order: **trust**
(stays in their boundary), **friction** (no rip-and-replace, low marginal cost), **scale**
(don't build the ingest dragon), **cost** (cheap by default).

### Data plane (deterministic — the critical path)

```
claude/codex  ->  user/home IP  ->  native OTLP  ->  WAF  ->  API Gateway  ->  Lambda
                                                                                  |  (in THEIR VPC)
                                                                                  |  1. decode protobuf
                                                                                  |  2. redact (deterministic: pattern-match secrets/PII/PAN — NOT judgment)
                                                                                  |  3. HASH-CHAIN + SIGN     <- integrity established at ingest, in their boundary
                                                                                  |  4. FAN OUT (dumb, no judgment, no filtering — rate CONSERVED 1:1):
                                                                                  +--> HEC -> SIEM                  (analyst's existing world: Splunk / CrowdStrike / Sentinel)
                                                                                  +--> Kinesis Firehose -> S3      (our fork; Firehose absorbs the conserved rate, batches to S3)
```

(See "The receiving tier on OUR fork" below for why Firehose, not S3-direct or a DB, on the
high-rate fork. S3 is still the resting place / system of record; Firehose is the shock absorber
in front of it. Security Lake/OCSF remains an optional alternate sink for customers who run it.)

This reuses Scott's existing, proven Lambda (decode + redact + HEC). The ONE new step is
hash-chain + sign before fan-out. Signing key in the Lambda's KMS/Secrets Manager — unreachable
by the agent, a stronger anti-tamper posture than the endpoint keychain. Honest boundary: this
attests "intact from the ingestion point onward" (catches anything in/after the SIEM), not
"from the endpoint" — the endpoint->Lambda hop is unsigned native OTLP. Endpoint-signing is a
later premium tier; Lambda-signing is the zero-endpoint-footprint default.

### The sinks (cheap-by-default, sink-agnostic)

The fan-out target is CONFIGURABLE; the product does not bet on one sink. Let the buyer's
existing cost/data posture choose:
- **Default: plain S3** — partitioned by session/date, your metadata layout. Cheap, write-heavy/
  read-thin-friendly (exactly the agent-telemetry workload shape), customer already knows it,
  near-zero marginal cost. Demo path AND recommended path. Chain fields ride as columns.
- **Optional: AWS Security Lake (OCSF)** — only for customers who ALREADY run it. Then it's free
  adoption of infra they pay for + agent data becomes first-class next to CloudTrail/GuardDuty.
  Do NOT make it load-bearing: Security Lake bills per-GB on ingest whether or not anyone queries
  (worst case for write-heavy/read-thin), and that's the CUSTOMER's bill — i.e. a sales objection.
- **Schema without the service:** write OCSF-shaped Parquet to plain S3 to get the queryable-
  next-to-everything benefit at S3 cost. Tamper-evidence fields (hash/sig/prev_hash) are OCSF
  extensions either way.
- Multi-cloud / non-AWS: the plain-sink path generalizes (Azure Blob + Sentinel, etc.);
  Security Lake does not.

### Why fork-at-Lambda beats tap-after-ingest

Two ways to get the data for analysis: query it back out of the SIEM, or fork a copy at the
Lambda. **Fork wins** for the scale concern: SIEM query APIs are rate-limited and built for
alert-triggered investigation, NOT continuous analysis (Splunk REST 50k-row cap; Graph Security
~45 calls/min/tenant). The protobuf is already decoded in the Lambda, so a second output is
nearly free, and you control your own sink's scale instead of being throttled. Caveat that makes
it safe: "us" must be a sink the CUSTOMER owns inside THEIR cloud, never a vendor SaaS endpoint —
or you lose the "we never touch your data outside your boundary" trust win.

"Read the customer's existing SIEM as your source" is itself a proven, mainstream pattern (the
entire 2025-26 AI-SOC category: Dropzone, Prophet, Radiant; SIEMs ship purpose-built query APIs
for it). Fork-at-Lambda is the lower-latency, scale-friendly variant of the same posture.

### The receiving tier on OUR fork (the architecture-correctness decision)

The concern that drove this: **what receives our fork without us owning a capacity tier that
falls over under load?** The load is REQUEST RATE, not bytes. Key facts established:

- **Volume is tiny** (~1MB/day/client metadata stream; ~3GB/mo at 100 clients = pennies). Storage
  cost is a non-issue. **The real constraint is request rate, not storage.**
- **The rate is CONSERVED, 1:1, end to end.** One OTLP event in -> one Lambda invocation ->
  one transform -> one write to EACH destination. Lambda scales to *survive* the rate but does
  NOT *shrink* it (no batching/culling; malformed reqs are rejected at WAF/API-GW before Lambda,
  a rounding error). So our sink sees the FULL per-event rate (thousands/sec sustained), same as
  HEC does. (Earlier claim that "Lambda absorbs/calms the rate before the fork" was WRONG.)
- **Therefore the receiver must absorb the conserved per-event rate as a MANAGED service we own
  no capacity for.** Ranked: S3 can take the rate but one-tiny-object-per-event at thousands/sec
  is an anti-pattern (per-PUT cost + millions of tiny objects). A DATABASE on the path is the
  foot-gun (Lambda->RDS connection storms; RDS Proxy exists because this is a known problem) —
  this is the capacity-bottleneck-you-own risk, correctly flinched at. EC2/ECS/EKS = you operate
  the scaling tier = max risk.

**Answer: Kinesis Data Firehose is the missing shock-absorber.** It accepts the conserved
per-event rate (fully managed, zero capacity for us to own), BUFFERS/BATCHES by size or time,
and delivers tidy batched objects to S3. Cheap (~$0.029/GB; negligible at this volume). It is
the purpose-built tier between a high-rate 1:1 source and a sink that doesn't want one-object-
per-event.

```
Lambda (1:1, per event) --fork--> HEC -> SIEM
                          \------> Kinesis Firehose --(buffer/batch)--> S3 (batched session objects)
```

The PRINCIPLE: the receiving tier must be a managed service we cannot overwhelm; anything with a
capacity ceiling WE own (a DB, a compute pool) must live BEHIND the fork, fed at a rate we
control — never exposed to the conserved firehose.

### What we do with it (processing = mostly LAZY, at investigation time)

"Process" is four distinct jobs at different times. Only one runs in the background:

1. **Verify the chain (deterministic — the verdict).** Recompute the hash chain for a session.
   Done **ON-READ, lazily** — only when a human/incident actually looks at a session. You don't
   prove integrity of a session nobody's reading; you prove it at the moment it matters. Fast
   (SHA-256 over one session). Kills an always-on verification tier.
2. **Promote a thin queryable INDEX into Postgres (the only background job, and it's small).**
   S3 batch lands -> S3 event -> tiny loader Lambda -> upsert session METADATA rows into Postgres
   (who/when/which agent/repo/#tool-calls/integrity-status/gap-or-not). Loaded per-batch at a
   CONTROLLED rate, so the DB never sees the per-event firehose — connection-storm risk avoided
   by construction. **Postgres is the searchable index of sessions; S3 is the full record.**
3. **Surface it (read-time, on-demand).** Dashboard/console-app/viewer queries Postgres to FIND
   the session worth investigating, then fetches full events from S3 for that session. No
   background compute.
4. **Analyze it (off-path, labeled, optional, on-demand).** AI summaries, "find similar sessions"
   — runs WHEN an analyst asks, never continuously, never a verdict. pgvector (added to the same
   Postgres) is the lazy embedding path; embed only the sliver investigated, not the firehose.

```
Firehose -> S3 (batched events = durable, complete record)
              |-- S3 event -> loader Lambda -> Postgres   [job 2: thin metadata index, per-batch, cheap]
              \-- on-demand at investigation time (no background compute):
                    analyst opens dashboard -> query Postgres -> pick a session ->
                      fetch full events from S3 -> VERIFY chain [job1] -> render [job3]
                      -> optional AI summary / similar-session retrieval [job4, labeled, off-path]
```

The whole model is the flight-recorder principle applied to compute: **record everything cheaply
now (Firehose->S3), process the sliver you investigate later.** The ONLY always-on processing is
the small per-batch loader Lambda. Everything expensive or probabilistic (verify, analyze, embed)
is lazy, at read-time, on a tiny working set.

DECISION (default): Postgres holds session METADATA only (enough to find a session); full events
+ verification come from S3 on click. Load richer event content into Postgres only IF analysts
need to query across event bodies ("every session that ran curl"). Start minimal.

### Read / analysis plane (probabilistic — OFF the critical path)

```
customer-owned sink (S3 / Security Lake)
        |
  [agentprov analyzer / reader]   <- reads as a GOVERNED SUBSCRIBER (Lake Formation grant, etc.)
        |  - VERIFY the chain (deterministic — the verdict)
        |  - surface to the analyst (the human's existing world)
        |  - AI-as-analyst: LABELED, ASSISTIVE, walled off — summaries & leads for a human,
        |    NEVER a verdict, NEVER fed back into the record or the SIEM events as fact
        |  - retrieval index (S3 Vectors / embeddings): "find sessions like this" — assistive
        |    search only, NOT detection; embed LAZILY (the sliver investigated), not the firehose
```

### Product surface: click-to-install app in the customer's SIEM/EDR console

Meet the buyer in the console they already use. Researched install surfaces:
- **Splunk (Splunkbase):** full — bundled dashboards + custom search commands. Scott knows this.
- **CrowdStrike Foundry (app catalog):** full + STRONGEST FIT — native dashboards + serverless
  Functions (Python, can call external APIs / run chain verification in-platform). Scott's Lambda
  already feeds CrowdStrike, so the whole loop can live in their boundary on their compute.
- **Microsoft Sentinel (Content Hub / Solutions):** qualified — workbooks + KQL/Logic-Apps, not
  arbitrary code.
- **SentinelOne:** outlier — no click-to-install third-party dashboard app (manual GitHub import).
- Tradeoff: the tap+display layer FORKS per SIEM (real cost); the recorder + chaining stay shared
  in the Lambda. Most AI-SOC vendors chose one-analyzer/many-thin-connectors to avoid this.
  Start with ONE SIEM (CrowdStrike Foundry or Splunk — whichever has the warmer path).
  The browser `viewer.html` already built is the seed of the in-console dashboard.

### The load-bearing rules (the discipline that keeps it a security product, not a guesser)

1. **Deterministic in the path; probabilistic off the path.** The ingest Lambda is DUMB:
   decode, redact, sign, fork. It never classifies, filters, scores, or judges — a classifier in
   the ingest path is IFC relocated to the worst possible spot (it silently decides completeness,
   breaking the one guarantee). All judgment happens after the fork, labeled as analysis.
2. **Customer-owned sinks only.** Every destination is in the customer's boundary. No vendor SaaS
   in the data path. This is the trust spine.
3. **AI/embeddings assist, never verdict.** AI summarizes and retrieves over the proven record for
   a human; vector similarity FINDS, it does not JUDGE. The verdict is always the deterministic
   chain. (The reason IFC was removed — do not reintroduce it through the analysis or vector layer.)
4. **Cheap by default, sink-agnostic.** S3 + lazy embedding over Security Lake + eager normalize.
   Match cost to actual use; the write-heavy/read-thin workload demands it.
5. **Differentiation is vertical depth + integrity, not "AI SOC analyst" (saturated).** Generalist
   AI-SOC tools read everything shallowly; agentprov reads AGENT telemetry deeply with a tamper-
   evidence guarantee none of them offer. Depth in a vertical + the integrity chain is the wedge.
6. **The receiving tier on our fork must be un-overwhelmable (managed); capacity-bounded tiers we
   own (DB, compute) live BEHIND the fork, fed at a rate we control.** The per-event rate is
   conserved 1:1 through the Lambda — Firehose absorbs it and batches to S3; Postgres sits behind
   S3, loaded per-batch, never exposed to the firehose.
7. **Process lazily, at investigation time.** Flight-recorder principle applied to compute:
   capture everything cheaply now, verify/analyze/embed the sliver you investigate later. The only
   always-on processing is a tiny per-batch metadata-loader Lambda; everything else is on-read.

### Status of this architecture

Design only — NOT built. The shipped artifact today is the local recorder + viewer (deterministic
spine, proven). This section captures the backwards-from-customer target so it survives context.
Build nothing here until a real customer pulls it; the hardest piece (the ingest Lambda) is
already operationally proven by Scott's prior work (knowledge owned; that client's code stays
theirs — clean-room rebuild).
