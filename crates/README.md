# agentprov — Rust capture core

A library-first, dependency-minimal Rust workspace that captures an AI coding
agent's terminal session into a **signed, tamper-evident** record. Built per the
architecture in the rewrite proposal: a tiny auditable trusted path, with
replay/viewer/export/collectors layered on top as optional convenience.

## Trust split

The thesis is **"distrust the agent; trust the chain."** That holds only because
the trust anchor lives where the agent can't forge it:

- The capture is a per-frame **sha256 hash chain** (consistency).
- The chain **tip is ed25519-signed** with a keychain-bound key (authenticity).
- **The CLI authenticates the signed tip before every display surface**
  (`cast`, `view`, `export`) against a *trusted* key — the machine keychain
  on-box, or a `--pubkey` pin obtained out-of-band off-box. The bundled
  `.pub`/`.sig` sidecars are never trusted on their own, so a re-forged +
  re-signed capture is refused.

  Note: this gate is enforced at the **CLI layer**, not inside the
  `agentprov-viewer` / `agentprov-replay-core` library components — those verify
  the keyless chain (consistency) but do not check the signature themselves. A
  direct library consumer must authenticate the tip itself (via
  `agentprov-integrity`) as the CLI does. Threading the trusted key into
  `viewer::serve` to make the component self-enforcing is deferred follow-up.

A keyless chain alone only catches accidental corruption; the signed tip is what
catches an adversary who recomputes the chain or truncates frames.

## Crates (build/dependency tiers)

| Crate | Tier | Deps | Role |
|---|---|---|---|
| `agentprov-capture-format` | 0 (trusted) | sha2 | Frozen APCAP v0 framed format + hash chain + fail-closed verify |
| `agentprov-pty-core` | 0 (trusted) | rustix, libc | Spawn child under a PTY, raw-mode tee, record frames, preserve exit code |
| `agentprov-integrity` | 0 (trusted) | ed25519-dalek | Sign/verify the chain tip; keychain-bound seed |
| `agentprov-replay-core` | 1 | — | APCAP → asciicast v2, summarize, range/seek (always chain-verified) |
| `agentprov-collectors` | 2 | serde, serde_json | Normalize agentsnitch network flows into a trust-labeled overlay + EvidenceSink |
| `agentprov-viewer` | 2 | getrandom | Hardened loopback HTTP viewer (token, CSP, no remote assets, no path traversal) |
| `agentprov-export` | 2 | — | APCAP → gif/mp4 via agg + ffmpeg, from a sanitized copy (never the evidence) |
| `agentprov-cli` | — | (all) | `run` / `verify` / `cast` / `view` / `export` / `flows` |

The Tier-0 trusted path is small enough to audit in an afternoon (≈15–18 crates
incl. transitive, no tokio / serde / regex / http).

## Usage

```
agentprov-rs run    --out session.apcap -- claude        # capture + sign
agentprov-rs verify [--pubkey <hex>] session.apcap       # chain + signature
agentprov-rs cast   session.apcap > session.cast         # authenticated → asciicast
agentprov-rs view   session.apcap                        # authenticated → loopback viewer
agentprov-rs export gif session.apcap session.gif        # authenticated → gif/mp4
agentprov-rs flows  events.jsonl flows/                  # agentsnitch overlay
```

`cast`/`view`/`export` refuse a forged or unauthenticated capture; pass
`--allow-unsigned` to downgrade unsigned/untrusted to a warning.

## Library use

The trusted core is library-first — every API takes `Read`/`Write`, not paths,
so you can feed a file, a socket, or an in-memory buffer. Capture a command,
then verify and re-walk the signed chain:

```rust
use agentprov_pty_core::CaptureSession;
use agentprov_capture_format::{verify, FrameType};
use agentprov_integrity::{Signing, to_hex};
use std::path::PathBuf;

// 1. Capture a child under a PTY into an APCAP file.
let out = PathBuf::from("session.apcap");
let result = CaptureSession::new("echo".into(), vec!["hi".into()], out.clone()).run()?;
println!("captured {} frames, exit {}", result.frames_written, result.exit_code);

// 2. Verify the hash chain and grab the tip (last frame's hash).
let mut tip = [0u8; 32];
let bytes = std::fs::read(&out)?;
verify(&bytes[..], |f| {
    tip = f.frame_hash;
    if f.frame_type == FrameType::PtyOutput { /* … */ }
})?; // Err on any tamper/truncation — fail-closed

// 3. Sign the tip with a keychain-bound ed25519 key → tamper-evidence.
let signer = Signing::load_or_create();
std::fs::write("session.apcap.sig", to_hex(&signer.sign_tip(&tip)))?;
std::fs::write("session.apcap.pub", to_hex(&signer.public_key()))?;
```

`agentprov-replay-core` turns the same APCAP into asciicast v2
(`to_asciicast`), a summary (`summarize`), or a per-frame audit log
(`frame_log`) — all chain-verified first.

## Known limitations (honest, in-code)

- **Keychain is defense-in-depth, not airtight.** The macOS keychain ACL trusts
  `/usr/bin/security`, so a same-user process (incl. the captured agent) can read
  the seed without a prompt. A hardware key or a separate-uid signing daemon would
  close this. It defends off-machine attackers and casual tampering.
- **One Resize frame at startup**, no live SIGWINCH (avoids a signal-handling dep).
- **Viewer CSP** allows `script-src 'wasm-unsafe-eval'` — asciinema-player's
  terminal emulator is WASM. No inline scripts, no remote origins; documented
  deviation from the otherwise strict policy.
- Deferred per the proposal: `S3MultipartSink` / `HTTPSCollectorSink` (the
  `EvidenceSink` trait + `LocalDirectorySink` are in place for them).
- Deferred from the proposal's security/format **prose** (not its build list):
  fuzz + malicious-ANSI/OSC corpus tests for the frame parser (it is strict and
  bounded but not yet fuzzed), and the two-level anchoring model where a
  higher-level event chain references APCAP frame *ranges* by root hash
  (event → frame_NNN..frame_MMM). The single signed tip is the current anchor.
- Signature enforcement lives in the CLI, not the viewer/replay components
  (see the trust-split note above).
