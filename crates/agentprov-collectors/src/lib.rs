//! agentprov-collectors — Tier-2 evidence ingestion for the flow overlay.
//!
//! This crate ingests OS-observed network flows from `agentsnitch` and
//! normalizes them into a timeline overlay that aligns with an APCAP capture.
//!
//! **Trust model (load-bearing — preserve this distinction in types and comments):**
//!
//! - The *flow itself* is a fact: the OS saw a real socket open on the wire.
//! - The *link to a tool call* is agentsnitch's probabilistic correlation,
//!   expressed as `linked_tool`, `confidence`, and `why`. These are carried
//!   **as-is from agentsnitch** — they are THEIR claim, never our verdict.
//!   We do not promote, demote, or corroborate them.
//!
//! Callers must preserve this label boundary. When presenting the overlay
//! alongside a capture, the flows are a separate evidence layer, weaker than
//! the signed APCAP chain.

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Public types ──────────────────────────────────────────────────────────────

/// One OS-observed network connection from agentsnitch, normalized for the
/// replay overlay. It is a *third evidence layer*: the flow itself is a fact
/// (a real socket the OS saw), but the link to a tool call is agentsnitch's
/// probabilistic correlation — **carried with its confidence, never as our
/// verdict**.
///
/// Fields `linked_tool`, `confidence`, and `why` are agentsnitch's claims,
/// carried as-is. We do not validate them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Flow {
    /// UTC timestamp — aligns to the APCAP chain timeline.
    pub ts: String,
    /// Best hostname/SNI available (SNI → hostname → PTR → remote ip:port).
    pub host: String,
    /// Raw ip:port. Omitted from JSON when empty (matches Go `omitempty`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remote: String,
    /// Direction observed by agentsnitch: "out" | "in".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub direction: String,
    /// Process ID as reported by agentsnitch.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub pid: i64,
    /// Bytes sent outbound, as reported by agentsnitch.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub bytes_out: i64,
    /// Transport protocol (e.g. "tcp", "udp").
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    /// agentsnitch's associated tool-use id. THEIR claim, carried as-is.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub linked_tool: String,
    /// agentsnitch's link confidence: "low" | "med" | "high". THEIR claim,
    /// carried as-is — not validated or corroborated by this crate.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub confidence: String,
    /// agentsnitch's human-readable reason for the correlation. THEIR claim,
    /// carried as-is — we make no judgment about its accuracy.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub why: String,
    /// Sensor path identifying which agentsnitch observer emitted this event
    /// (e.g. "network_statistics", "lsof").
    #[serde(skip_serializing_if = "String::is_empty")]
    pub observer: String,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

// ── agentsnitch wire types (private deserialize helpers) ──────────────────────

/// Outer envelope: `{"schema":"...transcript.v0","kind":"correlated|network","event":{...}}`
#[derive(Deserialize)]
struct AsnEnvelope {
    kind: String,
    event: serde_json::Value,
}

/// kind = "network" — a single OS-observed flow event.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AsnFlowEvent {
    ts: String,
    remote: String,
    /// Field name in the wire format is "hostname" (not "host").
    #[serde(rename = "hostname")]
    host: String,
    sni: String,
    ptr_hostname: String,
    direction: String,
    pid: i64,
    bytes_out: i64,
    protocol: String,
    observer: String,
}

/// kind = "correlated" — agentsnitch's probabilistic link between tool-use and flows.
#[derive(Deserialize, Default)]
#[serde(default)]
struct AsnCorrelated {
    ts: String,
    /// agentsnitch's link confidence. THEIR claim; we carry it, not verify it.
    confidence: String,
    /// agentsnitch's summary of WHY it made the correlation. THEIR claim.
    summary: String,
    semantic_ids: Vec<String>,
    flows: Vec<AsnFlowEvent>,
}

// ── Core logic ────────────────────────────────────────────────────────────────

/// Pick the best display hostname for a flow, mirroring Go's `bestHost`:
/// SNI → hostname → PTR → remote (all trimmed; fallback is untrimmed remote).
fn best_host(f: &AsnFlowEvent) -> String {
    for candidate in [&f.sni, &f.host, &f.ptr_hostname] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    f.remote.clone()
}

/// Parse an agentsnitch `events.jsonl` stream (one JSON envelope per line) into
/// normalized outbound [`Flow`]s, mirroring `flows.go`.
///
/// Lines that do not parse or are not `network`/`correlated` kinds are skipped —
/// best-effort ingest of an external tool's log. A malformed line must not abort
/// the whole overlay; the trust distinction between the capture path and this
/// external sensor is the reason we stay tolerant here.
///
/// Deduplication matches Go: key = `ts\x00host\x00direction`; first occurrence wins.
pub fn parse_flows<R: BufRead>(r: R) -> Vec<Flow> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<Flow> = Vec::new();

    let mut add = |fl: Flow| {
        if fl.host.is_empty() || fl.ts.is_empty() {
            return;
        }
        let key = format!("{}\x00{}\x00{}", fl.ts, fl.host, fl.direction);
        if seen.insert(key) {
            out.push(fl);
        }
    };

    for line_result in r.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let env: AsnEnvelope = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        match env.kind.as_str() {
            "correlated" => {
                let c: AsnCorrelated = match serde_json::from_value(env.event) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // THEIR tool-use id — first semantic_id or empty.
                let tool = c.semantic_ids.first().cloned().unwrap_or_default();
                for fe in &c.flows {
                    if fe.direction != "out" {
                        continue;
                    }
                    add(Flow {
                        ts: fe.ts.clone(),
                        host: best_host(fe),
                        remote: fe.remote.clone(),
                        direction: fe.direction.clone(),
                        pid: fe.pid,
                        bytes_out: fe.bytes_out,
                        protocol: fe.protocol.clone(),
                        observer: fe.observer.clone(),
                        // agentsnitch's claims, carried as-is:
                        linked_tool: tool.clone(),
                        confidence: c.confidence.clone(),
                        why: c.summary.clone(),
                    });
                }
            }
            "network" => {
                let fe: AsnFlowEvent = match serde_json::from_value(env.event) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if fe.direction != "out" {
                    continue;
                }
                add(Flow {
                    ts: fe.ts.clone(),
                    host: best_host(&fe),
                    remote: fe.remote.clone(),
                    direction: fe.direction.clone(),
                    pid: fe.pid,
                    bytes_out: fe.bytes_out,
                    protocol: fe.protocol.clone(),
                    observer: fe.observer.clone(),
                    // No correlation for bare network events:
                    linked_tool: String::new(),
                    confidence: String::new(),
                    why: String::new(),
                });
            }
            _ => {}
        }
    }
    out
}

/// Hash the normalized flow overlay so it can be committed into the evidence
/// chain alongside the capture. The overlay is evidence too, even though it's
/// a weaker/probabilistic layer.
///
/// Returns the sha256 hex of the canonical JSON (`serde_json::to_vec(&flows)`).
/// Stable: same flows in the same order always produce the same hash.
pub fn overlay_hash(flows: &[Flow]) -> String {
    let bytes = serde_json::to_vec(flows).expect("Flow is always serializable");
    let digest = Sha256::digest(&bytes);
    agentprov_integrity::to_hex(&digest)
}

// ── EvidenceSink ──────────────────────────────────────────────────────────────

/// Where normalized evidence is written. Implementations must be tiny — the
/// capture path must never depend on network availability, so this seam exists
/// to keep local I/O the only required impl.
///
/// # Future implementations
/// // ponytail: S3MultipartSink and HTTPSCollectorSink are explicitly deferred;
/// // they implement this trait without modifying capture. Add when needed.
pub trait EvidenceSink {
    /// Write the normalized flows to this sink.
    fn write_flows(&mut self, flows: &[Flow]) -> std::io::Result<()>;
    /// Finalize the sink (flush, close, etc.). Called exactly once after all
    /// `write_flows` calls for a session.
    fn finalize(&mut self) -> std::io::Result<()>;
}

/// Writes `flows.jsonl` (one [`Flow`] per line) and `flows.hash` (the
/// [`overlay_hash`]) into a local directory. Suitable for co-location with
/// the APCAP capture bundle.
pub struct LocalDirectorySink {
    dir: PathBuf,
    flows: Vec<Flow>,
}

impl LocalDirectorySink {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, flows: Vec::new() }
    }
}

impl EvidenceSink for LocalDirectorySink {
    fn write_flows(&mut self, flows: &[Flow]) -> std::io::Result<()> {
        self.flows.extend_from_slice(flows);
        Ok(())
    }

    fn finalize(&mut self) -> std::io::Result<()> {
        // Write flows.jsonl — one Flow per line, matching JSONL convention.
        let jsonl_path = self.dir.join("flows.jsonl");
        let mut f = std::fs::File::create(&jsonl_path)?;
        for flow in &self.flows {
            let line = serde_json::to_vec(flow)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            f.write_all(&line)?;
            f.write_all(b"\n")?;
        }
        f.flush()?;

        // Write flows.hash — sha256 hex of the canonical overlay JSON.
        let hash = overlay_hash(&self.flows);
        let hash_path = self.dir.join("flows.hash");
        std::fs::write(hash_path, format!("{hash}\n"))?;

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// Build a realistic 3-line agentsnitch sample:
    ///   line 1: kind=network with sni + hostname set (sni should win as host)
    ///   line 2: kind=correlated with confidence="high" and a summary/why
    ///   line 3: garbage that must be skipped silently
    fn sample_jsonl() -> &'static str {
        r#"{"schema":"agentsnitch.transcript.v0","kind":"network","event":{"ts":"2026-06-17T10:00:00Z","remote":"1.2.3.4:443","hostname":"fallback.example.com","sni":"api.example.com","ptr_hostname":"","direction":"out","pid":1234,"bytes_out":512,"protocol":"tcp","observer":"network_statistics"}}
{"schema":"agentsnitch.transcript.v0","kind":"correlated","event":{"ts":"2026-06-17T10:00:05Z","confidence":"high","summary":"Outbound TLS to GitHub during tool-use fetch_file","semantic_ids":["tool-use-abc123"],"flows":[{"ts":"2026-06-17T10:00:05Z","remote":"140.82.121.4:443","hostname":"","sni":"github.com","ptr_hostname":"","direction":"out","pid":1234,"bytes_out":1024,"protocol":"tcp","observer":"lsof"}]}}
this is not valid json at all {{{garbage
"#
    }

    #[test]
    fn parse_skips_garbage_and_counts_flows() {
        let flows = parse_flows(BufReader::new(sample_jsonl().as_bytes()));
        assert_eq!(flows.len(), 2, "garbage line must be skipped; 2 flows expected");
    }

    #[test]
    fn sni_wins_over_hostname() {
        let flows = parse_flows(BufReader::new(sample_jsonl().as_bytes()));
        // The network event has both sni="api.example.com" and hostname="fallback.example.com".
        // Go's bestHost checks SNI first, so "api.example.com" must win.
        assert_eq!(flows[0].host, "api.example.com");
    }

    #[test]
    fn correlated_flow_carries_their_confidence_and_why() {
        let flows = parse_flows(BufReader::new(sample_jsonl().as_bytes()));
        let corr = &flows[1];
        // agentsnitch's claims must be carried exactly, not interpreted.
        assert_eq!(corr.confidence, "high", "confidence must be their claim, carried as-is");
        assert_eq!(
            corr.why,
            "Outbound TLS to GitHub during tool-use fetch_file",
            "why must be their summary, carried as-is"
        );
        assert_eq!(corr.linked_tool, "tool-use-abc123");
        assert_eq!(corr.host, "github.com"); // sni wins here too
    }

    #[test]
    fn overlay_hash_is_stable() {
        let flows = parse_flows(BufReader::new(sample_jsonl().as_bytes()));
        let h1 = overlay_hash(&flows);
        let h2 = overlay_hash(&flows);
        assert_eq!(h1, h2, "same flows must produce the same hash");
        assert_eq!(h1.len(), 64, "sha256 hex is 64 chars");
    }

    #[test]
    fn overlay_hash_changes_on_mutation() {
        let flows = parse_flows(BufReader::new(sample_jsonl().as_bytes()));
        let h1 = overlay_hash(&flows);

        let mut flows2 = flows.clone();
        flows2[0].bytes_out += 1;
        let h2 = overlay_hash(&flows2);

        assert_ne!(h1, h2, "mutating a flow must change the hash");
    }

    #[test]
    fn local_directory_sink_writes_and_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut sink = LocalDirectorySink::new(dir.path().to_path_buf());

        let flows = parse_flows(BufReader::new(sample_jsonl().as_bytes()));
        sink.write_flows(&flows).unwrap();
        sink.finalize().unwrap();

        // flows.jsonl must exist and round-trip back to the same flows.
        let jsonl_path = dir.path().join("flows.jsonl");
        let file = std::fs::File::open(&jsonl_path).expect("flows.jsonl");
        let recovered: Vec<Flow> = BufReader::new(file)
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(&l).expect("valid Flow JSON"))
            .collect();
        assert_eq!(recovered, flows);

        // flows.hash must match overlay_hash of the recovered flows.
        let hash_path = dir.path().join("flows.hash");
        let stored_hash = std::fs::read_to_string(hash_path).expect("flows.hash");
        assert_eq!(stored_hash.trim(), overlay_hash(&flows));
    }

    #[test]
    fn inbound_flows_are_filtered_out() {
        // Go filters direction != "out" in both network and correlated branches.
        let inbound = r#"{"schema":"agentsnitch.transcript.v0","kind":"network","event":{"ts":"2026-06-17T10:00:00Z","remote":"5.6.7.8:1234","hostname":"inbound.example.com","sni":"","ptr_hostname":"","direction":"in","pid":99,"bytes_out":0,"protocol":"tcp","observer":"lsof"}}
"#;
        let flows = parse_flows(BufReader::new(inbound.as_bytes()));
        assert!(flows.is_empty(), "inbound flows must be dropped");
    }

    #[test]
    fn dedup_drops_second_occurrence_of_same_ts_host_dir() {
        // Two identical (ts, host, direction) tuples — first one wins.
        let duped = r#"{"schema":"agentsnitch.transcript.v0","kind":"network","event":{"ts":"2026-06-17T10:00:00Z","remote":"1.2.3.4:443","sni":"dup.example.com","hostname":"","ptr_hostname":"","direction":"out","pid":1,"bytes_out":100,"protocol":"tcp","observer":"lsof"}}
{"schema":"agentsnitch.transcript.v0","kind":"network","event":{"ts":"2026-06-17T10:00:00Z","remote":"1.2.3.4:443","sni":"dup.example.com","hostname":"","ptr_hostname":"","direction":"out","pid":2,"bytes_out":999,"protocol":"tcp","observer":"lsof"}}
"#;
        let flows = parse_flows(BufReader::new(duped.as_bytes()));
        assert_eq!(flows.len(), 1, "duplicate key must be deduplicated");
        assert_eq!(flows[0].pid, 1, "first occurrence wins");
    }
}
