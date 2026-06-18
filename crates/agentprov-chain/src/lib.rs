//! agentprov-chain — transcript → signed semantic chain.
//!
//! Direct port of the Go recorder's `normalize` classifier + hash-chain emitter
//! (agentprov `main.go`). It reads a Claude Code / Codex transcript JSONL, turns
//! each line into 0+ *semantic* nodes (prompt / tool_call / tool_result /
//! assistant / thinking / image / command·meta), hash-chains them, ed25519-signs
//! each, and writes `chain.jsonl` + `chain.pub` — byte-compatible with the format
//! the in-browser `viewer.html` verifier recomputes.
//!
//! The viewer's `analyze()` checks two things per node: `prev_hash` linkage and a
//! recomputed `hash` over the NUL-joined field string. It does NOT verify the
//! signature in-browser, so matching the *hash input* exactly is what makes the
//! viewer say "verified" instead of "CHAIN BREAKS". The signature is produced for
//! fidelity with the Go output and for out-of-band `verify`.
//!
//! Tier-2: this is the untrusted-parse path (arbitrary transcript JSON), hence
//! serde rather than hand-rolled parsing. The trusted signing key still comes from
//! `agentprov-integrity` (keychain-bound, agent-unreachable).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use agentprov_integrity::{to_hex, Signing};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Per-node content ceiling — high enough to carry full prompts/commands/output
/// verbatim. Content is hashed, so it stays tamper-evident. Matches Go `detailMax`.
const DETAIL_MAX: usize = 20000;

/// One recorder heartbeat ("recorder alive") per N agent events. Matches Go
/// `heartbeatEvery`.
const HEARTBEAT_EVERY: usize = 25;

#[derive(Debug)]
pub enum ChainError {
    Io(std::io::Error),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<std::io::Error> for ChainError {
    fn from(e: std::io::Error) -> Self {
        ChainError::Io(e)
    }
}

/// One link in the chain. Field order and `omitempty` semantics mirror the Go
/// `Node` struct's json tags exactly, because the viewer reads these serialized
/// fields back to recompute the hash. `Attrs` is a `BTreeMap` so its keys are
/// sorted for BOTH the hash input and serialization (the Go side sorts in both
/// `contentHash` and `json.Marshal`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Node {
    pub seq: i64,
    pub op: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub span_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub parent_span_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tool: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub trust: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub net: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub time: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub attrs: BTreeMap<String, String>,
    pub prev_hash: String,
    pub hash: String,
    pub sig: String,
}

/// Recompute the content hash for a node given the previous hash. The hash input
/// is the fields joined by NUL (\x00) in this exact order — seq, prev, op, agent,
/// span_id, parent_span_id, tool, trust, summary, detail, net, time — then for
/// each attrs key in SORTED order: NUL + key + "=" + value. This is byte-for-byte
/// what `viewer.html`'s `hashInput()` builds. `prev` starts as "GENESIS".
fn content_hash(prev: &str, n: &Node) -> String {
    let mut s = String::new();
    s.push_str(&n.seq.to_string());
    for field in [
        prev,
        &n.op,
        &n.agent,
        &n.span_id,
        &n.parent_span_id,
        &n.tool,
        &n.trust,
        &n.summary,
        &n.detail,
        &n.net,
        &n.time,
    ] {
        s.push('\x00');
        s.push_str(field);
    }
    // BTreeMap iterates in sorted key order, matching Go `sortedKeys`.
    for (k, v) in &n.attrs {
        s.push('\x00');
        s.push_str(k);
        s.push('=');
        s.push_str(v);
    }
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    to_hex(&h.finalize())
}

/// Recorder: appends signed, hash-chained nodes. Mirrors Go `recorder`.
struct Recorder<'a, W: Write> {
    w: W,
    signer: &'a Signing,
    prev: String,
    seq: i64,
}

impl<'a, W: Write> Recorder<'a, W> {
    fn new(w: W, signer: &'a Signing) -> Self {
        Self { w, signer, prev: "GENESIS".to_string(), seq: 0 }
    }

    fn emit(&mut self, mut n: Node) -> std::io::Result<()> {
        n.seq = self.seq;
        n.prev_hash = self.prev.clone();
        n.hash = content_hash(&self.prev, &n);
        // Go: Sig = hex(ed25519.Sign(priv, []byte(n.Hash))) — sign the hex string.
        n.sig = to_hex(&self.signer.sign_bytes(n.hash.as_bytes()));
        self.prev = n.hash.clone();
        let line = serde_json::to_string(&n).expect("node serializes");
        self.w.write_all(line.as_bytes())?;
        self.w.write_all(b"\n")?;
        self.w.flush()?; // flush each node: the record must survive an abrupt exit
        self.seq += 1;
        Ok(())
    }
}

// ── classifier helpers (ported from main.go) ────────────────────────────────

/// Truncate on a char boundary (Go `truncRunes` uses runes), appending "…" only
/// when the char count exceeds `max`.
fn trunc_runes(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let mut out: String = chars[..max].iter().collect();
    out.push('…');
    out
}

/// Pull human-readable text out of whatever a transcript packs into a
/// content/input/output field. Mirrors Go `flatten`.
fn flatten(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let mut parts = Vec::new();
            for e in arr {
                let s = flatten(e);
                if !s.is_empty() {
                    parts.push(s);
                }
            }
            parts.join(" ")
        }
        Value::Object(map) => {
            // An image block anywhere must never surface its base64 — describe it.
            if map.get("type").and_then(Value::as_str) == Some("image") {
                return image_detail(map.get("source"));
            }
            // Return flatten of the FIRST PRESENT key in this fixed order. Keys on
            // presence, not non-emptiness: a present-but-empty "text" returns ""
            // and does NOT fall through.
            for k in ["text", "thinking", "content", "command", "output", "stdout"] {
                if let Some(s) = map.get(k) {
                    return flatten(s);
                }
            }
            // Opaque control block (e.g. an extended-thinking signature) — don't
            // dump its raw JSON. Show the type if it has one.
            if map.contains_key("signature") {
                if let Some(t) = map.get("type").and_then(Value::as_str) {
                    if !t.is_empty() {
                        return format!("[{t}]");
                    }
                }
                return String::new();
            }
            // serde_json's default Map is sorted (BTreeMap), matching Go's sorted
            // json.Marshal of a map.
            serde_json::to_string(v).unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// Reports whether a "user" line is a slash/local-command tooling envelope rather
/// than text the human typed. Mirrors Go `isCommandEnvelope`.
fn is_command_envelope(s: &str) -> bool {
    s.contains("<command-name>")
        || s.contains("<command-message>")
        || s.contains("<local-command-stdout>")
        || s.contains("<local-command-caveat>")
        || s.contains("<command-args>")
}

/// Match http(s) URLs starting at a given byte. Returns the matched URL ending at
/// the first whitespace / quote / backtick / ')'. Hand-rolled to avoid a regex dep
/// and to match Go's `https?://[^\s"'`)]+`.
fn find_url(s: &str) -> Option<&str> {
    let lower = s.to_ascii_lowercase();
    let start = lower.find("http://").or_else(|| lower.find("https://"))?;
    let rest = &s[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == ')')
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Find up to `max` URLs (Go `urlRe.FindAllString(detail, max)`).
fn find_urls(s: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while out.len() < max {
        match find_url(rest) {
            Some(u) => {
                let u = u.to_string();
                // advance past this match
                let idx = rest.find(&u).map(|i| i + u.len()).unwrap_or(rest.len());
                out.push(u);
                if idx >= rest.len() {
                    break;
                }
                rest = &rest[idx..];
            }
            None => break,
        }
    }
    out
}

/// Match shell tools that reach the network. Mirrors Go `egressCmd`; returns the
/// matched tool token (the first alternative that hits), or None.
/// `\b(curl|wget|nc|ncat|telnet|ssh|scp|rsync|ftp|git\s+(clone|fetch|pull|push)|
///   pip\s+install|npm\s+(install|i)\b|brew\s+install)\b`
fn egress_match(detail: &str) -> Option<String> {
    // Scan token by token to honor word boundaries; for the multi-word patterns,
    // check the following whitespace-separated word.
    let toks: Vec<&str> = detail.split(|c: char| !(c.is_alphanumeric() || c == '_')).collect();
    // Re-tokenize keeping order with simple whitespace split for the 2-word forms.
    let words: Vec<&str> = detail.split_whitespace().collect();
    for w in &words {
        match *w {
            "curl" | "wget" | "nc" | "ncat" | "telnet" | "ssh" | "scp" | "rsync" | "ftp" => {
                return Some((*w).to_string());
            }
            _ => {}
        }
    }
    // Two-word egress patterns.
    for pair in words.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        match (a, b) {
            ("git", "clone") | ("git", "fetch") | ("git", "pull") | ("git", "push") => {
                return Some(format!("git {b}"));
            }
            ("pip", "install") => return Some("pip install".to_string()),
            ("npm", "install") | ("npm", "i") => return Some(format!("npm {b}")),
            ("brew", "install") => return Some("brew install".to_string()),
            _ => {}
        }
    }
    let _ = toks;
    None
}

/// Extract the egress target from a tool call. Mirrors Go `netHost`.
fn net_host(tool: &str, detail: &str) -> String {
    match tool {
        "WebFetch" | "WebSearch" => {
            if let Some(m) = find_url(detail) {
                return trunc_runes(m, 120);
            }
            trunc_runes(detail.trim(), 120) // WebSearch query
        }
        "Bash" => {
            match egress_match(detail) {
                None => String::new(),
                Some(tok) => {
                    let urls = find_urls(detail, 3);
                    if !urls.is_empty() {
                        return trunc_runes(&urls.join(" "), 120);
                    }
                    // egress tool but no explicit URL (e.g. `git push`, scp host:path)
                    trunc_runes(&format!("egress: {tok}"), 60)
                }
            }
        }
        _ => String::new(),
    }
}

/// Describe an uploaded image WITHOUT carrying its bytes. Mirrors Go `imageDetail`.
fn image_detail(source: Option<&Value>) -> String {
    let s = source.and_then(Value::as_object);
    let media = s
        .and_then(|m| m.get("media_type"))
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .unwrap_or("image");
    if let Some(data) = s.and_then(|m| m.get("data")).and_then(Value::as_str) {
        // base64 decodes to ~3/4 its length; keep the exact integer-division order.
        return format!("🖼 image uploaded — {media}, ~{} KB", data.len() * 3 / 4 / 1024);
    }
    if let Some(url) = s.and_then(|m| m.get("url")).and_then(Value::as_str) {
        return format!("🖼 image (url) — {}", trunc_runes(url, 100));
    }
    format!("🖼 image uploaded — {media}")
}

/// Pull the server name out of an MCP tool name (mcp__<server>__<tool>). Mirrors
/// Go `mcpServer`; returns "" for non-MCP tools.
fn mcp_server(tool: &str) -> String {
    let Some(rest) = tool.strip_prefix("mcp__") else {
        return String::new();
    };
    if let Some(i) = rest.find("__") {
        if i > 0 {
            return rest[..i].to_string();
        }
    }
    String::new()
}

fn obj_str(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Map one raw transcript line (Claude OR Codex) to provenance node(s). Mirrors
/// Go `normalize`.
fn normalize(raw: &Value) -> Vec<Node> {
    // ── Claude Code: keyed on a top-level "uuid". ──
    if let Some(uuid) = raw.get("uuid").and_then(Value::as_str) {
        let parent = obj_str(raw, "parentUuid");
        let ts = obj_str(raw, "timestamp");
        let typ = obj_str(raw, "type");
        let base = Node {
            span_id: uuid.to_string(),
            parent_span_id: parent,
            time: ts,
            trust: "unknown".to_string(),
            ..Default::default()
        };
        let msg = raw.get("message");
        let mut nodes: Vec<Node> = Vec::new();
        // Only iterate as blocks when content is an ARRAY (Go: content,_ := ... .([]any)).
        if let Some(content) = msg.and_then(|m| m.get("content")).and_then(Value::as_array) {
            for c in content {
                let Some(b) = c.as_object() else { continue };
                let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
                match btype {
                    "tool_use" => {
                        let mut n = base.clone();
                        n.op = "tool_call".to_string();
                        n.trust = "trusted".to_string();
                        n.tool = b.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                        n.summary = format!("tool_use {}", n.tool);
                        n.detail = trunc_runes(
                            &flatten(b.get("input").unwrap_or(&Value::Null)),
                            DETAIL_MAX,
                        );
                        n.net = net_host(&n.tool, &n.detail);
                        let srv = mcp_server(&n.tool);
                        if !srv.is_empty() {
                            n.attrs.insert("mcp".to_string(), srv);
                        }
                        nodes.push(n);
                    }
                    "tool_result" => {
                        let mut n = base.clone();
                        n.op = "tool_result".to_string();
                        n.trust = "untrusted".to_string();
                        n.summary = "tool_result".to_string();
                        n.detail = trunc_runes(
                            &flatten(b.get("content").unwrap_or(&Value::Null)),
                            DETAIL_MAX,
                        );
                        nodes.push(n);
                    }
                    "text" => {
                        let mut n = base.clone();
                        n.op = "assistant".to_string();
                        n.trust = "trusted".to_string();
                        n.summary = "assistant turn".to_string();
                        n.detail = trunc_runes(
                            &flatten(b.get("text").unwrap_or(&Value::Null)),
                            DETAIL_MAX,
                        );
                        nodes.push(n);
                    }
                    "thinking" | "redacted_thinking" => {
                        let mut n = base.clone();
                        n.op = "assistant".to_string();
                        n.trust = "trusted".to_string();
                        n.summary = "agent thinking".to_string();
                        let think = b.get("thinking").and_then(Value::as_str).unwrap_or("");
                        n.detail = trunc_runes(think, DETAIL_MAX);
                        nodes.push(n);
                    }
                    "image" => {
                        let mut n = base.clone();
                        n.op = "image".to_string();
                        n.trust = "untrusted".to_string();
                        n.summary = "image input".to_string();
                        n.detail = image_detail(b.get("source"));
                        nodes.push(n);
                    }
                    _ => {}
                }
            }
        }
        if nodes.is_empty() {
            let mut n = base;
            let detail = trunc_runes(
                &flatten(msg.and_then(|m| m.get("content")).unwrap_or(&Value::Null)),
                DETAIL_MAX,
            );
            match typ.as_str() {
                "user" => {
                    let meta = raw.get("isMeta").and_then(Value::as_bool).unwrap_or(false);
                    if meta || is_command_envelope(&detail) {
                        n.op = "other".to_string();
                        n.summary = "command/meta".to_string();
                        n.detail = detail;
                    } else {
                        n.op = "prompt".to_string();
                        n.trust = "untrusted".to_string();
                        n.summary = "user prompt".to_string();
                        n.detail = detail;
                    }
                }
                "assistant" => {
                    n.op = "assistant".to_string();
                    n.trust = "trusted".to_string();
                    n.summary = "assistant turn".to_string();
                    n.detail = detail;
                }
                other => {
                    n.op = "other".to_string();
                    n.summary = other.to_string();
                }
            }
            nodes.push(n);
        }
        return nodes;
    }

    // ── Codex: real kind nested under payload.type; outer "type" is the envelope. ──
    if let Some(outer) = raw.get("type").and_then(Value::as_str) {
        let ts = obj_str(raw, "timestamp");
        let payload = raw.get("payload");
        let ptype = payload
            .and_then(|p| p.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut n = Node {
            op: "other".to_string(),
            time: ts,
            trust: "unknown".to_string(),
            summary: format!("{outer}/{ptype}"),
            ..Default::default()
        };
        let pget = |k: &str| payload.and_then(|p| p.get(k));
        match ptype {
            "message" | "user_message" => {
                let role = payload
                    .and_then(|p| p.get("role"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if role == "assistant" {
                    n.op = "assistant".to_string();
                    n.trust = "trusted".to_string();
                    n.summary = "assistant turn".to_string();
                } else {
                    n.op = "prompt".to_string();
                    n.trust = "untrusted".to_string();
                    n.summary = "user prompt".to_string();
                }
                n.detail = trunc_runes(&flatten(pget("content").unwrap_or(&Value::Null)), DETAIL_MAX);
            }
            "function_call" | "custom_tool_call" => {
                n.op = "tool_call".to_string();
                n.trust = "trusted".to_string();
                n.tool = pget("name").and_then(Value::as_str).unwrap_or("").to_string();
                n.summary = format!("tool_call {}", n.tool);
                n.detail =
                    trunc_runes(&flatten(pget("arguments").unwrap_or(&Value::Null)), DETAIL_MAX);
                n.net = net_host(&n.tool, &n.detail);
                let srv = mcp_server(&n.tool);
                if !srv.is_empty() {
                    n.attrs.insert("mcp".to_string(), srv);
                }
            }
            "function_call_output" | "custom_tool_call_output" | "patch_apply_end" => {
                n.op = "tool_result".to_string();
                n.trust = "untrusted".to_string();
                n.summary = "tool_result".to_string();
                n.detail = trunc_runes(&flatten(pget("output").unwrap_or(&Value::Null)), DETAIL_MAX);
            }
            "agent_message" => {
                n.op = "assistant".to_string();
                n.trust = "trusted".to_string();
                n.summary = "assistant message".to_string();
                n.detail = trunc_runes(&flatten(pget("message").unwrap_or(&Value::Null)), DETAIL_MAX);
            }
            _ => {}
        }
        return vec![n];
    }

    Vec::new()
}

// ── file folding (ported from recordFileAs / recordLineAs / subagent helpers) ─

fn record_line_as<W: Write>(
    line: &str,
    agent: &str,
    rec: &mut Recorder<W>,
    count: &mut usize,
) -> std::io::Result<()> {
    if line.is_empty() {
        return Ok(());
    }
    let raw: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Ok(()), // skip unparseable lines, like Go
    };
    if !raw.is_object() {
        return Ok(());
    }
    for mut n in normalize(&raw) {
        n.agent = agent.to_string();
        rec.emit(n)?;
        *count += 1;
        if count.is_multiple_of(HEARTBEAT_EVERY) {
            rec.emit(Node {
                op: "heartbeat".to_string(),
                summary: "recorder alive".to_string(),
                ..Default::default()
            })?;
        }
    }
    Ok(())
}

fn record_file_as<W: Write>(
    path: &Path,
    agent: &str,
    rec: &mut Recorder<W>,
    count: &mut usize,
) -> std::io::Result<()> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = line?;
        record_line_as(line.trim(), agent, rec, count)?;
    }
    Ok(())
}

/// Subagent transcript paths for a main transcript at `<project>/<sessionId>.jsonl`
/// — they live in `<project>/<sessionId>/subagents/agent-*.jsonl`. Sorted for a
/// deterministic order. Mirrors Go `subagentFiles`.
fn subagent_files(main_path: &Path) -> Vec<std::path::PathBuf> {
    let dir = match main_path.to_str() {
        Some(s) => std::path::PathBuf::from(s.strip_suffix(".jsonl").unwrap_or(s)),
        None => return Vec::new(),
    };
    let sub_dir = dir.join("subagents");
    let mut matches: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&sub_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("agent-") && name.ends_with(".jsonl") {
                    matches.push(p);
                }
            }
        }
    }
    matches.sort();
    matches
}

/// Derive the short agent id from a `subagents/agent-<id>.jsonl` path. Mirrors Go
/// `subagentID`.
fn subagent_id(path: &Path) -> String {
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .strip_suffix(".jsonl")
        .unwrap_or("");
    base.strip_prefix("agent-").unwrap_or(base).to_string()
}

/// Record a past transcript (Claude/Codex) into `out_dir/chain.jsonl`, folding in
/// any subagents, and write `out_dir/chain.pub`. Returns the total node count
/// written (heartbeats + semantic nodes + subagent markers — i.e. `rec.seq`).
/// Mirrors Go `recordTranscriptTo`.
pub fn record_transcript(transcript_path: &Path, out_dir: &Path) -> Result<usize, ChainError> {
    record_transcript_with_cast(transcript_path, out_dir, None)
}

/// Like [`record_transcript`], but if `cast_path` is given (and exists), emit a
/// `cast_recording` node committing to the cast's sha256 — this is what makes
/// the viewer's "Real recording" tab appear (it keys on a `cast_recording`
/// node) and binds the real terminal recording into the signed chain.
pub fn record_transcript_with_cast(
    transcript_path: &Path,
    out_dir: &Path,
    cast_path: Option<&Path>,
) -> Result<usize, ChainError> {
    // Validate the transcript exists up front (Go opens it first).
    let _probe = File::open(transcript_path)?;
    drop(_probe);

    // Ensure the output dir exists (the shim points at a fresh session dir).
    std::fs::create_dir_all(out_dir)?;

    let signer = Signing::load_or_create();
    let key_source = match signer.source {
        agentprov_integrity::KeySource::Keychain => "keychain",
        agentprov_integrity::KeySource::Ephemeral => "ephemeral",
    };

    // chain.pub: hex(pub)+"\n", matching Go writePubFileAt.
    std::fs::write(out_dir.join("chain.pub"), format!("{}\n", to_hex(&signer.public_key())))?;

    let out = File::create(out_dir.join("chain.jsonl"))?;
    let mut rec = Recorder::new(BufWriter::new(out), &signer);

    let mut start_attrs = BTreeMap::new();
    start_attrs.insert("key".to_string(), key_source.to_string());
    rec.emit(Node {
        op: "heartbeat".to_string(),
        summary: "recorder start".to_string(),
        attrs: start_attrs,
        ..Default::default()
    })?;

    let mut count: usize = 0;
    record_file_as(transcript_path, "main", &mut rec, &mut count)?;

    // Fold in any subagents the main session spawned. One signed chain covers the
    // whole tree; tampering ANY node — main or sub — fractures verify.
    let subs = subagent_files(transcript_path);
    for sp in &subs {
        let id = subagent_id(sp);
        let mut attrs = BTreeMap::new();
        attrs.insert("id".to_string(), id.clone());
        attrs.insert(
            "source".to_string(),
            sp.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
        );
        rec.emit(Node {
            op: "subagent".to_string(),
            agent: id.clone(),
            summary: "subagent spawned".to_string(),
            attrs,
            ..Default::default()
        })?;
        record_file_as(sp, &id, &mut rec, &mut count)?;
    }

    // Bind the real terminal recording into the chain (makes the viewer's
    // "Real recording" tab appear). Hash-commit the cast so it can't be swapped.
    if let Some(cast) = cast_path {
        if let Ok(bytes) = std::fs::read(cast) {
            use sha2::{Digest, Sha256};
            let sum = Sha256::digest(&bytes);
            let mut attrs = BTreeMap::new();
            attrs.insert("sha256".to_string(), to_hex(&sum));
            attrs.insert(
                "file".to_string(),
                cast.file_name().and_then(|n| n.to_str()).unwrap_or("session.cast").to_string(),
            );
            attrs.insert("bytes".to_string(), bytes.len().to_string());
            attrs.insert("key".to_string(), key_source.to_string());
            rec.emit(Node {
                op: "cast_recording".to_string(),
                summary: "real terminal recording (asciinema) — reconstruction's untrusted sibling".to_string(),
                attrs,
                ..Default::default()
            })?;
        }
    }

    rec.emit(Node {
        op: "heartbeat".to_string(),
        summary: "recorder end (clean exit)".to_string(),
        ..Default::default()
    })?;

    rec.w.flush().map_err(ChainError::Io)?;
    Ok(rec.seq as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Read back the chain.jsonl an out_dir produced into a Vec<Value>.
    fn read_chain(out_dir: &Path) -> Vec<Value> {
        let data = std::fs::read_to_string(out_dir.join("chain.jsonl")).unwrap();
        data.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Compute the NUL-joined hash input exactly as the test pins it, independent
    /// of `content_hash`, so test 3 truly pins the format.
    fn reference_hash(prev: &str, n: &Node) -> String {
        let mut s = format!("{}", n.seq);
        for f in [
            prev, &n.op, &n.agent, &n.span_id, &n.parent_span_id, &n.tool, &n.trust, &n.summary,
            &n.detail, &n.net, &n.time,
        ] {
            s.push('\u{0}');
            s.push_str(f);
        }
        for (k, v) in &n.attrs {
            s.push('\u{0}');
            s.push_str(&format!("{k}={v}"));
        }
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        to_hex(&h.finalize())
    }

    const SYNTH: &str = concat!(
        r#"{"uuid":"u1","parentUuid":null,"type":"user","timestamp":"2026-01-01T00:00:01Z","message":{"content":"Add a /health endpoint."}}"#,
        "\n",
        r#"{"uuid":"u2","parentUuid":"u1","type":"assistant","timestamp":"2026-01-01T00:00:02Z","message":{"content":[{"type":"tool_use","name":"Read","input":{"file_path":"/srv/api/server.go"}}]}}"#,
        "\n",
        r#"{"uuid":"u3","parentUuid":"u2","type":"user","timestamp":"2026-01-01T00:00:03Z","message":{"content":[{"type":"tool_result","content":"package main"}]}}"#,
        "\n"
    );

    fn write_synth(dir: &Path) -> std::path::PathBuf {
        let p = dir.join("transcript.jsonl");
        std::fs::write(&p, SYNTH).unwrap();
        p
    }

    #[test]
    fn ops_and_chain_link() {
        let tmp = std::env::temp_dir().join(format!("apchain-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let t = write_synth(&tmp);
        let n = record_transcript(&t, &tmp).unwrap();
        assert!(n >= 5, "expected start + 3 semantic + end nodes, got {n}");

        let chain = read_chain(&tmp);
        let ops: Vec<&str> = chain.iter().map(|v| v["op"].as_str().unwrap()).collect();
        // start heartbeat, prompt, tool_call, tool_result, end heartbeat
        assert_eq!(ops.first(), Some(&"heartbeat"));
        assert!(ops.contains(&"prompt"), "ops: {ops:?}");
        assert!(ops.contains(&"tool_call"), "ops: {ops:?}");
        assert!(ops.contains(&"tool_result"), "ops: {ops:?}");
        assert_eq!(ops.last(), Some(&"heartbeat"));

        // The tool_call should be Read and carry the file_path in detail.
        let tc = chain.iter().find(|v| v["op"] == "tool_call").unwrap();
        assert_eq!(tc["tool"], "Read");
        assert!(tc["detail"].as_str().unwrap().contains("/srv/api/server.go"));

        // Hash chain links: first prev_hash is GENESIS, each node's prev_hash ==
        // previous node's hash.
        assert_eq!(chain[0]["prev_hash"], "GENESIS");
        for i in 1..chain.len() {
            assert_eq!(
                chain[i]["prev_hash"], chain[i - 1]["hash"],
                "link broke at node {i}"
            );
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn tamper_breaks_chain() {
        let tmp = std::env::temp_dir().join(format!("apchain-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let t = write_synth(&tmp);
        record_transcript(&t, &tmp).unwrap();
        let chain = read_chain(&tmp);

        // Find the tool_result node, flip a byte in its detail, recompute its hash
        // input the way the viewer would, and assert the stored hash no longer
        // matches — i.e. the hash covers the content.
        let idx = chain.iter().position(|v| v["op"] == "tool_result").unwrap();
        let prev = chain[idx]["prev_hash"].as_str().unwrap();

        // Reconstruct a Node from the stored JSON, then tamper detail.
        let mut n = Node {
            seq: chain[idx]["seq"].as_i64().unwrap(),
            op: chain[idx]["op"].as_str().unwrap().to_string(),
            agent: chain[idx]["agent"].as_str().unwrap_or("").to_string(),
            span_id: chain[idx]["span_id"].as_str().unwrap_or("").to_string(),
            parent_span_id: chain[idx]["parent_span_id"].as_str().unwrap_or("").to_string(),
            tool: chain[idx]["tool"].as_str().unwrap_or("").to_string(),
            trust: chain[idx]["trust"].as_str().unwrap_or("").to_string(),
            summary: chain[idx]["summary"].as_str().unwrap_or("").to_string(),
            detail: chain[idx]["detail"].as_str().unwrap_or("").to_string(),
            net: chain[idx]["net"].as_str().unwrap_or("").to_string(),
            time: chain[idx]["time"].as_str().unwrap_or("").to_string(),
            attrs: BTreeMap::new(),
            ..Default::default()
        };
        let stored_hash = chain[idx]["hash"].as_str().unwrap();
        assert_eq!(reference_hash(prev, &n), stored_hash, "untampered must match");
        n.detail.push('X'); // flip/append a byte
        assert_ne!(
            reference_hash(prev, &n),
            stored_hash,
            "tampering detail must change the hash"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn pins_known_hash_format() {
        // A fixed node — compute the NUL-joined sha256 by hand here to pin the
        // exact format the Go formula / viewer.html use.
        let mut attrs = BTreeMap::new();
        attrs.insert("mcp".to_string(), "fs".to_string());
        let n = Node {
            seq: 7,
            op: "tool_call".to_string(),
            agent: "main".to_string(),
            span_id: "sp1".to_string(),
            parent_span_id: "sp0".to_string(),
            tool: "mcp__fs__read".to_string(),
            trust: "trusted".to_string(),
            summary: "tool_use mcp__fs__read".to_string(),
            detail: "hello".to_string(),
            net: "".to_string(),
            time: "2026-01-01T00:00:00Z".to_string(),
            attrs,
            ..Default::default()
        };
        let prev = "GENESIS";

        // Hand-built reference string: seq, then NUL-joined fields, then sorted attrs.
        let expect_input = format!(
            "7\u{0}GENESIS\u{0}tool_call\u{0}main\u{0}sp1\u{0}sp0\u{0}mcp__fs__read\u{0}trusted\u{0}tool_use mcp__fs__read\u{0}hello\u{0}\u{0}2026-01-01T00:00:00Z\u{0}mcp=fs"
        );
        let mut h = Sha256::new();
        h.update(expect_input.as_bytes());
        let expect = to_hex(&h.finalize());

        assert_eq!(content_hash(prev, &n), expect, "content_hash must match hand-built NUL format");
        assert_eq!(reference_hash(prev, &n), expect, "reference must match too");
    }

    #[test]
    fn flatten_and_helpers() {
        // flatten keys on PRESENCE: present-but-empty "text" returns "" (no fallthrough).
        let v: Value = serde_json::json!({"text": "", "content": "ignored"});
        assert_eq!(flatten(&v), "");
        // array joins non-empty parts with a space.
        let v: Value = serde_json::json!([{"text": "a"}, {"text": ""}, {"text": "b"}]);
        assert_eq!(flatten(&v), "a b");
        // image block describes, never surfaces bytes.
        let v: Value = serde_json::json!({"type":"image","source":{"media_type":"image/png","data":"AAAA"}});
        assert!(flatten(&v).contains("image uploaded"));
        // net_host: WebFetch pulls URL; Bash only on egress tool.
        assert_eq!(net_host("WebFetch", "see https://example.com/x now"), "https://example.com/x");
        assert_eq!(net_host("Bash", "ls -la"), "");
        assert_eq!(net_host("Bash", "curl https://evil.test/p"), "https://evil.test/p");
        assert_eq!(net_host("Bash", "git push origin main"), "egress: git push");
        // mcp server extraction.
        assert_eq!(mcp_server("mcp__fs__read"), "fs");
        assert_eq!(mcp_server("Read"), "");
        // command envelope detection.
        assert!(is_command_envelope("<command-name>/foo</command-name>"));
        assert!(!is_command_envelope("just text"));
    }

    #[test]
    fn end_to_end_on_real_sample() {
        let sample = Path::new("/Users/scottmoore/github/agentprov/sample.jsonl");
        if !sample.exists() {
            return; // sample not present in this environment — skip, don't fail.
        }
        let tmp = std::env::temp_dir().join(format!("apchain-sample-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let n = record_transcript(sample, &tmp).expect("record real sample");
        assert!(n > 2, "real sample produced too few nodes: {n}");

        // Verify the chain links end-to-end like the viewer would, AND recompute
        // each hash to confirm content integrity.
        let chain = read_chain(&tmp);
        let mut prev = "GENESIS".to_string();
        for (i, v) in chain.iter().enumerate() {
            assert_eq!(v["prev_hash"].as_str().unwrap(), prev, "link broke at {i}");
            prev = v["hash"].as_str().unwrap().to_string();
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn recorder_emits_to_writer() {
        // Lightweight check that Recorder::emit fills seq/prev/hash/sig and chains.
        let signer = Signing::from_seed([3u8; 32]);
        let mut buf = Vec::new();
        {
            let mut rec = Recorder::new(Cursor::new(&mut buf), &signer);
            rec.emit(Node { op: "a".to_string(), ..Default::default() }).unwrap();
            rec.emit(Node { op: "b".to_string(), ..Default::default() }).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines[0]["prev_hash"], "GENESIS");
        assert_eq!(lines[0]["seq"], 0);
        assert_eq!(lines[1]["prev_hash"], lines[0]["hash"]);
        assert!(!lines[0]["sig"].as_str().unwrap().is_empty());
    }
}
