//! agentprov-viewer — Tier-2 local APCAP viewer.
//!
//! Loopback-only HTTP server (hand-rolled on `std::net`, no async stack).
//! The APCAP is verified once at startup via `agentprov-replay-core`; if
//! verification fails the server serves an error page and never emits capture
//! bytes to any client. An unguessable 128-bit token in the URL gates all
//! capture-data routes.
//!
//! # Security rules implemented here
//!
//! - **127.0.0.1 only / port 0** — `TcpListener::bind("127.0.0.1:0")`.
//! - **Token** — generated with `getrandom`, 16 random bytes → 32 hex chars.
//!   Routes `/` (Index) and `/cast` require `?t=<token>` in the URL.
//!   Static assets (`/player.js`, `/player.css`, `/font.ttf`) need no token
//!   (vendored files with no capture data).
//! - **CSP** — `default-src 'none'; script-src 'self'; style-src 'self'
//!   'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src
//!   'self'`. No remote origins. Inline `<script>` is forbidden, so the player
//!   bootstrap lives at `/boot.js` (served from 'self').
//! - **Allowlist routing** — `route()` matches an exact fixed set of paths.
//!   Unrecognised paths → `NotFound`. Client-supplied path bytes never touch the
//!   filesystem.
//! - **Fail-closed** — `to_asciicast` is called once at startup. On tamper
//!   `Err`, all data routes return an error page.

use agentprov_collectors::Flow;
use agentprov_replay_core::{frame_log, summarize, to_asciicast, FrameEntry, ReplaySummary};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ── JSON builders (hand-rolled, no serde — matches the viewer's no-dep style) ──

/// Escape a string as a JSON value body (no surrounding quotes).
fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

/// Build the tamper-evident log as a JSON array.
fn frame_log_json(entries: &[FrameEntry]) -> Vec<u8> {
    let mut s = String::from("[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        use std::fmt::Write as _;
        let _ = write!(
            s,
            "{{\"seq\":{},\"kind\":\"{}\",\"at\":{:.3},\"bytes\":{},\"hash\":\"{}\"}}",
            e.seq, json_str(&e.kind), e.at_secs, e.bytes, json_str(&e.hash_hex)
        );
    }
    s.push(']');
    s.into_bytes()
}

/// Build the network-flow overlay as a JSON array. confidence/why/linked_tool
/// are agentsnitch's CLAIM — the frontend labels them as such, never our verdict.
fn flows_json(flows: &[Flow]) -> Vec<u8> {
    let mut s = String::from("[");
    for (i, f) in flows.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        use std::fmt::Write as _;
        let _ = write!(
            s,
            "{{\"ts\":\"{}\",\"host\":\"{}\",\"direction\":\"{}\",\"bytes_out\":{},\"linked_tool\":\"{}\",\"confidence\":\"{}\",\"why\":\"{}\"}}",
            json_str(&f.ts), json_str(&f.host), json_str(&f.direction),
            f.bytes_out, json_str(&f.linked_tool), json_str(&f.confidence), json_str(&f.why)
        );
    }
    s.push(']');
    s.into_bytes()
}

// ── embedded web assets ──────────────────────────────────────────────────────

const PLAYER_JS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/asciinema-player.min.js"
));

const PLAYER_CSS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/asciinema-player.css"
));

const FONT_TTF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../web/font/JetBrainsMono-Regular.ttf"
));

// ── token generation ─────────────────────────────────────────────────────────

/// Generate a 128-bit random token encoded as 32 lowercase hex chars.
/// Uses `getrandom` directly — no dependency on `rand`.
pub fn gen_token() -> String {
    let mut bytes = [0u8; 16]; // 128 bits
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    agentprov_integrity::to_hex(&bytes)
}

// ── routing ───────────────────────────────────────────────────────────────────

/// Every possible response classification.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Token-gated index page (bakes token into the cast URL).
    Index,
    /// Vendored asciinema-player JS.
    Player,
    /// Vendored asciinema-player CSS.
    Css,
    /// JetBrains Mono font.
    Font,
    /// Bootstrap script that mounts the player (served from 'self' so CSP passes).
    Boot,
    /// Token-gated verified asciicast.
    Cast,
    /// Panel JS that fetches /log and /flows (served from 'self' so CSP passes).
    PanelJs,
    /// Token-gated tamper-evident frame-log JSON.
    Log,
    /// Token-gated network-flow overlay JSON.
    Flows,
    /// Token-gated GIF render (download).
    DownloadGif,
    /// Token-gated MP4 render (download).
    DownloadMp4,
    /// Wrong or missing token on a gated route.
    Forbidden,
    /// Anything not in the allowlist (includes path-traversal attempts).
    NotFound,
}

/// Map an HTTP request path (including query string) to a `Route`.
///
/// Algorithm:
/// 1. Split path at `?` to get (path_only, query).
/// 2. Match path_only against the fixed allowlist.
/// 3. For token-gated routes (`/` and `/cast`), extract `t=` from the query
///    and compare with `==` to the token. Wrong/missing → `Forbidden`.
/// 4. Everything else → `NotFound` (no filesystem access ever).
pub fn route(path: &str, token: &str) -> Route {
    // Split once at '?' — only the first '?' matters.
    let (path_only, query) = match path.find('?') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path, ""),
    };

    // Reject any path with traversal sequences immediately.
    // This is belt-and-suspenders; we also never do a filesystem join.
    if path_only.contains("..") || path_only.contains('\0') {
        return Route::NotFound;
    }

    // Token-gated routes carry capture data — require the exact token or 403.
    let gated = |r: Route| if token_matches(query, token) { r } else { Route::Forbidden };

    match path_only {
        "/" => gated(Route::Index),
        "/cast" => gated(Route::Cast),
        "/log" => gated(Route::Log),
        "/flows" => gated(Route::Flows),
        "/download.gif" => gated(Route::DownloadGif),
        "/download.mp4" => gated(Route::DownloadMp4),
        // Static assets / panel JS — no capture data, no token needed.
        "/player.js" => Route::Player,
        "/player.css" => Route::Css,
        "/font.ttf" => Route::Font,
        "/boot.js" => Route::Boot,
        "/panel.js" => Route::PanelJs,
        // Anything else (including /../../etc/passwd after stripping query).
        _ => Route::NotFound,
    }
}

/// Extract `t=<value>` from a query string and compare with `==` to `token`.
fn token_matches(query: &str, token: &str) -> bool {
    // Walk key=value pairs separated by '&'.
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix("t=") {
            // Exact comparison only — never contains/prefix/suffix.
            return val == token;
        }
    }
    false
}

// ── URL helper ────────────────────────────────────────────────────────────────

/// Build the full viewer URL from a bound port and a token.
pub fn build_url(port: u16, token: &str) -> String {
    format!("http://127.0.0.1:{port}/?t={token}")
}

// ── security headers ─────────────────────────────────────────────────────────

/// The security header block appended to every response.
///
/// CSP: `default-src 'none'` kills everything not explicitly allowed.
/// No remote URLs — all origins are 'self'. `script-src 'self'` with
/// `'wasm-unsafe-eval'` is required: asciinema-player 3.x uses a WASM terminal
/// emulator (`WebAssembly.instantiate`). Without `'wasm-unsafe-eval'` the player
/// silently fails to render. This is the only deviation from the mandated CSP;
/// inline `<script>` is still blocked (hence the /boot.js route), and no remote
/// origins are allowed.
pub fn security_headers() -> &'static str {
    "Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n"
}

// ── HTML page generation ──────────────────────────────────────────────────────

/// Build the index HTML for a successfully verified capture.
///
/// The cast URL embeds the token in data-cast so the inline-free CSP passes.
/// `AsciinemaPlayer.create` is called from /boot.js (served from 'self').
fn index_html(summary: &ReplaySummary, token: &str, can_gif: bool, can_mp4: bool) -> Vec<u8> {
    let cmd = html_escape(&summary.command);
    let exit = html_escape(&summary.exit);
    let duration = format!("{:.1}s", summary.duration_secs);
    let dims = format!("{}×{}", summary.width, summary.height);
    let tip = &summary.tip_hex[..12.min(summary.tip_hex.len())];
    let frames = summary.frames;
    // Download buttons — disabled (with reason) when the renderer is missing.
    let gif_btn = download_btn("download.gif", "Download GIF", can_gif, token);
    let mp4_btn = download_btn("download.mp4", "Download MP4", can_mp4, token);

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>agentprov viewer — {cmd}</title>
<link rel="stylesheet" href="/player.css">
<style>
:root{{--bg:#0b0e14;--panel:#11151f;--line:#1e2433;--ink:#e6edf3;--dim:#7d8694;--ok:#3fb950;--mono:ui-monospace,"SF Mono",Menlo,monospace;}}
*{{box-sizing:border-box;}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;}}
@font-face{{font-family:"JetBrains Mono";src:url("/font.ttf") format("truetype");font-weight:400;}}
header{{padding:14px 24px;border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:10px;}}
header h1{{font-size:15px;margin:0;}}
header .tag{{color:var(--dim);font-size:13px;}}
.badge{{display:inline-block;padding:3px 9px;border-radius:999px;font:11px/1 var(--mono);border:1px solid var(--line);background:var(--panel);color:var(--dim);margin-left:4px;}}
.badge b{{color:var(--ink);}}
.ok{{color:var(--ok);font-weight:700;}}
.container{{max-width:1100px;margin:0 auto;padding:20px 24px 60px;}}
.meta{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center;}}
#player{{border:1px solid var(--line);border-radius:8px;overflow:hidden;height:500px;}}
.actions{{margin:16px 0;display:flex;gap:10px;}}
.btn{{display:inline-block;padding:7px 14px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--ink);font:13px var(--mono);text-decoration:none;cursor:pointer;}}
.btn[aria-disabled="true"]{{opacity:.4;pointer-events:none;}}
.section{{margin-top:24px;border:1px solid var(--line);border-radius:8px;background:var(--panel);}}
.section>summary,.section>.shead{{padding:12px 16px;font:13px var(--mono);color:var(--dim);cursor:pointer;user-select:none;}}
#logbox{{padding:0 16px 16px;overflow:auto;}}
#logbox table{{width:100%;border-collapse:collapse;font:12px var(--mono);}}
#logbox th,#logbox td{{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);color:var(--ink);}}
#logbox th{{color:var(--dim);}}
#flowbox{{padding:0 16px 16px;}}
.flow{{padding:8px 0;border-bottom:1px solid var(--line);font:12px var(--mono);}}
.claim{{color:var(--dim);font-style:italic;margin-top:3px;}}
</style>
</head>
<body>
<header>
  <h1>agentprov</h1>
  <span class="tag">tamper-evident viewer</span>
  <span class="badge ok">✓ verified</span>
</header>
<div class="container">
  <div class="meta">
    <span class="badge">cmd: <b>{cmd}</b></span>
    <span class="badge">exit: <b>{exit}</b></span>
    <span class="badge">duration: <b>{duration}</b></span>
    <span class="badge">dims: <b>{dims}</b></span>
    <span class="badge">tip: <b>{tip}…</b></span>
  </div>
  <div id="player"
       data-cast="/cast?t={token}"
       data-theme="asciinema"
       data-fit="both"
       data-font-size="14px">
  </div>
  <div class="actions">{gif_btn}{mp4_btn}</div>

  <div class="section">
    <div class="shead" id="logbtn">▸ Tamper-evident log — {frames} frames · <span class="ok">SIGNATURE VALID</span> · tip {tip}…</div>
    <div id="logbox" hidden></div>
  </div>

  <div class="section">
    <div class="shead">Network egress (OS-observed; correlation is agentsnitch's claim)</div>
    <div id="flowbox"></div>
  </div>
</div>
<script src="/player.js"></script>
<script src="/boot.js"></script>
<script src="/panel.js"></script>
</body>
</html>
"#
    );
    html.into_bytes()
}

/// One download button. Disabled (with a reason title) when the renderer is absent.
fn download_btn(route: &str, label: &str, enabled: bool, token: &str) -> String {
    if enabled {
        format!(r#"<a class="btn" href="/{route}?t={token}">{label}</a>"#)
    } else {
        format!(r#"<span class="btn" aria-disabled="true" title="install agg/ffmpeg to enable">{label}</span>"#)
    }
}

/// A minimal error page served when APCAP verification fails.
/// No capture bytes, no player, no token.
fn error_html(reason: &str) -> Vec<u8> {
    let reason = html_escape(reason);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>agentprov viewer — verification failed</title>
<style>body{{margin:0;background:#0b0e14;color:#e6edf3;font:14px/1.6 -apple-system,sans-serif;padding:40px;}}
h1{{color:#f85149;}}pre{{background:#11151f;border:1px solid #1e2433;padding:12px;border-radius:6px;white-space:pre-wrap;word-break:break-word;}}</style>
</head>
<body>
<h1>Capture failed verification</h1>
<p>This APCAP file did not pass the tamper-evidence check. The content has NOT been displayed.</p>
<pre>{reason}</pre>
</body>
</html>
"#
    )
    .into_bytes()
}

/// Bootstrap script: reads `data-cast` from the player div and mounts the player.
/// Served from /boot.js so CSP `script-src 'self'` allows it.
fn boot_js() -> &'static [u8] {
    b"(function(){var el=document.getElementById('player');if(!el)return;var cast=el.getAttribute('data-cast');var theme=el.getAttribute('data-theme')||'asciinema';var fit=el.getAttribute('data-fit')||'both';var fontSize=el.getAttribute('data-font-size')||'14px';if(window.AsciinemaPlayer&&cast){AsciinemaPlayer.create(cast,el,{theme:theme,fit:fit,terminalFontSize:fontSize,autoPlay:false});}})();\n"
}

/// Panel JS: fetches /log and /flows (with the token from the URL) and renders
/// the tamper-evident log table + network overlay. Served from 'self' so the
/// strict CSP (no inline script) passes. Pure DOM building — no innerHTML with
/// untrusted data (textContent only), so terminal/flow strings can't inject.
fn panel_js() -> &'static [u8] {
    br#"(function(){
var t=new URLSearchParams(location.search).get('t');
function mk(tag,txt){var e=document.createElement(tag);if(txt!=null)e.textContent=txt;return e;}
// Tamper-evident log
var logBtn=document.getElementById('logbtn'),logBox=document.getElementById('logbox');
if(logBtn){logBtn.addEventListener('click',function(){
  if(logBox.dataset.loaded){logBox.hidden=!logBox.hidden;return;}
  fetch('/log?t='+encodeURIComponent(t)).then(function(r){return r.json();}).then(function(rows){
    var tbl=mk('table');var h=mk('tr');['seq','time','kind','bytes','hash'].forEach(function(c){h.appendChild(mk('th',c));});tbl.appendChild(h);
    rows.forEach(function(r){var tr=mk('tr');
      tr.appendChild(mk('td',r.seq));tr.appendChild(mk('td',r.at.toFixed(3)+'s'));
      tr.appendChild(mk('td',r.kind));tr.appendChild(mk('td',r.bytes));
      tr.appendChild(mk('td',r.hash.slice(0,12)+'...'));tbl.appendChild(tr);});
    logBox.appendChild(tbl);logBox.dataset.loaded='1';logBox.hidden=false;
  });
});}
// Network overlay
var flowBox=document.getElementById('flowbox');
if(flowBox){fetch('/flows?t='+encodeURIComponent(t)).then(function(r){return r.json();}).then(function(rows){
  if(!rows.length){flowBox.appendChild(mk('p','No network overlay (run: agentprov flows <events.jsonl> <session-dir>).'));return;}
  rows.forEach(function(f){var d=mk('div');d.className='flow';
    d.appendChild(mk('span',f.direction+' '+f.host+'  '+f.bytes_out+'B  '+f.ts));
    if(f.linked_tool||f.confidence){var c=mk('div');c.className='claim';
      c.textContent='agentsnitch reports: linked to '+f.linked_tool+' (confidence: '+f.confidence+')'+(f.why?' - '+f.why:'');d.appendChild(c);}
    flowBox.appendChild(d);});
});}
})();
"#
}

/// Minimal HTML escaping for values inserted into HTML attributes/text.
fn html_escape(s: &str) -> String {
    s.chars().fold(String::new(), |mut out, c| {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
        out
    })
}

// ── HTTP response helpers ─────────────────────────────────────────────────────

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{}\r\n",
        body.len(),
        security_headers()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn write_forbidden(stream: &mut TcpStream) -> io::Result<()> {
    write_response(stream, "403 Forbidden", "text/plain; charset=utf-8", b"403 Forbidden")
}

fn write_not_found(stream: &mut TcpStream) -> io::Result<()> {
    write_response(stream, "404 Not Found", "text/plain; charset=utf-8", b"404 Not Found")
}

/// Render the capture to gif/mp4 (server-side, via export crate) and stream it
/// as a download. The apcap path is SERVER-side (never from the request), and
/// export goes through replay-core so a tampered capture fails to render.
fn write_render(
    stream: &mut TcpStream,
    state: &Arc<ServerState>,
    format: agentprov_export::Format,
) -> io::Result<()> {
    let (ext, ctype) = match format {
        agentprov_export::Format::Gif => ("gif", "image/gif"),
        agentprov_export::Format::Mp4 => ("mp4", "video/mp4"),
    };
    let tmp = std::env::temp_dir().join(format!("agentprov-view-{}.{ext}", std::process::id()));
    if let Err(e) = agentprov_export::render(&state.apcap_path, &tmp, format) {
        let _ = std::fs::remove_file(&tmp);
        return write_response(
            stream,
            "500 Internal Server Error",
            "text/plain; charset=utf-8",
            format!("render failed: {e}").as_bytes(),
        );
    }
    let body = std::fs::read(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nContent-Disposition: attachment; filename=\"session.{ext}\"\r\nCache-Control: no-store\r\n{}\r\n",
        body.len(), security_headers()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

fn write_method_not_allowed(stream: &mut TcpStream) -> io::Result<()> {
    write_response(
        stream,
        "405 Method Not Allowed",
        "text/plain; charset=utf-8",
        b"405 Method Not Allowed",
    )
}

// ── request line parsing ──────────────────────────────────────────────────────

/// Parse an HTTP request line like `GET /path?q HTTP/1.1` → `(method, path_with_query)`.
/// Returns `None` if the line is malformed.
fn parse_request_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

// ── server state ──────────────────────────────────────────────────────────────

/// Immutable state shared across all connections (single-threaded loop, so Arc
/// is belt-and-suspenders for future threading, but we never spawn threads here).
struct ServerState {
    token: String,
    /// Pre-generated asciicast bytes (verified at startup). `None` if verify failed.
    cast_bytes: Option<Vec<u8>>,
    /// Pre-generated index HTML (contains token — generated once).
    index_html: Vec<u8>,
    /// Error HTML (used when cast_bytes is None).
    error_html: Vec<u8>,
    /// SERVER-side apcap path — used to render video on demand. Never from a
    /// request (no path-traversal surface).
    apcap_path: PathBuf,
    /// Pre-built tamper-evident log JSON (the frame chain). Empty if verify failed.
    log_json: Vec<u8>,
    /// Pre-built network-flow overlay JSON (from a sibling flows.jsonl, if any).
    flows_json: Vec<u8>,
}

impl ServerState {
    fn new(apcap_path: &PathBuf) -> io::Result<Self> {
        let token = gen_token();
        let apcap_bytes = std::fs::read(apcap_path)?;

        // Renderer availability (for the download buttons).
        let renderers = agentprov_export::renderers_available();
        let can_gif = renderers.agg;
        let can_mp4 = renderers.agg && renderers.ffmpeg;

        // Network-flow overlay: optional sibling flows.jsonl next to the apcap.
        let flows_json = load_flows_json(apcap_path);

        match summarize(&apcap_bytes[..]) {
            Ok(summary) => {
                let mut cast_buf = Vec::new();
                to_asciicast(&apcap_bytes[..], &mut cast_buf)
                    .map_err(|e| io::Error::other(e.to_string()))?;

                // Tamper-evident log JSON (frame chain).
                let log_json = match frame_log(&apcap_bytes[..]) {
                    Ok(entries) => frame_log_json(&entries),
                    Err(_) => b"[]".to_vec(),
                };

                let idx = index_html(&summary, &token, can_gif, can_mp4);
                Ok(Self {
                    index_html: idx,
                    cast_bytes: Some(cast_buf),
                    error_html: Vec::new(),
                    token,
                    apcap_path: apcap_path.clone(),
                    log_json,
                    flows_json,
                })
            }
            Err(e) => Ok(Self {
                index_html: Vec::new(),
                cast_bytes: None,
                error_html: error_html(&e.to_string()),
                token,
                apcap_path: apcap_path.clone(),
                log_json: b"[]".to_vec(),
                flows_json,
            }),
        }
    }
}

/// Load + parse a sibling `flows.jsonl` next to the apcap into overlay JSON.
/// Missing file → empty array (no overlay; never an error).
fn load_flows_json(apcap_path: &Path) -> Vec<u8> {
    let flows_path = apcap_path.with_file_name("flows.jsonl");
    let Ok(file) = std::fs::File::open(&flows_path) else {
        return b"[]".to_vec();
    };
    let flows = agentprov_collectors::parse_flows(BufReader::new(file));
    flows_json(&flows)
}

// ── connection handler ────────────────────────────────────────────────────────

fn handle_connection(mut stream: TcpStream, state: &Arc<ServerState>) {
    let reader = BufReader::new(&stream);
    let mut lines = reader.lines();

    // Read only the request line; ignore the rest of the headers.
    let request_line = match lines.next() {
        Some(Ok(line)) => line,
        _ => return, // malformed or EOF
    };

    let (method, path) = match parse_request_line(&request_line) {
        Some(v) => v,
        None => return,
    };

    // Only GET is supported.
    if method != "GET" {
        let _ = write_method_not_allowed(&mut stream);
        return;
    }

    // Determine the route (pure function, no filesystem access).
    let r = route(path, &state.token);

    let result = match r {
        Route::Index => {
            if state.cast_bytes.is_some() {
                write_response(
                    &mut stream,
                    "200 OK",
                    "text/html; charset=utf-8",
                    &state.index_html,
                )
            } else {
                write_response(
                    &mut stream,
                    "200 OK",
                    "text/html; charset=utf-8",
                    &state.error_html,
                )
            }
        }
        Route::Cast => match &state.cast_bytes {
            Some(bytes) => write_response(
                &mut stream,
                "200 OK",
                "application/json",
                bytes,
            ),
            None => write_not_found(&mut stream),
        },
        Route::Player => write_response(
            &mut stream,
            "200 OK",
            "application/javascript; charset=utf-8",
            PLAYER_JS,
        ),
        Route::Css => write_response(
            &mut stream,
            "200 OK",
            "text/css; charset=utf-8",
            PLAYER_CSS,
        ),
        Route::Font => write_response(&mut stream, "200 OK", "font/ttf", FONT_TTF),
        Route::Boot => write_response(
            &mut stream,
            "200 OK",
            "application/javascript; charset=utf-8",
            boot_js(),
        ),
        Route::PanelJs => write_response(
            &mut stream,
            "200 OK",
            "application/javascript; charset=utf-8",
            panel_js(),
        ),
        Route::Log => write_response(&mut stream, "200 OK", "application/json", &state.log_json),
        Route::Flows => write_response(&mut stream, "200 OK", "application/json", &state.flows_json),
        Route::DownloadGif => write_render(&mut stream, state, agentprov_export::Format::Gif),
        Route::DownloadMp4 => write_render(&mut stream, state, agentprov_export::Format::Mp4),
        Route::Forbidden => write_forbidden(&mut stream),
        Route::NotFound => write_not_found(&mut stream),
    };

    // Best-effort: ignore write errors (client may have closed).
    let _ = result;
}

// ── public entry point ────────────────────────────────────────────────────────

/// Serve `apcap_path` on `127.0.0.1:<os-port>` behind a random 128-bit token.
///
/// Prints the full URL (including token) to stderr on startup, then blocks
/// accepting connections until the process exits or an unrecoverable error
/// occurs. Single-threaded accept loop: one viewer, one user.
///
/// If the APCAP fails verification, still binds and serves an error page —
/// the URL is printed so the caller can open it and see the failure reason.
pub fn serve(apcap_path: PathBuf) -> io::Result<()> {
    serve_inner(apcap_path, false)
}

/// Like [`serve`], but also opens the system browser at the viewer URL so the
/// user doesn't copy/paste (and risk pasting a stale viewer's URL → 403).
pub fn serve_and_open(apcap_path: PathBuf) -> io::Result<()> {
    serve_inner(apcap_path, true)
}

fn serve_inner(apcap_path: PathBuf, open_browser: bool) -> io::Result<()> {
    let state = ServerState::new(&apcap_path)?;
    let state = Arc::new(state);

    // Bind on loopback with OS-assigned port. NEVER 0.0.0.0.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let url = build_url(port, &state.token);

    println!("agentprov viewer: {url}");
    if state.cast_bytes.is_none() {
        println!("agentprov viewer: WARNING — capture did not verify; error page will be shown");
    }
    if open_browser {
        open_in_browser(&url);
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_connection(s, &state),
            Err(e) => eprintln!("agentprov viewer: connection error: {e}"),
        }
    }
    Ok(())
}

/// Open `url` in the default browser, best-effort. `open` on macOS, `xdg-open`
/// on Linux. Failure is silent — the URL is already printed for manual use.
fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(target_os = "macos"))]
    let opener = "xdg-open";
    let _ = std::process::Command::new(opener).arg(url).spawn();
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use agentprov_capture_format::{FrameType, Writer};

    /// Regression: the URL the viewer PRINTS must route to Index, not Forbidden.
    /// (Reproduces the "paste the URL → 403" report.)
    #[test]
    fn printed_url_routes_to_index_not_403() {
        let token = gen_token();
        let url = build_url(12345, &token);
        // what the browser sends as the request target: path + query
        let target = &url[url.find("/?").expect("url has /?")..];
        assert_eq!(route(target, &token), Route::Index, "url={url} target={target}");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal valid APCAP in memory for smoke-testing the data path.
    fn make_apcap() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        let resize = {
            let mut p = [0u8; 4];
            p[0..2].copy_from_slice(&80u16.to_le_bytes());
            p[2..4].copy_from_slice(&24u16.to_le_bytes());
            p
        };
        w.write(FrameType::SessionStart, 0, 0, b"claude --bare").unwrap();
        w.write(FrameType::Resize, 10_000_000, 10_000_000, &resize).unwrap();
        w.write(FrameType::PtyOutput, 100_000_000, 100_000_000, b"hello\n").unwrap();
        w.write(FrameType::SessionEnd, 200_000_000, 200_000_000, b"exit=0").unwrap();
        buf
    }

    // ── gen_token ────────────────────────────────────────────────────────────

    #[test]
    fn gen_token_length_and_uniqueness() {
        let a = gen_token();
        let b = gen_token();
        // >=32 hex chars (128-bit entropy at 4 bits/char = 32 chars minimum).
        assert!(a.len() >= 32, "token too short: {}", a.len());
        // All chars are lowercase hex.
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "non-hex char in token");
        // Two consecutive calls must differ (probability of collision ≈ 2^-128).
        assert_ne!(a, b, "two consecutive tokens must differ");
    }

    // ── route ────────────────────────────────────────────────────────────────

    const GOOD: &str = "deadbeef0123456789abcdef01234567"; // 32-char fake token

    #[test]
    fn route_index_correct_token() {
        assert_eq!(route(&format!("/?t={GOOD}"), GOOD), Route::Index);
    }

    #[test]
    fn route_index_wrong_token_is_forbidden() {
        assert_eq!(route("/?t=wrongtoken", GOOD), Route::Forbidden);
    }

    #[test]
    fn route_index_missing_token_is_forbidden() {
        assert_eq!(route("/", GOOD), Route::Forbidden);
    }

    #[test]
    fn route_cast_correct_token() {
        assert_eq!(route(&format!("/cast?t={GOOD}"), GOOD), Route::Cast);
    }

    #[test]
    fn route_cast_wrong_token_is_forbidden() {
        assert_eq!(route("/cast?t=bad", GOOD), Route::Forbidden);
    }

    #[test]
    fn route_cast_missing_token_is_forbidden() {
        assert_eq!(route("/cast", GOOD), Route::Forbidden);
    }

    #[test]
    fn route_static_assets_no_token_needed() {
        assert_eq!(route("/player.js", GOOD), Route::Player);
        assert_eq!(route("/player.css", GOOD), Route::Css);
        assert_eq!(route("/font.ttf", GOOD), Route::Font);
        assert_eq!(route("/boot.js", GOOD), Route::Boot);
    }

    #[test]
    fn route_path_traversal_is_not_found() {
        // No client path ever maps to a filesystem read.
        assert_eq!(route("/../../etc/passwd", GOOD), Route::NotFound);
        assert_eq!(route("/../../../etc/shadow?t=x", GOOD), Route::NotFound);
        assert_eq!(route("/..%2f..%2fetc%2fpasswd", GOOD), Route::NotFound);
    }

    #[test]
    fn route_unknown_paths_are_not_found() {
        assert_eq!(route("/random", GOOD), Route::NotFound);
        assert_eq!(route("/chain.jsonl", GOOD), Route::NotFound);
        assert_eq!(route("/admin", GOOD), Route::NotFound);
        assert_eq!(route("/cast.cast", GOOD), Route::NotFound);
    }

    // Guard: a path that CONTAINS the right token as a substring but is not
    // the exact value must not be treated as valid.
    #[test]
    fn route_token_substring_is_forbidden() {
        // The query value has the right token embedded but with a prefix.
        let bad_query = format!("/cast?t=prefix{GOOD}");
        assert_eq!(route(&bad_query, GOOD), Route::Forbidden);

        let bad_suffix = format!("/cast?t={GOOD}suffix");
        assert_eq!(route(&bad_suffix, GOOD), Route::Forbidden);
    }

    // ── security_headers ─────────────────────────────────────────────────────

    #[test]
    fn security_headers_csp() {
        let h = security_headers();
        assert!(h.contains("default-src 'none'"), "must include default-src 'none'");
        assert!(h.contains("X-Content-Type-Options: nosniff"), "must include nosniff");
        // No remote origins allowed in any directive.
        assert!(!h.contains("http://"), "must not contain http:// (remote origin)");
        assert!(!h.contains("https://"), "must not contain https:// (remote origin)");
        // wasm-unsafe-eval is required because asciinema-player 3.x uses a WASM
        // terminal emulator (10 WebAssembly references in the minified JS).
        assert!(h.contains("'wasm-unsafe-eval'"), "must include wasm-unsafe-eval for asciinema-player WASM");
    }

    #[test]
    fn security_headers_no_inline_script() {
        let h = security_headers();
        // CSP must NOT contain 'unsafe-inline' applied to scripts.
        // 'unsafe-inline' is allowed ONLY in style-src.
        // The script-src directive must be 'self' + 'wasm-unsafe-eval' only.
        assert!(h.contains("script-src 'self' 'wasm-unsafe-eval'"),
            "script-src must be 'self' 'wasm-unsafe-eval' — no unsafe-inline");
        // 'unsafe-inline' must appear only as part of style-src, not script-src.
        // We verify this by checking that style-src contains unsafe-inline.
        assert!(h.contains("style-src 'self' 'unsafe-inline'"),
            "style-src must contain unsafe-inline (needed for asciinema-player CSS variables)");
        // And the style-src unsafe-inline must not somehow enable scripts.
        // This is structurally guaranteed because CSP directives are separated by ';'.
        let script_directive = h.split(';').find(|d| d.trim_start().starts_with("script-src"));
        let script_directive = script_directive.expect("must have script-src directive");
        assert!(!script_directive.contains("'unsafe-inline'"),
            "script-src directive must not contain 'unsafe-inline'");
    }

    // ── build_url ─────────────────────────────────────────────────────────────

    #[test]
    fn build_url_format() {
        let url = build_url(54321, "abc123");
        assert_eq!(url, "http://127.0.0.1:54321/?t=abc123");
        // Must be loopback only.
        assert!(url.starts_with("http://127.0.0.1:"), "must be loopback");
    }

    // ── data path smoke test ──────────────────────────────────────────────────

    /// Confirm that a Writer-built in-memory APCAP goes through
    /// `to_asciicast` cleanly. This validates the viewer's data path works
    /// before we ever spin up a server.
    #[test]
    fn apcap_to_asciicast_smoke() {
        let apcap = make_apcap();
        let mut out = Vec::new();
        let n = to_asciicast(&apcap[..], &mut out).expect("to_asciicast must succeed on valid APCAP");
        assert!(n > 0, "should emit at least one event line");
        let text = std::str::from_utf8(&out).expect("asciicast must be UTF-8");
        assert!(text.starts_with('{'), "asciicast must start with JSON header");
        assert!(text.contains("\"version\":2"), "asciicast header must have version:2");
    }

    /// Confirm that `summarize` returns expected fields on the same APCAP.
    #[test]
    fn summarize_smoke() {
        let apcap = make_apcap();
        let s = summarize(&apcap[..]).expect("summarize must succeed on valid APCAP");
        assert_eq!(s.command, "claude --bare");
        assert_eq!(s.exit, "exit=0");
        assert_eq!(s.width, 80);
        assert_eq!(s.height, 24);
    }

    // ── parse_request_line ────────────────────────────────────────────────────

    #[test]
    fn parse_request_line_valid() {
        let (m, p) = parse_request_line("GET /foo?t=abc HTTP/1.1").unwrap();
        assert_eq!(m, "GET");
        assert_eq!(p, "/foo?t=abc");
    }

    #[test]
    fn parse_request_line_malformed_returns_none() {
        assert!(parse_request_line("BADLINE").is_none());
        assert!(parse_request_line("").is_none());
    }

    #[test]
    fn new_data_routes_are_token_gated() {
        let tok = "secrettoken";
        // Correct token → the intended route.
        assert_eq!(route("/log?t=secrettoken", tok), Route::Log);
        assert_eq!(route("/flows?t=secrettoken", tok), Route::Flows);
        assert_eq!(route("/download.gif?t=secrettoken", tok), Route::DownloadGif);
        assert_eq!(route("/download.mp4?t=secrettoken", tok), Route::DownloadMp4);
        // Wrong / missing token → Forbidden, never the data route.
        assert_eq!(route("/log?t=wrong", tok), Route::Forbidden);
        assert_eq!(route("/flows", tok), Route::Forbidden);
        assert_eq!(route("/download.gif", tok), Route::Forbidden);
        // panel.js needs no token (no capture data).
        assert_eq!(route("/panel.js", tok), Route::PanelJs);
        // Traversal on a data route → NotFound, never a file read.
        assert_eq!(route("/../log?t=secrettoken", tok), Route::NotFound);
    }

    #[test]
    fn log_json_has_frames_and_hashes() {
        let apcap = make_apcap();
        let entries = frame_log(&apcap[..]).unwrap();
        let json = String::from_utf8(frame_log_json(&entries)).unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains("\"seq\":0"));
        assert!(json.contains("\"hash\":\""));
        assert!(json.contains("\"kind\":\"SessionStart\""));
    }
}
