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

use agentprov_replay_core::{summarize, to_asciicast, ReplaySummary};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;

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

// ── error ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ViewerError {
    Io(io::Error),
    Replay(agentprov_replay_core::ReplayError),
}

impl std::fmt::Display for ViewerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Replay(e) => write!(f, "replay: {e}"),
        }
    }
}

impl From<io::Error> for ViewerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<agentprov_replay_core::ReplayError> for ViewerError {
    fn from(e: agentprov_replay_core::ReplayError) -> Self {
        Self::Replay(e)
    }
}

// ── token generation ─────────────────────────────────────────────────────────

/// Generate a 128-bit random token encoded as 32 lowercase hex chars.
/// Uses `getrandom` directly — no dependency on `rand`.
pub fn gen_token() -> String {
    let mut bytes = [0u8; 16]; // 128 bits
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
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

    match path_only {
        // Token-gated routes — capture data flows through here.
        "/" => {
            if token_matches(query, token) {
                Route::Index
            } else {
                Route::Forbidden
            }
        }
        "/cast" => {
            if token_matches(query, token) {
                Route::Cast
            } else {
                Route::Forbidden
            }
        }
        // Static vendored assets — no capture data, no token needed.
        "/player.js" => Route::Player,
        "/player.css" => Route::Css,
        "/font.ttf" => Route::Font,
        "/boot.js" => Route::Boot,
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
fn index_html(summary: &ReplaySummary, token: &str) -> Vec<u8> {
    let cmd = html_escape(&summary.command);
    let exit = html_escape(&summary.exit);
    let duration = format!("{:.1}s", summary.duration_secs);
    let dims = format!("{}×{}", summary.width, summary.height);
    let tip = &summary.tip_hex[..12.min(summary.tip_hex.len())];

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
.meta{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;}}
#player{{border:1px solid var(--line);border-radius:8px;overflow:hidden;height:500px;}}
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
</div>
<script src="/player.js"></script>
<script src="/boot.js"></script>
</body>
</html>
"#
    );
    html.into_bytes()
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
}

impl ServerState {
    fn new(apcap_path: &PathBuf) -> Result<Self, ViewerError> {
        let token = gen_token();

        // Read the APCAP file once.
        let apcap_bytes = std::fs::read(apcap_path)?;

        // Attempt to summarize (chain-verifies internally).
        let summary_result = summarize(&apcap_bytes[..]);

        match summary_result {
            Ok(summary) => {
                // Generate verified asciicast.
                let mut cast_buf = Vec::new();
                to_asciicast(&apcap_bytes[..], &mut cast_buf)?;

                let idx = index_html(&summary, &token);
                Ok(Self {
                    index_html: idx,
                    cast_bytes: Some(cast_buf),
                    error_html: Vec::new(), // not used when verified
                    token,
                })
            }
            Err(e) => {
                let err_html = error_html(&e.to_string());
                Ok(Self {
                    token,
                    cast_bytes: None,
                    index_html: Vec::new(), // not used when failed
                    error_html: err_html,
                })
            }
        }
    }
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
    let state = ServerState::new(&apcap_path).map_err(|e| io::Error::other(e.to_string()))?;
    let state = Arc::new(state);

    // Bind on loopback with OS-assigned port. NEVER 0.0.0.0.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let url = build_url(port, &state.token);

    eprintln!("agentprov viewer: {url}");
    if state.cast_bytes.is_none() {
        eprintln!("agentprov viewer: WARNING — capture did not verify; error page will be shown");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_connection(s, &state),
            Err(e) => eprintln!("agentprov viewer: connection error: {e}"),
        }
    }
    Ok(())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use agentprov_capture_format::{FrameType, Writer};

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
}
