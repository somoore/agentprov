package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func awaitInterrupt() <-chan os.Signal {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	return c
}

//go:embed viewer.html
var viewerHTML []byte

//go:embed sample.jsonl
var sampleTranscript []byte

//go:embed web/asciinema-player.min.js
var asciinemaJS []byte

//go:embed web/asciinema-player.css
var asciinemaCSS []byte

//go:embed web/font/JetBrainsMono-Regular.ttf
var fontRegular []byte

//go:embed web/font/JetBrainsMono-Bold.ttf
var fontBold []byte

// fontDir writes the embedded JetBrains Mono fonts to a temp dir so agg can use
// them — JetBrains Mono (Apache 2.0) covers the glyphs Claude's TUI uses (❯,
// box-drawing, powerline) that system fonts like Menlo render as blobs. Returns
// "" if the write fails (agg then falls back to a system font).
func fontDir() string {
	// Per-user cache dir, 0700, and create-if-absent with O_EXCL: a shared fixed
	// path in $TMPDIR lets another local account pre-plant a symlink or a font
	// that agg then loads.
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "agentprov", "fonts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	reg := filepath.Join(dir, "JetBrainsMono-Regular.ttf")
	bold := filepath.Join(dir, "JetBrainsMono-Bold.ttf")
	if !writeFontIfMissing(reg, fontRegular) {
		return ""
	}
	_ = writeFontIfMissing(bold, fontBold)
	return dir
}

// writeFontIfMissing creates a font 0600 only if no entry exists. An existing
// entry is accepted only if it is a regular file (never a symlink/device).
func writeFontIfMissing(path string, data []byte) bool {
	if fi, err := os.Lstat(path); err == nil {
		return fi.Mode().IsRegular()
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	return werr == nil && cerr == nil
}

// cmdDemo is the zero-install proof: write the bundled sample transcript, record
// it to a chain, verify it clean, then tell the user the one command that breaks
// it. Works with no Claude/Codex install and no transcript of their own.
func cmdDemo() error {
	const sample = "agentprov-sample.jsonl"
	if err := writeFileAtomic(sample, sampleTranscript, 0o600); err != nil {
		return err
	}
	fmt.Print("agentprov demo — a tamper-evident record of a (sample) agent run.\n\n")
	fmt.Printf("1. recording the bundled sample run (%s) ...\n", sample)
	if err := cmdRecord(sample); err != nil {
		return err
	}
	fmt.Println("\n2. verifying the record (pinned to the public key this demo just wrote):")
	if err := cmdVerifyWith("chain.jsonl", "chain.pub", false); err != nil {
		return err
	}
	fmt.Println("\n3. now BREAK it — alter what the agent did, and watch verify fail:")
	fmt.Println("     agentprov tamper chain.jsonl 7    # rewrite the curl command")
	fmt.Println("     agentprov verify chain.jsonl      # -> CHAIN BROKEN at seq 7")
	fmt.Println("\n   or see it in the browser:")
	fmt.Println("     agentprov view chain.jsonl")
	return nil
}

// cmdView serves the embedded viewer + the chain file on loopback and opens a
// browser at it. Served (not file://) so the viewer can fetch the chain by URL.
// The viewer is a pure renderer: it recomputes the hash chain for consistency.
// It has no key, so it does NOT verify signatures — the CLI does that.
func cmdView(chainPath string) error { return cmdViewFlows(chainPath, "") }

// renderVideo turns a .cast into a video by RE-RENDERING the recording's frames
// (agg, then ffmpeg for mp4) — never by capturing the screen. Returns the output
// path and its content-type. Used by both the CLI and the viewer's /video
// endpoint, so the user can click a button and get a download. err names exactly
// what's missing so the UI can tell them how to enable it.
func renderVideo(castPath, format string) (outPath, contentType string, err error) {
	if _, e := os.Stat(castPath); e != nil {
		return "", "", fmt.Errorf("cast not found: %s", castPath)
	}
	agg, e := exec.LookPath("agg")
	if e != nil {
		return "", "", errors.New("agg-missing")
	}
	dir := filepath.Dir(castPath)
	base := strings.TrimSuffix(filepath.Base(castPath), filepath.Ext(castPath))
	gifPath := filepath.Join(dir, base+".gif")

	// Render from a SANITIZED COPY of the cast, never the original: agg draws a
	// non-breaking space (U+00A0, which Claude's prompt emits) as a visible box.
	// We replace nbsp with a normal space for the video only. The signed/served
	// cast stays byte-exact — we never alter the evidence to make the video look
	// nicer; we render a cosmetically-cleaned copy.
	renderSrc := castPath
	if raw, e := os.ReadFile(castPath); e == nil {
		cleaned := strings.ReplaceAll(string(raw), " ", " ")
		if cleaned != string(raw) {
			// O_EXCL + a random name in the per-user temp dir: never a predictable
			// shared path that a pre-planted symlink could redirect.
			if tmpf, terr := os.CreateTemp("", "agentprov-render-*.cast"); terr == nil {
				_, werr := tmpf.WriteString(cleaned)
				cerr := tmpf.Close()
				if werr == nil && cerr == nil {
					renderSrc = tmpf.Name()
					defer os.Remove(tmpf.Name())
				} else {
					os.Remove(tmpf.Name())
				}
			}
		}
	}
	// Tuned for TUI fidelity: a high FPS cap so the agent's in-place repaints
	// (spinners, token counters) land on settled frames rather than mid-paint,
	// a real terminal monospace font with proper box-drawing glyphs, and a
	// short idle cap so we don't dwell on dead frames. Residual smearing on a
	// line that's repainting at the captured instant is inherent to flattening
	// a TUI to video — these flags minimize it.
	aggArgs := []string{"--fps-cap", "30", "--idle-time-limit", "2", "--font-size", "16"}
	if fd := fontDir(); fd != "" {
		// bundled JetBrains Mono — crisp ❯, box-drawing, powerline glyphs.
		aggArgs = append(aggArgs, "--font-dir", fd, "--font-family", "JetBrains Mono")
	} else {
		aggArgs = append(aggArgs, "--font-family", aggFont())
	}
	aggArgs = append(aggArgs, renderSrc, gifPath)
	if out, e := exec.Command(agg, aggArgs...).CombinedOutput(); e != nil {
		// retry bare (no font flags) if the bundled/system font is rejected.
		if out2, e2 := exec.Command(agg, "--fps-cap", "30", "--idle-time-limit", "2", renderSrc, gifPath).CombinedOutput(); e2 != nil {
			return "", "", fmt.Errorf("agg failed: %v\n%s\n%s", e, out, out2)
		}
	}
	if format == "gif" {
		return gifPath, "image/gif", nil
	}
	// mp4 requested (default): needs ffmpeg; fall back to gif if absent.
	ff, e := exec.LookPath("ffmpeg")
	if e != nil {
		return gifPath, "image/gif", nil // gif is a fine, universally-playable fallback
	}
	mp4Path := filepath.Join(dir, base+".mp4")
	args := []string{"-y", "-i", gifPath, "-movflags", "+faststart",
		"-pix_fmt", "yuv420p", "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2", mp4Path}
	if _, e := exec.Command(ff, args...).CombinedOutput(); e != nil {
		return gifPath, "image/gif", nil // mp4 step failed; gif still good
	}
	return mp4Path, "video/mp4", nil
}

// aggFont picks a monospace font with good box-drawing glyphs that's likely
// installed, per OS. agg falls back internally if it's missing; we also retry
// without the flag on failure.
func aggFont() string {
	switch runtime.GOOS {
	case "darwin":
		return "Menlo"
	case "windows":
		return "Consolas"
	default:
		return "DejaVu Sans Mono"
	}
}

// cmdVideo is the CLI entry; the viewer uses renderVideo directly via /video.
func cmdVideo(castPath string) error {
	out, _, err := renderVideo(castPath, "mp4")
	if err != nil {
		if err.Error() == "agg-missing" {
			fmt.Println("agentprov video needs `agg` (renders the cast frames to video — NO screen capture).")
			fmt.Println("  install:  brew install agg     ·  for .mp4 also:  brew install ffmpeg")
			return errors.New("agg not installed")
		}
		return err
	}
	fmt.Printf("  ✓ %s\n", out)
	return nil
}

func cmdViewFlows(chainPath, flowsPath string) error {
	abs, err := filepath.Abs(chainPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("chain not found: %s (record or run first)", chainPath)
	}

	// Parse agentsnitch flows if provided (a third, OS-observed evidence layer).
	var flowsJSON []byte
	if flowsPath != "" {
		flows, ferr := loadFlows(flowsPath)
		if ferr != nil {
			return fmt.Errorf("reading flows %s: %w", flowsPath, ferr)
		}
		flowsJSON, _ = json.Marshal(flows)
		fmt.Printf("agentprov: overlaying %d agentsnitch network flow(s) from %s\n", len(flows), flowsPath)
	}

	castPath := filepath.Join(filepath.Dir(abs), "session.cast")
	mux := newViewerMux(abs, castPath, flowsJSON)

	ln, err := net.Listen("tcp", "127.0.0.1:0") // loopback, OS-assigned port
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/?chain=/chain", ln.Addr().String())
	srv := &http.Server{
		Handler:           viewerGuard(mux, viewerAllowedHosts(ln.Addr().String())),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	fmt.Printf("agentprov view: %s\n", url)
	fmt.Println("serving the flight-recorder viewer — press Ctrl-C to stop.")
	go openBrowser(url)

	// serve until interrupted
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	sig := awaitInterrupt()
	select {
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	case err := <-errCh:
		return err
	}
}

// newViewerMux builds the viewer's routes. Kept separate from the server setup
// so the Host/method guard can be tested with httptest.
func newViewerMux(abs, castPath string, flowsJSON []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/flows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if flowsJSON == nil {
			w.Write([]byte("[]"))
			return
		}
		w.Write(flowsJSON)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(viewerHTML)
	})
	mux.HandleFunc("/chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		http.ServeFile(w, r, abs)
	})
	mux.HandleFunc("/asciinema-player.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(asciinemaJS)
	})
	mux.HandleFunc("/asciinema-player.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(asciinemaCSS)
	})
	// serve a .cast recording sitting next to the chain, if present.
	mux.HandleFunc("/cast", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(castPath); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, castPath)
	})
	// render the cast to a video server-side (agg/ffmpeg) and stream it back as
	// a download. POST-only + same-origin (enforced by viewerGuard) so a web page
	// cannot drive a render through DNS rebinding.
	mux.HandleFunc("/video", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("agentprov: rendering session video (agg/ffmpeg)…")
		out, ct, err := renderVideo(castPath, "mp4")
		if err != nil {
			if err.Error() == "agg-missing" {
				http.Error(w, "agg not installed — run: brew install agg (and ffmpeg for mp4). agg renders the recording frames; it does NOT capture your screen.", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "render failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", `attachment; filename="agentprov-session`+filepath.Ext(out)+`"`)
		http.ServeFile(w, r, out)
		fmt.Printf("agentprov: served %s\n", out)
	})
	return mux
}

// viewerAllowedHosts is the exact Host allowlist for the loopback viewer.
func viewerAllowedHosts(addr string) map[string]struct{} {
	hosts := map[string]struct{}{addr: {}}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		hosts["localhost:"+port] = struct{}{}
	}
	return hosts
}

// viewerGuard rejects DNS-rebinding/cross-site access to the loopback viewer.
// Browsers send the attacker's hostname in Host when a page rebinds a name to
// 127.0.0.1, so the allowlist closes that path; /video additionally requires
// POST and a same-origin (or absent) Origin.
func viewerGuard(next http.Handler, allowedHosts map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allowedHosts[r.Host]; !ok {
			http.Error(w, "forbidden: unexpected Host (viewer is loopback-only)", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/video" {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "method not allowed: /video requires POST", http.StatusMethodNotAllowed)
				return
			}
			if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
				http.Error(w, "forbidden: cross-site request", http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !viewerOriginAllowed(origin, allowedHosts) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
		} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func viewerOriginAllowed(origin string, allowedHosts map[string]struct{}) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	_, ok := allowedHosts[u.Host]
	return ok
}

func openBrowser(url string) {
	time.Sleep(250 * time.Millisecond) // let the server bind
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
