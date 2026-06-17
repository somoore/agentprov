package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	dir := filepath.Join(os.TempDir(), "agentprov-fonts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	reg := filepath.Join(dir, "JetBrainsMono-Regular.ttf")
	bold := filepath.Join(dir, "JetBrainsMono-Bold.ttf")
	if _, err := os.Stat(reg); err != nil {
		if os.WriteFile(reg, fontRegular, 0o644) != nil {
			return ""
		}
	}
	if _, err := os.Stat(bold); err != nil {
		_ = os.WriteFile(bold, fontBold, 0o644)
	}
	return dir
}

// cmdDemo is the zero-install proof: write the bundled sample transcript, record
// it to a chain, verify it clean, then tell the user the one command that breaks
// it. Works with no Claude/Codex install and no transcript of their own.
func cmdDemo() error {
	const sample = "agentprov-sample.jsonl"
	if err := os.WriteFile(sample, sampleTranscript, 0o600); err != nil {
		return err
	}
	fmt.Print("agentprov demo — a tamper-evident record of a (sample) agent run.\n\n")
	fmt.Printf("1. recording the bundled sample run (%s) ...\n", sample)
	if err := cmdRecord(sample); err != nil {
		return err
	}
	fmt.Println("\n2. verifying the record:")
	if err := cmdVerify("chain.jsonl"); err != nil {
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
// The viewer is a pure renderer: it recomputes the same hash chain the CLI does,
// so what you see in the browser is the real verification.
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
			tmp := filepath.Join(os.TempDir(), "agentprov-render-"+base+".cast")
			if os.WriteFile(tmp, []byte(cleaned), 0o600) == nil {
				renderSrc = tmp
				defer os.Remove(tmp)
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
	castPath := filepath.Join(filepath.Dir(abs), "session.cast")
	mux.HandleFunc("/cast", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(castPath); err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, castPath)
	})
	// render the cast to a video server-side (agg/ffmpeg) and stream it back as
	// a download — so the user clicks a button, no command, no screen capture.
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

	ln, err := net.Listen("tcp", "127.0.0.1:0") // loopback, OS-assigned port
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/?chain=/chain", ln.Addr().String())
	srv := &http.Server{Handler: mux}

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
