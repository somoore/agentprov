package main

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
func cmdView(chainPath string) error {
	abs, err := filepath.Abs(chainPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("chain not found: %s (record or run first)", chainPath)
	}

	mux := http.NewServeMux()
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
