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
