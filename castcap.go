package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// castWriter writes an asciinema v2 .cast: a JSON header line, then one
// [elapsedSeconds, "o", data] line per output chunk. Concurrency-safe; flushes
// each event so the recording survives an abrupt exit (same discipline as the
// chain recorder). The header keeps a unix start timestamp so the relative
// event times can later be aligned to the chain's absolute UTC.
type castWriter struct {
	mu    sync.Mutex
	f     *os.File
	start time.Time
}

func newCastWriter(path string, cols, rows int, startUnix int64) (*castWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	hdr := map[string]any{
		"version": 2, "width": cols, "height": rows,
		"timestamp": startUnix,
		"env":       map[string]string{"TERM": os.Getenv("TERM"), "SHELL": os.Getenv("SHELL")},
	}
	b, _ := json.Marshal(hdr)
	f.Write(b)
	f.Write([]byte("\n"))
	return &castWriter{f: f, start: time.Now()}, nil
}

// write records an output chunk as a timed cast event.
func (c *castWriter) write(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ev := []any{time.Since(c.start).Seconds(), "o", string(p)}
	b, _ := json.Marshal(ev)
	c.f.Write(b)
	c.f.Write([]byte("\n"))
	c.f.Sync()
}

func (c *castWriter) close() { c.f.Close() }

// runInPTY runs cmd attached to a PTY, mirroring the PTY's output to the user's
// real terminal AND to a .cast recording. stdin is forwarded to the PTY so the
// session stays fully interactive. Returns the agent's wait error.
//
// This is the capture that makes the recording OUR artifact: the agent runs in
// a real terminal (so its interactive TUI/colors render), and every byte it
// paints to that terminal is teed into the .cast verbatim — the literal session.
func runInPTY(cmd *exec.Cmd, castPath string) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("pty start: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	// size the PTY to the real terminal, and keep it synced on resize.
	cols, rows := 80, 24
	if w, h, e := term.GetSize(int(os.Stdin.Fd())); e == nil {
		cols, rows = w, h
	}
	_ = pty.InheritSize(os.Stdin, ptmx)

	cw, err := newCastWriter(castPath, cols, rows, time.Now().Unix())
	if err != nil {
		return err
	}
	defer cw.close()

	// put the real terminal in raw mode so keystrokes pass through untouched;
	// restore on exit.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// stdin -> PTY (user typing into the agent)
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()

	// PTY -> (real terminal + cast). A tee: the user sees the live session,
	// the cast captures the identical bytes.
	teeWriter := castTee{out: os.Stdout, cast: cw}
	_, _ = io.Copy(teeWriter, ptmx)

	return cmd.Wait()
}

// castTee writes the same bytes to the real terminal and the cast recording.
type castTee struct {
	out  io.Writer
	cast *castWriter
}

func (t castTee) Write(p []byte) (int, error) {
	t.cast.write(p)
	return t.out.Write(p)
}
