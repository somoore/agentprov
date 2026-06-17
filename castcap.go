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
	mu         sync.Mutex
	f          *os.File
	start      time.Time
	paused     bool
	pausedAt   time.Time
	pausedTotal time.Duration // total idle time excluded from the timeline
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

// write records an output chunk as a timed cast event. While paused, output is
// dropped from the recording (the live terminal still shows it) — and paused
// time is excluded from the cast timeline so playback doesn't sit on dead air.
func (c *castWriter) write(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		return
	}
	elapsed := time.Since(c.start) - c.pausedTotal
	ev := []any{elapsed.Seconds(), "o", string(p)}
	b, _ := json.Marshal(ev)
	c.f.Write(b)
	c.f.Write([]byte("\n"))
	c.f.Sync()
}

// pause stops recording output; resume restores it and excludes the idle gap.
func (c *castWriter) pause() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused {
		c.paused = true
		c.pausedAt = time.Now()
	}
}
func (c *castWriter) resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.paused {
		c.paused = false
		c.pausedTotal += time.Since(c.pausedAt)
	}
}

func (c *castWriter) close() { c.f.Close() }

// runInPTY runs cmd attached to a PTY, mirroring the PTY's output to the user's
// real terminal AND to a .cast recording. stdin is forwarded to the PTY so the
// session stays fully interactive. Returns the agent's wait error.
//
// This is the capture that makes the recording OUR artifact: the agent runs in
// a real terminal (so its interactive TUI/colors render), and every byte it
// paints to that terminal is teed into the .cast verbatim — the literal session.
// idleTimeout is how long with no human keystroke before we PAUSE recording.
// The session keeps running; we just stop recording dead air, and mark the gap
// so the verified record shows exactly when the human went idle and returned.
const idleTimeout = 45 * time.Second

// ptyHooks lets cmdRun record idle/resume boundaries into the signed chain.
type ptyHooks struct {
	onIdle   func(idleStart time.Time)              // human went quiet (timeout fired)
	onResume func(idleStart, resume time.Time)      // human input returned
}

func runInPTY(cmd *exec.Cmd, castPath string, hooks ptyHooks) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("pty start: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

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

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// Activity-tracked stdin -> PTY. Every human keystroke resets the idle
	// timer; if it fires, we pause the cast recorder (stops dead-air padding)
	// and mark the gap; the next keystroke resumes. Session is never killed.
	activity := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				select {
				case activity <- struct{}{}:
				default:
				}
				ptmx.Write(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}()
	go watchIdle(activity, cw, hooks)

	// PTY -> (real terminal + cast). The user always sees the live session;
	// the cast only records while not paused.
	teeWriter := castTee{out: os.Stdout, cast: cw}
	_, _ = io.Copy(teeWriter, ptmx)

	return cmd.Wait()
}

// watchIdle pauses the recorder after idleTimeout with no human input, and
// resumes on the next keystroke. Boundaries are reported to the chain via hooks.
func watchIdle(activity <-chan struct{}, cw *castWriter, hooks ptyHooks) {
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	paused := false
	var idleStart time.Time
	for {
		select {
		case _, ok := <-activity:
			if !ok {
				return
			}
			if paused {
				paused = false
				cw.resume()
				if hooks.onResume != nil {
					hooks.onResume(idleStart, time.Now())
				}
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idleTimeout)
		case <-timer.C:
			if !paused {
				paused = true
				idleStart = time.Now()
				cw.pause()
				if hooks.onIdle != nil {
					hooks.onIdle(idleStart)
				}
			}
		}
	}
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
