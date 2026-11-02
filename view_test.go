package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestViewerGuardHostAllowlist is the regression for DNS rebinding: a request
// whose Host is not the loopback address (as a rebinding browser sends) must be
// refused before any evidence is served.
func TestViewerGuardHostAllowlist(t *testing.T) {
	dir := t.TempDir()
	chain := filepath.Join(dir, "chain.jsonl")
	if err := os.WriteFile(chain, []byte(`{"seq":0}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := viewerGuard(newViewerMux(chain, filepath.Join(dir, "session.cast"), nil),
		viewerAllowedHosts("127.0.0.1:12345"))

	// Attacker-controlled Host (rebinding) -> 403.
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/chain", nil)
	req.Host = "evil.example"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("foreign Host got %d, want 403", rr.Code)
	}

	// Loopback Host -> served, with no-store/nosniff.
	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345/chain", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("loopback Host got %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("missing nosniff, got %q", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("missing no-store, got %q", got)
	}
}

// TestViewerRejectsStateChangingVideoGET: /video spawns agg/ffmpeg, so a plain
// GET (e.g. a cross-site <img>) must not trigger a render.
func TestViewerRejectsStateChangingVideoGET(t *testing.T) {
	dir := t.TempDir()
	h := viewerGuard(newViewerMux(filepath.Join(dir, "chain.jsonl"), filepath.Join(dir, "session.cast"), nil),
		viewerAllowedHosts("127.0.0.1:12345"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:12345/video", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /video got %d, want 405", rr.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:12345/video", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST /video got %d, want 403", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:12345/video", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST /video got %d, want 403", rr.Code)
	}
}

func TestViewerOriginAllowed(t *testing.T) {
	hosts := viewerAllowedHosts("127.0.0.1:9999")
	for _, ok := range []string{"http://127.0.0.1:9999", "http://localhost:9999"} {
		if !viewerOriginAllowed(ok, hosts) {
			t.Errorf("origin %q should be allowed", ok)
		}
	}
	for _, bad := range []string{"https://127.0.0.1:9999", "http://evil.example", "null", ""} {
		if viewerOriginAllowed(bad, hosts) {
			t.Errorf("origin %q should be rejected", bad)
		}
	}
	if !strings.Contains(haveViewerHTML(), "Record internally consistent") {
		t.Error("viewer verdict still over-claims a verified record")
	}
}

// haveViewerHTML reads the same embedded asset the server serves.
func haveViewerHTML() string { return string(viewerHTML) }
