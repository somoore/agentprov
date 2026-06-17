package main

import (
	"testing"
	"unicode/utf8"
)

// TestUTF8BoundarySplit verifies that a multi-byte UTF-8 stream split at every
// byte boundary reassembles to valid UTF-8 via completeUTF8Prefix — i.e. PTY
// reads landing mid-character never corrupt the recording with U+FFFD.
func TestUTF8BoundarySplit(t *testing.T) {
	full := []byte("a─b✻c✳─✶")
	for split := 1; split < len(full); split++ {
		var out, pending []byte
		feed := func(p []byte) {
			if len(pending) > 0 {
				p = append(pending, p...)
				pending = nil
			}
			g := completeUTF8Prefix(p)
			if g < len(p) {
				pending = append([]byte{}, p[g:]...)
				p = p[:g]
			}
			out = append(out, p...)
		}
		feed(full[:split])
		feed(full[split:])
		if string(out) != string(full) || !utf8.Valid(out) {
			t.Fatalf("split=%d: got %q valid=%v", split, out, utf8.Valid(out))
		}
	}
}
