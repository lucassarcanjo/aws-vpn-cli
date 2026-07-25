// Package fixture serves the real management transcript the spike captured, so
// every suite that depends on the handshake contract reads the same bytes.
//
// This package is imported ONLY from _test.go files. Nothing reachable from main
// refers to it, so it is never linked into the shipped binary — it is test data
// with just enough code to parse itself, not part of the tool's trust surface.
package fixture

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed handshake.txt
var handshake string

// Transcript is the named management lines from the captured handshake. Keys are
// the names in handshake.txt (hold0, need, challenge, …).
type Transcript map[string]string

// Line returns the named line, panicking if it is absent — a missing fixture is
// a broken test binary, not a runtime condition worth threading an error for.
func (t Transcript) Line(name string) string {
	l, ok := t[name]
	if !ok {
		panic(fmt.Sprintf("fixture: no line named %q in handshake.txt", name))
	}
	return l
}

// Handshake parses the embedded transcript.
func Handshake() Transcript {
	t := Transcript{}
	for ln := range strings.SplitSeq(handshake, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if name, line, ok := strings.Cut(ln, " "); ok {
			t[name] = line
		}
	}
	return t
}
