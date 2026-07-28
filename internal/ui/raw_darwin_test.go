//go:build darwin

package ui

import (
	"os"
	"syscall"
	"testing"
)

// TestRawModeRoundTrip needs a real terminal, so it skips wherever there isn't
// one (CI, `go test` under a pipe). When it does run, it is the only thing that
// checks the ioctls actually do what the picker assumes.
func TestRawModeRoundTrip(t *testing.T) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		t.Skip("no controlling terminal:", err)
	}
	defer tty.Close()

	before, err := getTermios(tty)
	if err != nil {
		t.Fatalf("reading the terminal's settings: %v", err)
	}
	restore, err := rawMode(tty)
	if err != nil {
		t.Fatalf("entering raw mode: %v", err)
	}
	during, err := getTermios(tty)
	if err != nil {
		restore()
		t.Fatalf("reading back the raw settings: %v", err)
	}
	if during.Lflag&syscall.ECHO != 0 {
		restore()
		t.Fatal("raw mode still echoes; the filter query would be typed twice")
	}
	if during.Lflag&syscall.ICANON != 0 {
		restore()
		t.Fatal("raw mode still buffers by line; a keystroke wouldn't arrive until enter")
	}
	if during.Cc[syscall.VMIN] != 1 {
		restore()
		t.Fatalf("VMIN is %d, want 1 — a read should return on the first byte", during.Cc[syscall.VMIN])
	}

	restore()
	after, err := getTermios(tty)
	if err != nil {
		t.Fatalf("reading the restored settings: %v", err)
	}
	// Compare the flags raw mode touches rather than the whole struct: Lflag
	// also carries kernel status bits (PENDIN, FLUSHO) that the tty sets on its
	// own, so an exact match is a flake waiting to happen.
	const touched = syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	if after.Lflag&touched != before.Lflag&touched {
		t.Fatalf("line discipline came back changed: before %#x, after %#x",
			before.Lflag&touched, after.Lflag&touched)
	}
	if after.Oflag&syscall.OPOST != before.Oflag&syscall.OPOST {
		t.Fatal("output post-processing wasn't restored; the shell would stop translating newlines")
	}
	if after.Cc[syscall.VMIN] != before.Cc[syscall.VMIN] || after.Cc[syscall.VTIME] != before.Cc[syscall.VTIME] {
		t.Fatal("the read timing wasn't restored")
	}
	if rows := windowRows(tty); rows <= 0 {
		t.Fatalf("a real terminal should report a height, got %d", rows)
	}
}

// The ioctls are also how the picker knows it has a terminal at all, so the
// failure has to be clean rather than a garbled screen.
func TestRawModeRefusesNonTerminals(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := rawMode(f); err == nil {
		t.Fatal("raw mode on /dev/null should fail; it is a character device but not a tty")
	}
	if got := windowRows(f); got != 0 {
		t.Fatalf("windowRows(/dev/null) = %d, want 0", got)
	}
}
