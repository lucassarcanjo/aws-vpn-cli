//go:build !darwin

package ui

import (
	"errors"
	"os"
)

// `awsvpn` is a macOS tool, but the package still has to compile elsewhere — the
// vulnerability scan in CI runs on Linux. Rather than port the termios calls to
// platforms nothing here supports, this is the honest answer: no raw mode, so
// Select declines and its caller falls back to the typed prompt.

func rawMode(*os.File) (func(), error) {
	return nil, errors.New("raw terminal mode is implemented for macOS only")
}

func windowRows(*os.File) int { return 0 }
