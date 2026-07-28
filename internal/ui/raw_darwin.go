//go:build darwin

package ui

import (
	"os"
	"syscall"
	"unsafe"
)

// This file is the only place in the package that talks to the kernel. It exists
// so that reading one keystroke at a time costs no dependency: taking a tty out
// of line-buffered mode is two ioctls over a struct the standard library already
// declares. macOS is the platform `awsvpn` runs on — it drives the AWS VPN
// Client, which ships nowhere else — so these are the BSD names, and every other
// platform gets the stub in raw_other.go.

// termios is the sub-struct of syscall.Termios we touch, named for readability.

// rawMode takes f out of line-buffered mode: no echo, no line editing, no
// signal-generating keys, and a read that returns the moment a key is pressed
// rather than at the newline. The returned func puts back exactly what was there
// before and must be called, or the shell is left unusable.
//
// The error doubles as the terminal check: an ioctl on anything that isn't a tty
// fails with ENOTTY, which is more honest than guessing from a file's mode bits.
func rawMode(f *os.File) (func(), error) {
	prev, err := getTermios(f)
	if err != nil {
		return nil, err
	}
	raw := *prev
	// Input: no CR/NL translation (we want the bytes as typed) and no flow
	// control, so ctrl-s doesn't freeze the picker.
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	// Output: no post-processing, which is why everything we draw ends "\r\n" —
	// the kernel is no longer adding the carriage return for us.
	raw.Oflag &^= syscall.OPOST
	// Local: no echo (we paint the query ourselves), no line assembly, and no
	// signals from the keyboard — ctrl-c arrives as a byte the picker reads as
	// "cancel", which lets it restore the terminal on its way out.
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	// Return from a read as soon as there is one byte, and never on a timer.
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 1, 0

	if err := setTermios(f, &raw); err != nil {
		return nil, err
	}
	return func() { _ = setTermios(f, prev) }, nil
}

// windowRows reports the terminal's height, or 0 when f can't say.
func windowRows(f *os.File) int {
	var ws struct{ rows, cols, xpixel, ypixel uint16 }
	if err := ioctl(f, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0
	}
	return int(ws.rows)
}

func getTermios(f *os.File) (*syscall.Termios, error) {
	var t syscall.Termios
	if err := ioctl(f, syscall.TIOCGETA, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return &t, nil
}

func setTermios(f *os.File, t *syscall.Termios) error {
	return ioctl(f, syscall.TIOCSETA, unsafe.Pointer(t))
}

// ioctl keeps arg an unsafe.Pointer up to the call itself, so the value it points
// at can't be collected or moved out from under the kernel.
func ioctl(f *os.File, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}
