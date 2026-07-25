package ui

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Reporter narrates a long-running command. `connect` is the only thing slow
// enough to need it: it takes minutes of wall-clock (a human signing in), and
// the raw log it used to mirror to the terminal answered "what is happening?"
// in a form written for a machine. A Reporter answers it for a person.
//
// The contract is one in-flight step at a time. Step opens it, OK closes it,
// and Note/Warn/Block interject without disturbing it.
type Reporter interface {
	// Step opens (or replaces) the in-flight step.
	Step(format string, args ...any)
	// OK closes the in-flight step as done, with its final wording.
	OK(format string, args ...any)
	// Note records an aside while the step continues.
	Note(format string, args ...any)
	// Warn records something that didn't work, while the step continues.
	Warn(format string, args ...any)
	// Block writes pre-formatted, multi-line text (the sign-in prompt).
	Block(text string)
	// Styler matches the reporter's destination, so text built for Block is
	// styled exactly like the lines around it.
	Styler() Styler
	// Stop settles the in-flight step and hands the terminal back.
	Stop()
}

// spinnerFrames animate the in-flight step.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const frameRate = 90 * time.Millisecond

const (
	escHideCursor = "\x1b[?25l"
	escShowCursor = "\x1b[?25h"
	escClearLine  = "\r\x1b[2K"
)

// Steps is the Reporter people see. On a terminal it animates a single line in
// place; anywhere else — a pipe, `--verbose` (where raw log lines are already
// streaming and a redrawing line would fight them), or NO_COLOR — it writes
// plain lines and nothing is lost.
type Steps struct {
	w    io.Writer
	s    Styler
	live bool

	mu        sync.Mutex
	msg       string // the in-flight step; "" when none
	painted   bool   // the spinner line is currently on screen (live only)
	recorded  bool   // a permanent line for msg has already been printed
	frame     int
	animating bool
	done      bool
	stopCh    chan struct{}
	sigOnce   sync.Once
}

// NewSteps returns a reporter for w, animating only when w is a terminal.
func NewSteps(w io.Writer) *Steps {
	s := For(w)
	return &Steps{w: w, s: s, live: s.Color() && IsTerminal(w)}
}

// NewStaticSteps returns a reporter that never animates, for output that shares
// the terminal with another stream.
func NewStaticSteps(w io.Writer) *Steps {
	return &Steps{w: w, s: For(w)}
}

// Step opens the in-flight step. A previous step that never got its OK is left
// on screen as a record rather than being overwritten.
func (s *Steps) Step(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eraseLocked()
	s.flushLocked()
	s.msg, s.recorded = fmt.Sprintf(format, args...), false
	s.animateLocked()
	s.paintLocked()
}

// OK closes the in-flight step as done.
func (s *Steps) OK(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eraseLocked()
	fmt.Fprintf(s.w, "  %s %s\n", s.s.Green(CheckMark), fmt.Sprintf(format, args...))
	s.msg, s.recorded = "", false
}

// Note records an aside; the in-flight step survives it.
func (s *Steps) Note(format string, args ...any) {
	s.interject(s.s.Dim(Dot), fmt.Sprintf(format, args...))
}

// Warn records a non-fatal problem; the in-flight step survives it.
func (s *Steps) Warn(format string, args ...any) {
	s.interject(s.s.Yellow(WarnMark), fmt.Sprintf(format, args...))
}

func (s *Steps) interject(mark, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eraseLocked()
	s.recordIfUnseenLocked()
	fmt.Fprintf(s.w, "  %s %s\n", mark, msg)
	s.paintLocked()
}

// Styler matches this reporter's destination.
func (s *Steps) Styler() Styler { return s.s }

// Block writes pre-formatted text, keeping the in-flight step below it.
func (s *Steps) Block(text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eraseLocked()
	s.recordIfUnseenLocked()
	fmt.Fprint(s.w, text)
	s.paintLocked()
}

// Stop settles the in-flight step. A step still open when the command ends
// (because it failed) is left on screen as a record of how far we got, so the
// error that follows has context.
func (s *Steps) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eraseLocked()
	s.flushLocked()
	s.msg, s.done = "", true
	if s.stopCh != nil {
		close(s.stopCh)
		s.stopCh, s.animating = nil, false
		fmt.Fprint(s.w, escShowCursor)
	}
}

// animateLocked starts the repaint loop on the first live step.
func (s *Steps) animateLocked() {
	if !s.live || s.animating || s.done {
		return
	}
	s.animating = true
	s.stopCh = make(chan struct{})
	fmt.Fprint(s.w, escHideCursor)
	s.restoreCursorOnSignal()
	go s.loop(s.stopCh)
}

func (s *Steps) loop(stop <-chan struct{}) {
	t := time.NewTicker(frameRate)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.mu.Lock()
			s.frame++
			s.paintLocked()
			s.mu.Unlock()
		}
	}
}

// paintLocked draws the in-flight step in place (live only).
func (s *Steps) paintLocked() {
	if !s.live || s.msg == "" || s.done {
		return
	}
	fmt.Fprintf(s.w, "%s  %s %s", escClearLine, s.s.Cyan(spinnerFrames[s.frame%len(spinnerFrames)]), s.msg)
	s.painted = true
}

// eraseLocked removes the animated line so something permanent can take its place.
func (s *Steps) eraseLocked() {
	if s.painted {
		fmt.Fprint(s.w, escClearLine)
		s.painted = false
	}
}

// recordIfUnseenLocked commits the in-flight step to a permanent line only when
// nothing else is showing it. On an animating terminal the step is repainted
// below whatever we interject, so recording it too would say it twice.
func (s *Steps) recordIfUnseenLocked() {
	if s.live && !s.done {
		return
	}
	s.flushLocked()
}

// flushLocked commits the in-flight step to a permanent line. Used when output
// would otherwise scroll past it unrecorded: an interjection on a
// non-animating terminal, or a step that never got its OK.
func (s *Steps) flushLocked() {
	if s.msg == "" || s.recorded {
		return
	}
	fmt.Fprintf(s.w, "  %s %s\n", s.s.Dim(Dot), s.msg)
	s.recorded = true
}

// restoreCursorOnSignal makes Ctrl-C give the cursor back. Without it, a
// connect interrupted mid-spinner leaves the user's shell with an invisible
// cursor. We restore, then re-raise with the default handler so the interrupt
// still does exactly what it did before.
func (s *Steps) restoreCursorOnSignal() {
	s.sigOnce.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig, ok := <-ch
			if !ok {
				return
			}
			s.Stop()
			signal.Stop(ch)
			if sg, ok := sig.(syscall.Signal); ok {
				signal.Reset(sg)
				_ = syscall.Kill(os.Getpid(), sg)
			}
		}()
	})
}

// Discard returns a Reporter that says nothing — the default when a caller
// (a test, the launchd-run supervisor) has no one to narrate to.
func Discard() Reporter { return discard{} }

type discard struct{}

func (discard) Step(string, ...any) {}
func (discard) OK(string, ...any)   {}
func (discard) Note(string, ...any) {}
func (discard) Warn(string, ...any) {}
func (discard) Block(string)        {}
func (discard) Styler() Styler      { return Plain() }
func (discard) Stop()               {}
