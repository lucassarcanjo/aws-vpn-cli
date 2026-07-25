// Package ui renders everything a person sees. It is deliberately tiny and
// dependency-free: ANSI attributes when the destination is a terminal that wants
// colour, and plain text everywhere else — a pipe, a file, CI, the launchd-run
// supervisor, or a terminal whose owner set NO_COLOR. Styling decisions live
// here so the command layer can describe *what* it is saying rather than how it
// looks, and so "does this deserve colour?" is answered in exactly one place.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Glyphs used across the command surface. macOS terminals are UTF-8, so these
// are safe to print unconditionally.
const (
	// CheckMark marks a finished action.
	CheckMark = "✔"
	// CrossMark marks a failure.
	CrossMark = "✖"
	// WarnMark marks something that didn't work but isn't fatal.
	WarnMark = "!"
	// Bullet is a filled state dot (connected).
	Bullet = "●"
	// Ring is a hollow state dot (disconnected).
	Ring = "○"
	// Dot prefixes an informational line.
	Dot = "·"
	// Arrow is the interactive prompt marker.
	Arrow = "→"
)

const escReset = "\x1b[0m"

// Styler applies ANSI attributes, or returns text untouched when the
// destination shouldn't get colour. The zero value is a plain styler, so a
// forgotten constructor degrades to no colour rather than to garbage.
type Styler struct{ color bool }

// For returns a Styler suited to w: colour only for a terminal that wants it.
func For(w io.Writer) Styler { return Styler{color: wantsColor(w)} }

// Plain returns a Styler that never emits escapes — for tests and for text
// destined for a log file.
func Plain() Styler { return Styler{} }

// Color reports whether this Styler emits escapes.
func (s Styler) Color() bool { return s.color }

func (s Styler) wrap(code, v string) string {
	if !s.color || v == "" {
		return v
	}
	return code + v + escReset
}

// Bold renders v with increased intensity.
func (s Styler) Bold(v string) string { return s.wrap("\x1b[1m", v) }

// Dim renders v as secondary information.
func (s Styler) Dim(v string) string { return s.wrap("\x1b[2m", v) }

// Green renders v as success.
func (s Styler) Green(v string) string { return s.wrap("\x1b[32m", v) }

// Red renders v as failure.
func (s Styler) Red(v string) string { return s.wrap("\x1b[31m", v) }

// Yellow renders v as a warning.
func (s Styler) Yellow(v string) string { return s.wrap("\x1b[33m", v) }

// Cyan renders v as an in-progress accent.
func (s Styler) Cyan(v string) string { return s.wrap("\x1b[36m", v) }

// wantsColor decides whether w should receive escapes. NO_COLOR (any value)
// always wins; CLICOLOR_FORCE overrides the terminal check so piped demos and
// screenshots can keep colour.
func wantsColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return IsTerminal(w)
}

// IsTerminal reports whether w is a character device — close enough to "a human
// is watching" without pulling in a terminal library. It costs us only that
// output redirected to /dev/null looks like a terminal, which no one sees.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// Field is one labelled value in a summary block.
type Field struct{ Label, Value string }

// Fields writes an indented, column-aligned block of labelled values. Empty
// values are skipped, so a caller can hand over every field it might have and
// let the block shrink to what's actually known. Labels are padded before they
// are styled — escape sequences have width on the wire but not on screen.
func (s Styler) Fields(w io.Writer, fields ...Field) {
	width := 0
	for _, f := range fields {
		if f.Value != "" && len(f.Label) > width {
			width = len(f.Label)
		}
	}
	for _, f := range fields {
		if f.Value == "" {
			continue
		}
		label := f.Label + strings.Repeat(" ", width-len(f.Label))
		fmt.Fprintf(w, "  %s  %s\n", s.Dim(label), f.Value)
	}
}

// Done reports a completed action.
func Done(w io.Writer, format string, args ...any) {
	s := For(w)
	fmt.Fprintf(w, "%s %s\n", s.Green(CheckMark), fmt.Sprintf(format, args...))
}

// Warn reports something that didn't work but doesn't stop the command.
func Warn(w io.Writer, format string, args ...any) {
	s := For(w)
	fmt.Fprintf(w, "%s %s\n", s.Yellow(WarnMark), fmt.Sprintf(format, args...))
}

// Hint writes an indented, dimmed line: the "what next" under a result.
func Hint(w io.Writer, format string, args ...any) {
	s := For(w)
	fmt.Fprintf(w, "  %s\n", s.Dim(fmt.Sprintf(format, args...)))
}

// Fail prints err as the command's last word: the first line beside a red cross,
// and any remaining lines — the actionable part of our multi-line errors — kept
// as indented, dimmed guidance.
func Fail(w io.Writer, err error) {
	s := For(w)
	lines := strings.Split(strings.TrimRight(err.Error(), "\n"), "\n")
	fmt.Fprintf(w, "%s %s\n", s.Red(CrossMark), lines[0])
	for _, line := range lines[1:] {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			fmt.Fprintf(w, "  %s\n", s.Dim(trimmed))
		} else {
			fmt.Fprintln(w)
		}
	}
}

// Duration renders d the way a person reads a clock rather than the way Go
// prints it: "45s", "12m 04s", "3h 07m" — and a bare "3m" for a round number,
// which is what a timeout wants to say.
func Duration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int(d/time.Minute) % 60
	s := int(d/time.Second) % 60
	switch {
	case h > 0 && m == 0:
		return fmt.Sprintf("%dh", h)
	case h > 0:
		return fmt.Sprintf("%dh %02dm", h, m)
	case m > 0 && s == 0:
		return fmt.Sprintf("%dm", m)
	case m > 0:
		return fmt.Sprintf("%dm %02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
