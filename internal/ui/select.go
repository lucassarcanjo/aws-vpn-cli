package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// Choice is one row of an interactive list. Label is the thing being chosen and
// the only text the filter searches; Note is the dimmed context beside it, which
// tends to read the same on every row and would match everything. Callers pad
// Label themselves when they want a column, because only they know the whole set.
type Choice struct{ Label, Note string }

// ErrNoTerminal says the caller should fall back to a typed prompt: stdin or the
// output isn't a terminal (a pipe, a script, CI), so there are no keystrokes to
// read and nothing to redraw.
var ErrNoTerminal = errors.New("not an interactive terminal")

// ErrCancelled reports that the person aborted the picker.
var ErrCancelled = errors.New("selection cancelled")

// selectHint is the one line that teaches the whole interaction.
const selectHint = "type to filter " + Dot + " ↑↓ move " + Dot + " enter select " + Dot + " esc cancel"

const (
	filterLabel       = "filter"
	filterPlaceholder = "type to narrow the list"
	noMatch           = "no match"
)

// Select draws choices on out and lets the person narrow and pick: typing
// filters the list the forgiving way fzf does ("pd" finds "prod"), the arrow
// keys move the highlight, enter returns the index of the highlighted row, and
// esc / ctrl-c cancel.
//
// It puts in into raw mode for the duration — that is what turns "type a number,
// press enter" into "press a key" — and restores it on every exit path,
// cancellation and an interrupt included.
func Select(in, out *os.File, title string, choices []Choice) (int, error) {
	if len(choices) == 0 {
		return 0, errors.New("nothing to choose from")
	}
	if !IsTerminal(out) {
		return 0, ErrNoTerminal
	}
	// Redrawing in place assumes the frame stays put. A frame taller than the
	// window scrolls instead, and every rewind after that lands on the wrong
	// line — so hand a list that big to the typed prompt, which just prints.
	// A window that reports no height at all (a pty nobody sized) tells us
	// nothing, so it isn't taken as a reason to give up on the picker.
	if rows := windowRows(out); rows > 0 && len(choices)+6 > rows {
		return 0, ErrNoTerminal
	}
	// Raw mode doubles as the terminal check for in: it fails on anything that
	// isn't a tty, which is exactly the case the typed prompt exists for.
	restore, err := rawMode(in)
	if err != nil {
		return 0, ErrNoTerminal
	}
	defer restore()

	// The keyboard can no longer raise SIGINT — ctrl-c arrives as a byte the
	// picker reads — but a signal from elsewhere would otherwise leave the shell
	// in raw mode with no cursor, which is a terminal nobody can use.
	p := newSelector(out, title, choices)
	stopSignals := onSignal(func() {
		p.showCursor()
		restore()
	})
	defer stopSignals()
	return p.run(in)
}

// onSignal restores the terminal if the process is asked to quit, then lets the
// signal do what it always did. The returned func unregisters the handler; it
// follows the pattern Steps uses for the spinner's cursor.
func onSignal(restore func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig, ok := <-ch
		if !ok {
			return
		}
		restore()
		signal.Stop(ch)
		if sg, ok := sig.(syscall.Signal); ok {
			signal.Reset(sg)
			_ = syscall.Kill(os.Getpid(), sg)
		}
	}()
	return func() { signal.Stop(ch); close(ch) }
}

// selector holds one picker's state: where it draws, what it draws, what has
// been typed, and whether a frame is already on screen (only later frames rewind
// over the earlier one).
//
// live is about cursor movement rather than colour, so it follows "is this a
// terminal?" and not the Styler: NO_COLOR asks for plain text, not for a fresh
// copy of the list on every keystroke.
type selector struct {
	out     io.Writer
	s       Styler
	live    bool
	title   string
	choices []Choice

	query   string
	matches []int // indices into choices, in list order, that the query keeps
	sel     int   // position within matches
	drawn   bool
}

func newSelector(out io.Writer, title string, choices []Choice) *selector {
	p := &selector{out: out, s: For(out), live: IsTerminal(out), title: title, choices: choices}
	p.filter()
	return p
}

// run paints, reads a key, repaints. It is Select without the terminal plumbing,
// so the keystroke handling and what lands on screen can be tested with a string
// and a buffer.
//
// Raw mode turns off the kernel's newline translation, so every line ends
// "\r\n" rather than "\n": the carriage return is what brings the cursor back to
// column one.
func (p *selector) run(in io.Reader) (int, error) {
	fmt.Fprintf(p.out, "\r\n  %s\r\n\r\n", p.s.Bold(p.title))
	p.hideCursor()
	defer p.showCursor()

	p.paint()
	keys := bufio.NewReader(in)
	for {
		k, err := readKey(keys)
		if err != nil {
			// stdin closing mid-picker is a broken session, not a choice.
			return 0, fmt.Errorf("reading selection: %w", err)
		}
		switch k.kind {
		case keyUp:
			p.move(-1)
		case keyDown:
			p.move(1)
		case keyRune:
			p.query += string(k.r)
			p.filter()
		case keyBackspace:
			p.query = trimLastRune(p.query)
			p.filter()
		case keyClear:
			p.query = ""
			p.filter()
		case keyEnter:
			if len(p.matches) == 0 {
				continue // nothing is highlighted, so enter has nothing to mean
			}
			i := p.matches[p.sel]
			p.finish(i)
			return i, nil
		case keyCancel:
			p.finish(-1)
			return 0, ErrCancelled
		default:
			continue // an unmapped key shouldn't cost a repaint
		}
		p.paint()
	}
}

// move walks the highlight through the matches, wrapping at both ends: down from
// the last row lands on the first, which is quicker than travelling back.
func (p *selector) move(by int) {
	if len(p.matches) == 0 {
		return
	}
	p.sel = (p.sel + by + len(p.matches)) % len(p.matches)
}

// filter recomputes which rows the query keeps and puts the highlight back on
// the first of them, because the row it was on may not have survived.
func (p *selector) filter() {
	p.matches = p.matches[:0]
	for i, c := range p.choices {
		if matchesQuery(c.Label, p.query) {
			p.matches = append(p.matches, i)
		}
	}
	p.sel = 0
}

// paint draws the frame — the filter line, one row per choice, the key hint —
// rewinding the cursor first over the frame it drew last time so each pass
// overwrites the previous one in place.
//
// The frame is always the same height whatever the query keeps: matches are
// collected at the top and the rows they no longer fill are blanked. A frame
// that never changes height is a frame that can be redrawn with one cursor
// rewind and no leftovers.
//
// Off a terminal there is no cursor to move, so the first pass simply appends
// and later ones are the caller's problem — nothing there is reading keystrokes.
func (p *selector) paint() {
	var b strings.Builder
	p.rewind(&b)
	fmt.Fprintf(&b, "%s  %s  %s\r\n", p.clear(), p.s.Dim(filterLabel), p.filterValue())
	for row := range p.choices {
		switch {
		case row < len(p.matches):
			c := p.choices[p.matches[row]]
			marker, label := " ", c.Label
			if row == p.sel {
				marker, label = p.s.Cyan(Arrow), p.s.Bold(c.Label)
			}
			fmt.Fprintf(&b, "%s  %s  %s  %s\r\n", p.clear(), marker, label, p.s.Dim(c.Note))
		case row == 0:
			fmt.Fprintf(&b, "%s     %s\r\n", p.clear(), p.s.Dim(noMatch))
		default:
			fmt.Fprintf(&b, "%s\r\n", p.clear())
		}
	}
	fmt.Fprintf(&b, "%s  %s\r\n", p.clear(), p.s.Dim(selectHint))
	io.WriteString(p.out, b.String())
	p.drawn = true
}

// finish wipes the frame and leaves the chosen row in its place, so what stays
// on screen is the decision rather than the machinery that made it. i < 0 means
// nothing was chosen, and the frame goes without a replacement.
func (p *selector) finish(i int) {
	var b strings.Builder
	if p.live {
		p.rewind(&b)
		for range p.frameHeight() {
			fmt.Fprintf(&b, "%s\r\n", p.clear())
		}
		fmt.Fprintf(&b, "\x1b[%dA", p.frameHeight())
	}
	if i >= 0 {
		fmt.Fprintf(&b, "  %s  %s  %s\r\n", p.s.Cyan(Arrow), p.s.Bold(p.choices[i].Label), p.s.Dim(p.choices[i].Note))
	}
	io.WriteString(p.out, b.String())
}

// frameHeight is the filter line, every choice row, and the hint.
func (p *selector) frameHeight() int { return len(p.choices) + 2 }

// rewind moves the cursor back to the top of the frame already on screen.
func (p *selector) rewind(b *strings.Builder) {
	if p.live && p.drawn {
		fmt.Fprintf(b, "\x1b[%dA", p.frameHeight())
	}
}

func (p *selector) filterValue() string {
	if p.query == "" {
		return p.s.Dim(filterPlaceholder)
	}
	return p.query
}

func (p *selector) clear() string {
	if !p.live {
		return ""
	}
	return escClearLine
}

// The cursor is ours while the picker owns the screen: it would otherwise sit at
// the end of whichever line was drawn last, blinking somewhere meaningless.
func (p *selector) hideCursor() { p.cursor(escHideCursor) }
func (p *selector) showCursor() { p.cursor(escShowCursor) }

func (p *selector) cursor(esc string) {
	if p.live {
		fmt.Fprint(p.out, esc)
	}
}

// matchesQuery reports whether every rune of query appears in s in order,
// ignoring case — the forgiving rule fzf made everyone expect, where "pd" finds
// "prod" and a typo-free prefix isn't required.
func matchesQuery(s, query string) bool {
	if query == "" {
		return true
	}
	rest := strings.ToLower(s)
	for _, r := range strings.ToLower(query) {
		i := strings.IndexRune(rest, r)
		if i < 0 {
			return false
		}
		rest = rest[i+len(string(r)):]
	}
	return true
}

func trimLastRune(s string) string {
	rs := []rune(s)
	if len(rs) == 0 {
		return s
	}
	return string(rs[:len(rs)-1])
}

// key is one decoded keystroke: an intent, plus the rune when it was typed text.
type key struct {
	kind keyKind
	r    rune
}

type keyKind int

const (
	keyOther keyKind = iota
	keyUp
	keyDown
	keyEnter
	keyRune
	keyBackspace
	keyClear
	keyCancel
)

// readKey decodes a single keystroke. Anything printable is text for the filter,
// which leaves the movement and exit keys to the control bytes and to the escape
// sequences the arrow keys send ("\x1b[A"). A bare escape means cancel; it is
// told apart from an arrow key by whether more bytes arrived in the same read,
// which holds for a sequence and not for a finger on esc.
func readKey(r *bufio.Reader) (key, error) {
	c, _, err := r.ReadRune()
	if err != nil {
		return key{}, err
	}
	switch c {
	case '\r', '\n':
		return key{kind: keyEnter}, nil
	case 0x03, 0x04: // ctrl-c, ctrl-d
		return key{kind: keyCancel}, nil
	case 0x7f, 0x08: // delete, backspace
		return key{kind: keyBackspace}, nil
	case 0x15, 0x17: // ctrl-u, ctrl-w — one word is the whole query here
		return key{kind: keyClear}, nil
	case 0x10: // ctrl-p
		return key{kind: keyUp}, nil
	case 0x0e: // ctrl-n
		return key{kind: keyDown}, nil
	case 0x1b:
		return readEscape(r)
	}
	if unicode.IsPrint(c) && c != utf8.RuneError {
		return key{kind: keyRune, r: c}, nil
	}
	return key{kind: keyOther}, nil
}

// readEscape decodes what follows an escape byte: an arrow key, some other
// sequence we ignore, or nothing at all — a bare esc, which cancels.
func readEscape(r *bufio.Reader) (key, error) {
	if r.Buffered() == 0 {
		return key{kind: keyCancel}, nil
	}
	intro, _, err := r.ReadRune()
	if err != nil {
		return key{}, err
	}
	if intro != '[' && intro != 'O' {
		return key{kind: keyOther}, nil
	}
	final, _, err := r.ReadRune()
	if err != nil {
		return key{}, err
	}
	switch final {
	case 'A':
		return key{kind: keyUp}, nil
	case 'B':
		return key{kind: keyDown}, nil
	}
	return key{kind: keyOther}, nil
}
