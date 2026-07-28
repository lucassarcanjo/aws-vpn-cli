package ui

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

var pickList = []Choice{
	{Label: "dev    ", Note: "us-east-2"},
	{Label: "prod   ", Note: "us-east-2"},
	{Label: "staging", Note: "eu-west-1"},
	{Label: "uat    ", Note: "us-east-2"},
}

// pick runs the picker over a keystroke script, off-terminal, and returns what
// was chosen plus everything that was drawn.
func pick(t *testing.T, keys string) (int, string, error) {
	t.Helper()
	var buf bytes.Buffer
	i, err := newSelector(&buf, "Which profile?", pickList).run(strings.NewReader(keys))
	return i, buf.String(), err
}

func TestSelectMovesAndPicks(t *testing.T) {
	neutralEnv(t)
	for _, tc := range []struct {
		name string
		keys string
		want int
	}{
		{"enter takes the first row", "\r", 0},
		{"down twice", "\x1b[B\x1b[B\r", 2},
		{"down then up", "\x1b[B\x1b[A\r", 0},
		{"up from the top wraps to the bottom", "\x1b[A\r", 3},
		{"down from the bottom wraps to the top", "\x1b[B\x1b[B\x1b[B\x1b[B\r", 0},
		{"ctrl-n and ctrl-p move too", "\x0e\x0e\x10\r", 1},
		{"application-mode arrows", "\x1bOB\r", 1},
		{"newline counts as enter", "\x1b[B\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, out, err := pick(t, tc.keys)
			if err != nil {
				t.Fatalf("run(%q): %v", tc.keys, err)
			}
			if got != tc.want {
				t.Fatalf("run(%q) = %d, want %d\n%s", tc.keys, got, tc.want, out)
			}
		})
	}
}

func TestSelectFiltersAsYouType(t *testing.T) {
	neutralEnv(t)
	for _, tc := range []struct {
		name string
		keys string
		want int
	}{
		{"a name typed in full", "prod\r", 1},
		{"a prefix is enough", "st\r", 2},
		{"case is ignored", "UAT\r", 3},
		{"gaps are allowed, fzf-style", "pd\r", 1},
		{"a trailing letter still matches the padded label", "uat\r", 3},
		{"arrows move within the matches", "a\x1b[B\r", 3},
		{"backspace widens the search again", "prodx\x7f\r", 1},
		{"ctrl-u starts over", "prod\x15uat\r", 3},
		{"one match still needs enter", "sta\r", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, out, err := pick(t, tc.keys)
			if err != nil {
				t.Fatalf("run(%q): %v", tc.keys, err)
			}
			if got != tc.want {
				t.Fatalf("run(%q) = %d, want %d\n%s", tc.keys, got, tc.want, out)
			}
		})
	}
}

func TestSelectEnterOnNoMatchDoesNothing(t *testing.T) {
	neutralEnv(t)
	// The dangerous failure here would be enter falling through to a row nobody
	// asked for, so a dead-end query must leave the picker waiting.
	got, out, err := pick(t, "zzz\r\x7f\x7f\x7f\x1b[B\r")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Fatalf("got %d, want 1 (the row picked after backing out of the dead end)\n%s", got, out)
	}
	if !strings.Contains(out, noMatch) {
		t.Fatalf("a query matching nothing should say so:\n%s", out)
	}
}

func TestSelectCancels(t *testing.T) {
	neutralEnv(t)
	for _, keys := range []string{"\x1b", "\x03", "\x04", "prod\x1b"} {
		_, out, err := pick(t, keys)
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("keys %q: got %v, want ErrCancelled\n%s", keys, err, out)
		}
	}
}

func TestSelectExhaustedInputIsAnError(t *testing.T) {
	neutralEnv(t)
	// No enter, no cancel: stdin ended under the picker, which is a broken
	// session rather than a choice — and must not read as "picked the first one".
	_, out, err := pick(t, "\x1b[B")
	if err == nil || errors.Is(err, ErrCancelled) {
		t.Fatalf("closed input should fail loudly, got %v\n%s", err, out)
	}
}

func TestSelectRendersEveryChoiceAndTheHint(t *testing.T) {
	neutralEnv(t)
	_, out, err := pick(t, "\r")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Which profile?", "dev", "prod", "staging", "uat", "us-east-2", filterPlaceholder, selectHint} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q missing from the picker:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "\r\n") {
		t.Fatal("raw mode needs carriage returns; lines would stair-step without them")
	}
}

func TestSelectShowsWhatWasTyped(t *testing.T) {
	neutralEnv(t)
	_, out, err := pick(t, "pro\r")
	if err != nil {
		t.Fatal(err)
	}
	// The query is echoed by us, not by the terminal: raw mode turned the local
	// echo off, so a filter that isn't painted is a filter nobody can see.
	if !strings.Contains(out, filterLabel+"  pro") {
		t.Fatalf("the typed query never reached the screen:\n%s", out)
	}
}

// live returns a selector that draws as if the buffer were a terminal, which is
// what makes the cursor arithmetic observable in a test.
func live(out *bytes.Buffer) *selector {
	p := newSelector(out, "Which profile?", pickList)
	p.live = true
	return p
}

func TestSelectRepaintsInPlace(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	if _, err := live(&buf).run(strings.NewReader("\x1b[B\r")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// The frame is the filter line, four rows and the hint, so each rewind walks
	// six lines: once to repaint after the arrow key, then twice to finish —
	// back up over the frame to wipe it, and back up again to write the choice
	// where it stood.
	if got, want := strings.Count(out, "\x1b[6A"), 3; got != want {
		t.Fatalf("rewound %d times, want %d:\n%q", got, want, out)
	}
	if !strings.HasPrefix(out, "\r\n") || !strings.Contains(out, escHideCursor) || !strings.HasSuffix(out, escShowCursor) {
		t.Fatalf("the cursor should be hidden for the picker and handed back after:\n%q", out)
	}
}

func TestSelectFrameHeightSurvivesFiltering(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	p := live(&buf)
	if _, err := p.run(strings.NewReader("sta")); err == nil {
		t.Fatal("expected the closed-input error")
	}
	// A shorter list must not shorten the frame, or the next rewind lands in the
	// wrong place and the picker smears itself across the scrollback.
	frames := strings.Split(buf.String(), "\x1b[6A")
	if len(frames) != 4 { // the first paint plus one per typed rune
		t.Fatalf("expected four fixed-height frames, got %d:\n%q", len(frames), buf.String())
	}
	for i, f := range frames[1:] {
		if got := strings.Count(f, "\r\n"); got != p.frameHeight() {
			t.Fatalf("frame %d is %d lines, want %d:\n%q", i+1, got, p.frameHeight(), f)
		}
	}
}

func TestSelectLeavesOnlyTheChoiceBehind(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	if _, err := live(&buf).run(strings.NewReader("uat\r")); err != nil {
		t.Fatal(err)
	}
	final := lastFrame(buf.String())
	if strings.Contains(final, selectHint) || strings.Contains(final, filterLabel) || strings.Contains(final, "prod") {
		t.Fatalf("the picker left its machinery on screen:\n%q", final)
	}
	if !strings.Contains(final, "uat") {
		t.Fatalf("the chosen profile should stay as the record of the choice:\n%q", final)
	}
}

func TestSelectCancelLeavesNothingBehind(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	if _, err := live(&buf).run(strings.NewReader("uat\x1b")); !errors.Is(err, ErrCancelled) {
		t.Fatalf("want ErrCancelled, got %v", err)
	}
	final := lastFrame(buf.String())
	for _, gone := range []string{"uat", "prod", selectHint, filterLabel} {
		if strings.Contains(final, gone) {
			t.Fatalf("a cancelled picker should wipe its frame, found %q in:\n%q", gone, final)
		}
	}
}

// lastFrame is what is left on screen: everything written after the final rewind.
func lastFrame(out string) string {
	return out[strings.LastIndex(out, "\x1b[6A"):]
}

// NO_COLOR asks for plain text, not for a copy of the list per keystroke: the
// marker stays, the colour goes, the redraw stays.
func TestSelectRedrawsWithoutColour(t *testing.T) {
	neutralEnv(t)
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	if _, err := live(&buf).run(strings.NewReader("\x1b[B\r")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[36m") || strings.Contains(out, "\x1b[1m") {
		t.Fatalf("NO_COLOR still got colour:\n%q", out)
	}
	if !strings.Contains(out, "\x1b[6A") || !strings.Contains(out, escClearLine) {
		t.Fatalf("NO_COLOR shouldn't cost the in-place redraw:\n%q", out)
	}
	if !strings.Contains(out, Arrow) {
		t.Fatalf("the selected row lost its marker:\n%q", out)
	}
}

func TestMatchesQuery(t *testing.T) {
	for _, tc := range []struct {
		s, query string
		want     bool
	}{
		{"prod us-east-2", "", true},
		{"prod us-east-2", "prod", true},
		{"prod us-east-2", "PROD", true},
		{"prod us-east-2", "pd", true},
		{"prod us-east-2", "east", true},
		{"prod us-east-2", "dp", false}, // order matters, unlike a bag of letters
		{"prod us-east-2", "prodx", false},
		{"prod us-east-2", "prood", false}, // a repeated rune needs a second one to match
		{"café-1", "É", true},
	} {
		if got := matchesQuery(tc.s, tc.query); got != tc.want {
			t.Errorf("matchesQuery(%q, %q) = %v, want %v", tc.s, tc.query, got, tc.want)
		}
	}
}

func TestSelectNeedsChoices(t *testing.T) {
	neutralEnv(t)
	if _, err := Select(nil, nil, "Which profile?", nil); err == nil {
		t.Fatal("an empty list should be rejected before any terminal work")
	}
}

func TestSelectDeclinesWithoutATerminal(t *testing.T) {
	neutralEnv(t)
	// A file: not a character device, so it never gets as far as the ioctls.
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Select(f, f, "Which profile?", pickList); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("a file should send the caller to the typed prompt, got %v", err)
	}
	// /dev/null: a character device that looks enough like a terminal to get
	// past the cheap check, and is caught by raw mode failing.
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if _, err := Select(null, null, "Which profile?", pickList); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("/dev/null should send the caller to the typed prompt, got %v", err)
	}
}
