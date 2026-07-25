package notify

import (
	"strings"
	"testing"
)

func TestAppleScriptStringExact(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "prod-use2", `"prod-use2"`},
		{"embedded quote", `he said "hi"`, `"he said \"hi\""`},
		{"embedded backslash", `c:\path`, `"c:\\path"`},
		{"newline becomes space", "line1\nline2", `"line1 line2"`},
		{"tab becomes space", "a\tb", `"a b"`},
		{"empty", "", `""`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appleScriptString(c.in); got != c.want {
				t.Errorf("appleScriptString(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// appleUnescape is an independent oracle: it applies AppleScript's own rules for a
// double-quoted string literal (\\ -> \, \" -> ", surrounding quotes stripped). If
// our escaper is injection-safe, feeding its output through this must yield exactly
// the sanitized input — i.e. the interpreter sees one literal string and nothing
// the caller didn't intend, no matter how hostile the input.
func appleUnescape(t *testing.T, lit string) string {
	t.Helper()
	if len(lit) < 2 || lit[0] != '"' || lit[len(lit)-1] != '"' {
		t.Fatalf("literal %q is not wrapped in quotes", lit)
	}
	body := lit[1 : len(lit)-1]
	var b strings.Builder
	esc := false
	for _, r := range body {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == '"':
			t.Fatalf("unescaped double-quote inside literal %q — injection possible", lit)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestAppleScriptStringRoundTripsSafely(t *testing.T) {
	inputs := []string{
		"prod",
		`with "quotes"`,
		`back\slash`,
		`"; do shell script "rm -rf /"; "`, // classic break-out attempt
		`end" & (system attribute "HOME") & "`,
		"controls\r\n\ttab",
	}
	for _, in := range inputs {
		lit := appleScriptString(in)
		if got := appleUnescape(t, lit); got != sanitize(in) {
			t.Errorf("round-trip of %q: interpreter would see %q, want %q", in, got, sanitize(in))
		}
	}
}

// sanitize mirrors the one non-escaping transform appleScriptString makes:
// control characters are replaced with spaces (they cannot appear in a one-line
// literal). Everything else must survive verbatim.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
}
