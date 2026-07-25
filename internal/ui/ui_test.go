package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// neutralEnv removes any colour opinion the developer's shell may hold, so the
// tests below measure the code and not the environment.
func neutralEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("TERM", "xterm-256color")
}

func TestNonTerminalGetsNoEscapes(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	s := For(&buf)
	if s.Color() {
		t.Fatal("a plain buffer is not a terminal; colour should be off")
	}
	if got := s.Bold(s.Green("dev")); got != "dev" {
		t.Fatalf("styling a non-terminal changed the text: %q", got)
	}
}

func TestNoColorWinsOverForce(t *testing.T) {
	neutralEnv(t)
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("NO_COLOR", "1")
	if For(&bytes.Buffer{}).Color() {
		t.Fatal("NO_COLOR must win over CLICOLOR_FORCE")
	}
}

func TestForceColorWritesEscapes(t *testing.T) {
	neutralEnv(t)
	t.Setenv("CLICOLOR_FORCE", "1")
	s := For(&bytes.Buffer{})
	got := s.Green("up")
	if !strings.Contains(got, "\x1b[32m") || !strings.HasSuffix(got, escReset) {
		t.Fatalf("expected a wrapped, reset-terminated string, got %q", got)
	}
	if s.Green("") != "" {
		t.Fatal("empty text should stay empty rather than become a bare escape pair")
	}
}

func TestFieldsAlignsAndSkipsEmpty(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	For(&buf).Fields(&buf,
		Field{Label: "IP", Value: "10.0.0.1"},
		Field{Label: "endpoint", Value: "1.2.3.4:443"},
		Field{Label: "DNS", Value: ""}, // unknown: must not leave a dangling label
	)
	want := "  IP        10.0.0.1\n  endpoint  1.2.3.4:443\n"
	if buf.String() != want {
		t.Fatalf("fields block:\ngot:  %q\nwant: %q", buf.String(), want)
	}
}

func TestFieldsIgnoresEmptyValuesWhenSizingColumns(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	For(&buf).Fields(&buf,
		Field{Label: "IP", Value: "10.0.0.1"},
		Field{Label: "a-very-long-label", Value: ""},
	)
	if got := buf.String(); got != "  IP  10.0.0.1\n" {
		t.Fatalf("a skipped field widened the column: %q", got)
	}
}

func TestFailKeepsGuidanceUnderTheProblem(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	Fail(&buf, errors.New("`awsvpn connect` needs root — re-run with:\n  sudo awsvpn connect dev"))
	want := "✖ `awsvpn connect` needs root — re-run with:\n  sudo awsvpn connect dev\n"
	if buf.String() != want {
		t.Fatalf("error block:\ngot:  %q\nwant: %q", buf.String(), want)
	}
}

func TestDuration(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{900 * time.Millisecond, "1s"},
		{45 * time.Second, "45s"},
		{3 * time.Minute, "3m"},
		{12*time.Minute + 4*time.Second, "12m 04s"},
		{2 * time.Hour, "2h"},
		{3*time.Hour + 7*time.Minute, "3h 07m"},
		{-5 * time.Second, "0s"},
	} {
		if got := Duration(tc.in); got != tc.want {
			t.Errorf("Duration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
