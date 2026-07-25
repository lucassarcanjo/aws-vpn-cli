package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestStepsRecordsOnlyTheOutcome(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	r := NewSteps(&buf)
	r.Step("Starting the VPN engine")
	r.OK("VPN engine running (pid 42)")
	r.Stop()

	want := "  ✔ VPN engine running (pid 42)\n"
	if buf.String() != want {
		t.Fatalf("off a terminal, a completed step should print once:\ngot:  %q\nwant: %q", buf.String(), want)
	}
}

func TestStepsKeepsContextWhenInterrupted(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	r := NewSteps(&buf)
	r.Step("Waiting for you to sign in")
	r.Block("\n  Sign in at http://example.test\n\n")
	r.Note("Reopened the sign-in page")
	r.OK("Signed in")
	r.Stop()

	want := strings.Join([]string{
		"  · Waiting for you to sign in",
		"",
		"  Sign in at http://example.test",
		"",
		"  · Reopened the sign-in page",
		"  ✔ Signed in",
		"",
	}, "\n")
	if buf.String() != want {
		t.Fatalf("interjections should keep the step on the record:\ngot:  %q\nwant: %q", buf.String(), want)
	}
}

func TestStepsLeavesAnUnfinishedStepOnTheRecord(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	r := NewSteps(&buf)
	r.Step("Checking the AWS VPN engine")
	r.Stop() // the command failed here

	if got := buf.String(); got != "  · Checking the AWS VPN engine\n" {
		t.Fatalf("a step that never completed should say how far we got: %q", got)
	}
}

func TestStepsDoesNotRepeatARecordedStep(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	r := NewSteps(&buf)
	r.Step("Bringing the tunnel up")
	r.Note("DNS now resolves through 10.0.0.2")
	r.Note("still working")
	r.Stop()

	if n := strings.Count(buf.String(), "Bringing the tunnel up"); n != 1 {
		t.Fatalf("step recorded %d times, want 1:\n%s", n, buf.String())
	}
}

func TestStepsWritesNoEscapesOffATerminal(t *testing.T) {
	neutralEnv(t)
	var buf bytes.Buffer
	r := NewSteps(&buf)
	r.Step("Starting the VPN engine")
	r.Warn("something to know")
	r.OK("done")
	r.Stop()

	if strings.Contains(buf.String(), "\x1b") {
		t.Fatalf("escape sequences leaked into non-terminal output: %q", buf.String())
	}
	if strings.Contains(buf.String(), "\r") {
		t.Fatalf("carriage returns leaked into non-terminal output: %q", buf.String())
	}
}

func TestDiscardSaysNothing(t *testing.T) {
	r := Discard()
	r.Step("x")
	r.Note("y")
	r.Warn("z")
	r.Block("b")
	r.OK("ok")
	r.Stop()
	if r.Styler().Color() {
		t.Fatal("the discard reporter should never claim colour")
	}
}
