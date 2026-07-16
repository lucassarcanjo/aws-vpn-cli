package logging

import (
	"strings"
	"testing"
)

func TestRedactPasswordCommand(t *testing.T) {
	r := NewRedactor()
	// The CRV1 response carrying the assertion must never survive in a log line.
	in := `>> password "Auth" "CRV1::instance-1/abc::PHNhbWxwOlJlc3BvbnNlPnh4eA%3D%3D"`
	out := r.Redact(in)
	if strings.Contains(out, "PHNhbWxwOlJlc3BvbnNl") {
		t.Fatalf("assertion leaked: %q", out)
	}
	if !strings.Contains(out, "<redacted len=") {
		t.Fatalf("expected a redaction placeholder: %q", out)
	}
	// The command keyword stays legible; everything after it is gone.
	if !strings.Contains(out, `password "`) {
		t.Errorf("lost the command keyword: %q", out)
	}
}

func TestRedactSurvivesQuoteInjection(t *testing.T) {
	// A malicious endpoint could embed a quote in the CRV1 state, which %q renders
	// as \". Redacting the whole remainder (not a quoted sub-group) must still
	// scrub the assertion tail rather than stop at the injected quote.
	r := NewRedactor()
	in := `>> password "Auth" "CRV1::inst\"ance::SECRETASSERTIONVALUE"`
	out := r.Redact(in)
	if strings.Contains(out, "SECRETASSERTIONVALUE") {
		t.Fatalf("quote injection leaked the assertion: %q", out)
	}
}

func TestRedactRegisteredSecret(t *testing.T) {
	r := NewRedactor()
	secret := "super-secret-mgmt-password"
	r.Add(secret)
	out := r.Redact("connecting with " + secret + " now")
	if strings.Contains(out, secret) {
		t.Fatalf("registered secret leaked: %q", out)
	}
}

func TestRedactACSCommand(t *testing.T) {
	// The first-auth password (ACS::port) is not secret, but it flows through the
	// same password-command path, so it still gets redacted — fine and expected.
	r := NewRedactor()
	out := r.Redact(`password "Auth" "ACS::35001"`)
	if strings.Contains(out, "ACS::35001") {
		t.Errorf("value not redacted: %q", out)
	}
	if !strings.Contains(out, "<redacted len=") {
		t.Errorf("expected a placeholder: %q", out)
	}
}
