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
	// The realm and command shape stay legible for debugging.
	if !strings.Contains(out, `password "Auth"`) {
		t.Errorf("over-redacted, lost realm: %q", out)
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

func TestRedactACSNotOverRedacted(t *testing.T) {
	// The first-auth password (ACS::port) is not secret, but it flows through the
	// same password-command path, so it still gets length-redacted — that's fine
	// and expected. Just verify we don't crash and produce a placeholder.
	r := NewRedactor()
	out := r.Redact(`password "Auth" "ACS::35001"`)
	if !strings.Contains(out, "<redacted len=10>") {
		t.Errorf("ACS redaction = %q", out)
	}
}
