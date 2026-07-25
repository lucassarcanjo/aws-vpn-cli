package cli

import (
	"strings"
	"testing"
)

// The privilege error is the only place most users will ever read about
// `install-privilege`, so it has to offer the move that fits their situation:
// install one when there is none, re-install when the one on disk is stale.
func TestNotRootErrOffersTheApplicableFix(t *testing.T) {
	noGrant := notRootErr("connect", "to manage the tunnel", false, "/usr/local/bin/awsvpn").Error()
	// The re-run line echoes os.Args, which under `go test` is the test
	// binary's — so assert on the parts that don't depend on the invocation.
	if !strings.Contains(noGrant, "`awsvpn connect` needs root to manage the tunnel") {
		t.Errorf("the error must name the command and why it needs root:\n%s", noGrant)
	}
	if !strings.Contains(noGrant, "sudo awsvpn") {
		t.Errorf("the error must show the sudo re-run:\n%s", noGrant)
	}
	if !strings.Contains(noGrant, "sudo awsvpn install-privilege") {
		t.Errorf("with no grant, the error should offer to install one:\n%s", noGrant)
	}
	if strings.Contains(noGrant, "doesn't cover") {
		t.Errorf("with no grant there is no stale rule to blame:\n%s", noGrant)
	}

	stale := notRootErr("connect", "to manage the tunnel", true, "/usr/local/bin/awsvpn").Error()
	if !strings.Contains(stale, "/usr/local/bin/awsvpn") {
		t.Errorf("a stale rule should name the binary it fails to cover:\n%s", stale)
	}
	if !strings.Contains(stale, "install-privilege") {
		t.Errorf("a stale rule is fixed by re-installing it:\n%s", stale)
	}
}
