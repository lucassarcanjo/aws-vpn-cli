package signature

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
)

// TestVerifyRealBinary proves the exact codesign invocation works from Go against
// the genuinely-AWS-signed binary, when it is installed. Skipped on machines
// without the AWS VPN Client.
func TestVerifyRealBinary(t *testing.T) {
	if _, err := os.Stat(config.ACVCOpenVPNPath); err != nil {
		t.Skip("AWS VPN Client not installed; skipping live signature check")
	}
	if err := Verify(config.ACVCOpenVPNPath, config.AWSTeamID); err != nil {
		t.Fatalf("real acvc-openvpn failed verification: %v", err)
	}
}

// TestVerifyWrongTeamRejected: the same real binary must fail against a bogus
// pinned team id — this is the property that stops a swapped binary running.
func TestVerifyWrongTeamRejected(t *testing.T) {
	if _, err := os.Stat(config.ACVCOpenVPNPath); err != nil {
		t.Skip("AWS VPN Client not installed")
	}
	if err := Verify(config.ACVCOpenVPNPath, "0000000000"); err == nil {
		t.Fatal("expected verification to fail against a wrong team id")
	}
}

func TestVerifyMissingBinary(t *testing.T) {
	err := Verify(filepath.Join(t.TempDir(), "nope"), config.AWSTeamID)
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("expected ErrNotInstalled, got %v", err)
	}
}

func TestVerifyUnsignedFileRejected(t *testing.T) {
	// An arbitrary unsigned file must not pass the pinned check.
	f := filepath.Join(t.TempDir(), "fake-openvpn")
	if err := os.WriteFile(f, []byte("#!/bin/sh\necho not really openvpn\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Verify(f, config.AWSTeamID); err == nil {
		t.Fatal("expected an unsigned file to fail verification")
	}
}
