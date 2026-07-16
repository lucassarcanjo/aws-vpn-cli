// Package signature verifies that acvc-openvpn is genuinely AWS-signed before we
// execute it as root. Our entire trust claim is "the privileged crypto is AWS's
// signed binary", so this check runs right before the privileged exec: a swapped
// binary must not run as root under the user's name.
package signature

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var teamIDRe = regexp.MustCompile(`(?m)^TeamIdentifier=(\S+)`)

// ErrNotInstalled is returned when the binary is missing entirely.
var ErrNotInstalled = errors.New("acvc-openvpn not found")

// Verify checks that binPath has a valid, Apple-anchored code signature pinned to
// the given team identifier. It is a single codesign invocation combining
// integrity + team pin (exit 0 only if both hold). On failure it enriches the
// error with the team identifier actually found, so the operator can tell a
// tampered binary from a legitimate AWS signing-identity change.
func Verify(binPath, teamID string) error {
	if _, err := os.Stat(binPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w at %s — install the official AWS VPN Client from https://aws.amazon.com/vpn/client-vpn-download/", ErrNotInstalled, binPath)
		}
		return fmt.Errorf("cannot stat %s: %w", binPath, err)
	}

	req := fmt.Sprintf(`anchor apple generic and certificate leaf[subject.OU] = "%s"`, teamID)
	// -R=<req> passes the requirement inline; -R <req> would read it from a file.
	cmd := exec.Command("codesign", "--verify", "--strict", "-R="+req, binPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	found := teamIdentifier(binPath)
	detail := strings.TrimSpace(string(out))
	if found == "" {
		found = "unknown"
	}
	return fmt.Errorf(
		"signature verification failed for %s: %s\n"+
			"  found TeamIdentifier=%s, pinned=%s\n"+
			"  refusing to run an unverified binary as root; if AWS legitimately changed its\n"+
			"  signing identity, re-run with --allow-unverified-binary",
		binPath, detail, found, teamID)
}

// teamIdentifier best-effort extracts the signed team id for a friendlier error.
// codesign writes -d output to stderr, so combine the streams.
func teamIdentifier(binPath string) string {
	out, err := exec.Command("codesign", "-d", "--verbose=4", binPath).CombinedOutput()
	if err != nil {
		return ""
	}
	if m := teamIDRe.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}
