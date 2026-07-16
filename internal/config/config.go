// Package config holds the handful of external constants awsvpn depends on and
// the path layout. Two AWS-owned constants (the signing team identifier and the
// fixed callback port) live here so a future AWS change is a one-line update.
//
// Privileged runtime state (the active tunnel, its DNS revert record, the
// management socket, the connection log) lives in a ROOT-OWNED directory under
// /var/run — never in the user's home. This is deliberate: the state dir is
// written by root, and a user-writable directory that root writes into is a
// classic symlink-clobber privilege-escalation vector. User data (imported
// profiles) stays under the user's home, written as the user.
package config

import (
	"fmt"
	"path/filepath"
)

const (
	// AWSTeamID is the Apple Developer Team Identifier AWS uses to sign
	// acvc-openvpn. We pin it and verify the signature before executing the
	// binary as root, so a swapped binary can't run privileged under our name.
	AWSTeamID = "94KV3E626L"

	// CallbackPort is the fixed loopback port AWS Client VPN uses for the SAML
	// assertion consumer service (ACS) callback. The first auth attempt declares
	// it as "ACS::35001"; it is not configurable.
	CallbackPort = 35001

	// ACVCOpenVPNPath is where the official AWS VPN Client installs its
	// AWS-signed OpenVPN engine.
	ACVCOpenVPNPath = "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn"

	// RuntimeDir is the root-owned directory holding the single active
	// connection's state. Machine-global (there is one tunnel), cleared on
	// reboot, and — critically — not writable by any non-root user, so root's
	// writes here cannot be redirected through a planted symlink.
	RuntimeDir = "/var/run/awsvpn"
)

// CallbackAddr is the loopback socket the one-shot SAML listener binds to.
func CallbackAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", CallbackPort)
}

// FirstAuthPassword is the dummy password of the first auth attempt. It declares
// our callback port to the endpoint, which replies with the CRV1/SAML challenge.
func FirstAuthPassword() string {
	return fmt.Sprintf("ACS::%d", CallbackPort)
}

// ---- root-owned runtime state (/var/run/awsvpn) ----

// RunStatePath is where the active connection is recorded (JSON).
func RunStatePath() string { return filepath.Join(RuntimeDir, "run.json") }

// DNSBackupPath is the resolver state to revert to; written the moment DNS is
// applied so a crash mid-connect is still revertible on the next run.
func DNSBackupPath() string { return filepath.Join(RuntimeDir, "dns-backup.json") }

// LogPath is the current connection's log file.
func LogPath() string { return filepath.Join(RuntimeDir, "awsvpn.log") }

// MgmtSocketPath is the unix-domain management socket for the active tunnel.
func MgmtSocketPath() string { return filepath.Join(RuntimeDir, "mgmt.sock") }

// ---- user-owned data (the invoking user's home) ----

// AWSVPNClientDir is the official client's config directory. Read-only to us.
func AWSVPNClientDir(home string) string {
	return filepath.Join(home, ".config", "AWSVPNClient")
}

// ConnectionProfilesPath is the official client's profile index (plain JSON).
func ConnectionProfilesPath(home string) string {
	return filepath.Join(AWSVPNClientDir(home), "ConnectionProfiles")
}

// OpenVpnConfigsDir holds the official client's raw .ovpn files.
func OpenVpnConfigsDir(home string) string {
	return filepath.Join(AWSVPNClientDir(home), "OpenVpnConfigs")
}

// UserDataDir is awsvpn's own user-owned directory (imported profiles only).
func UserDataDir(home string) string {
	return filepath.Join(home, ".config", "awsvpn")
}

// ImportedProfilesDir holds .ovpn files the user imported via `awsvpn import`.
func ImportedProfilesDir(home string) string {
	return filepath.Join(UserDataDir(home), "profiles")
}
