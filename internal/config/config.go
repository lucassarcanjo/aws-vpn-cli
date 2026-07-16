// Package config holds the handful of external constants awsvpn depends on and
// the path layout of the official AWS VPN Client. Keeping the two AWS-owned
// constants (the signing team identifier and the fixed callback port) in one
// place means a future AWS change is a one-line update, not a mystery failure.
package config

import (
	"fmt"
	"path/filepath"
)

const (
	// AWSTeamID is the Apple Developer Team Identifier AWS uses to sign
	// acvc-openvpn. We pin it and verify the signature before executing the
	// binary as root, so a swapped binary can't run privileged under our name.
	// If AWS ever changes its signing identity this is the one line to update
	// (and users have --allow-unverified-binary as a stopgap).
	AWSTeamID = "94KV3E626L"

	// CallbackPort is the fixed loopback port AWS Client VPN uses for the SAML
	// assertion consumer service (ACS) callback. The first auth attempt declares
	// it to the endpoint as "ACS::35001"; it is not configurable — the IdP posts
	// the assertion to exactly this port.
	CallbackPort = 35001

	// ACVCOpenVPNPath is where the official AWS VPN Client installs its
	// AWS-signed OpenVPN engine. Its presence makes the AWS app a hard
	// prerequisite (acceptable: the target user already has it installed).
	ACVCOpenVPNPath = "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn"
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

// AWSVPNClientDir is the official client's config directory for the given user
// home. We read it strictly read-only and never mutate it.
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

// StateDir is awsvpn's own state directory (run state, imported profiles, logs).
// Kept separate from the AWS client's directory so we never write into theirs.
func StateDir(home string) string {
	return filepath.Join(home, ".config", "awsvpn")
}

// ImportedProfilesDir holds .ovpn files the user imported via `awsvpn import`.
func ImportedProfilesDir(home string) string {
	return filepath.Join(StateDir(home), "profiles")
}

// RunStatePath is where the daemon records the active connection (JSON).
func RunStatePath(home string) string {
	return filepath.Join(StateDir(home), "run.json")
}

// DNSBackupPath is where a live connection stashes the resolver state to revert
// to, so the next run can restore DNS even if this process died mid-connection.
func DNSBackupPath(home string) string {
	return filepath.Join(StateDir(home), "dns-backup.json")
}

// LogPath is the current connection's log file.
func LogPath(home string) string {
	return filepath.Join(StateDir(home), "awsvpn.log")
}

// MgmtSocketPath is the unix-domain management socket for the active tunnel.
func MgmtSocketPath(home string) string {
	return filepath.Join(StateDir(home), "mgmt.sock")
}
