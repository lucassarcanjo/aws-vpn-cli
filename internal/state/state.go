// Package state persists the single active connection under the root-owned
// runtime dir so `status` and `disconnect` can control an out-of-band background
// tunnel, and so a crashed prior connection can be detected and cleaned up on the
// next connect. State is machine-global (one tunnel) and root-owned; non-root
// commands read it (files are world-readable) but cannot tamper with it.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/dns"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ovpn"
)

// Run records everything needed to observe and tear down the active tunnel. It is
// written once with the PID/socket right after spawn (so a crash before the
// tunnel is up still leaves a killable record) and again at CONNECTED with the
// assignment details. A zero ConnectedAt means "still connecting".
type Run struct {
	Profile     string       `json:"profile"`
	OvpnPID     int          `json:"ovpn_pid"`
	MgmtSocket  string       `json:"mgmt_socket"`
	LogPath     string       `json:"log_path"`
	AssignedIP  string       `json:"assigned_ip"`
	RemoteIP    string       `json:"remote_ip"`
	Port        string       `json:"port"`
	ConnectedAt time.Time    `json:"connected_at"`
	DNS         []string     `json:"dns,omitempty"`
	Routes      []ovpn.Route `json:"routes,omitempty"`
	FullTunnel  bool         `json:"full_tunnel"`
}

// EnsureRuntimeDir creates the root-owned runtime dir (0755: root-writable,
// world-readable so non-sudo status/logs work). Must be called as root.
func EnsureRuntimeDir() error {
	return os.MkdirAll(config.RuntimeDir, 0o755)
}

// Save writes the active connection record.
func Save(r Run) error {
	if err := EnsureRuntimeDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(config.RunStatePath(), data, 0o644)
}

// Load reads the run state. ok=false means no active connection on record.
func Load() (Run, bool, error) {
	data, err := os.ReadFile(config.RunStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, err
	}
	var r Run
	if err := json.Unmarshal(data, &r); err != nil {
		return Run{}, false, err
	}
	return r, true, nil
}

// Clear removes the run state record.
func Clear() error {
	return removeIfExists(config.RunStatePath())
}

// SaveDNSBackup persists the resolver state to revert to, written the moment DNS
// is applied so a death before CONNECTED is still revertible on the next run.
func SaveDNSBackup(b dns.Backup) error {
	if err := EnsureRuntimeDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(config.DNSBackupPath(), data, 0o644)
}

// LoadDNSBackup reads the pending resolver revert state.
func LoadDNSBackup() (dns.Backup, bool, error) {
	data, err := os.ReadFile(config.DNSBackupPath())
	if errors.Is(err, os.ErrNotExist) {
		return dns.Backup{}, false, nil
	}
	if err != nil {
		return dns.Backup{}, false, err
	}
	var b dns.Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return dns.Backup{}, false, err
	}
	return b, true, nil
}

// ClearDNSBackup removes the pending resolver revert marker.
func ClearDNSBackup() error {
	return removeIfExists(config.DNSBackupPath())
}

// Alive reports whether the recorded openvpn process still exists. Note this is a
// necessary but not sufficient signal — callers that will signal the process must
// also confirm its identity (PID reuse), see daemon.teardown.
//
// The tunnel is root-owned but `status` runs unprivileged, so probing it from a
// normal shell fails with EPERM rather than succeeding: the kernel checks
// permission even for the null signal. EPERM only ever comes back when the
// process is there to be denied, so it means alive just as surely as a nil error.
func (r Run) Alive() bool {
	if r.OvpnPID <= 0 {
		return false
	}
	err := syscall.Kill(r.OvpnPID, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// Connecting reports a record written at spawn that has not yet reached CONNECTED.
func (r Run) Connecting() bool { return r.ConnectedAt.IsZero() }

// Duration is how long the tunnel has been up.
func (r Run) Duration() time.Duration {
	if r.ConnectedAt.IsZero() {
		return 0
	}
	return time.Since(r.ConnectedAt)
}

func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
