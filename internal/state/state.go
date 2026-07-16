// Package state persists the single active connection so `status` and
// `disconnect` can control an out-of-band background tunnel, and so a crashed
// prior connection can be detected and cleaned up on the next connect.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/larcanjo/awsvpn/internal/config"
	"github.com/larcanjo/awsvpn/internal/dns"
	"github.com/larcanjo/awsvpn/internal/ovpn"
)

// Run records everything needed to observe and tear down the active tunnel. The
// DNS revert state is stored separately (see SaveDNSBackup) because it must be
// persisted the instant DNS is applied — before the tunnel is fully up — so a
// death in that window still leaves a revertible marker.
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

// Save writes the run state for a user home, creating the state dir if needed.
func Save(home string, r Run) error {
	if err := os.MkdirAll(config.StateDir(home), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(config.RunStatePath(home), data, 0o644)
}

// Load reads the run state. ok=false means there is no active connection on
// record.
func Load(home string) (Run, bool, error) {
	data, err := os.ReadFile(config.RunStatePath(home))
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
func Clear(home string) error {
	err := os.Remove(config.RunStatePath(home))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// SaveDNSBackup persists the resolver state to revert to. It is written the
// moment DNS is applied so the next run can restore DNS even if this connection
// dies before it is fully established — the crash-safety net.
func SaveDNSBackup(home string, b dns.Backup) error {
	if err := os.MkdirAll(config.StateDir(home), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(config.DNSBackupPath(home), data, 0o644)
}

// LoadDNSBackup reads the pending resolver revert state. ok=false means no DNS
// override is currently on record.
func LoadDNSBackup(home string) (dns.Backup, bool, error) {
	data, err := os.ReadFile(config.DNSBackupPath(home))
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
func ClearDNSBackup(home string) error {
	err := os.Remove(config.DNSBackupPath(home))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Alive reports whether the recorded openvpn process is still running.
func (r Run) Alive() bool {
	if r.OvpnPID <= 0 {
		return false
	}
	// Signal 0 probes existence without delivering a signal.
	return syscall.Kill(r.OvpnPID, 0) == nil
}

// Duration is how long the tunnel has been up.
func (r Run) Duration() time.Duration {
	if r.ConnectedAt.IsZero() {
		return 0
	}
	return time.Since(r.ConnectedAt)
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
