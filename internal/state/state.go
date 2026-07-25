// Package state persists the single active connection under the root-owned
// runtime dir so `status` and `disconnect` can control an out-of-band background
// tunnel, and so a crashed prior connection can be detected and cleaned up on the
// next connect. State is machine-global (one tunnel) and root-owned; non-root
// commands read it (files are world-readable) but cannot tamper with it.
//
// A Store is rooted at a directory rather than at the package-level constant, so
// tests can point one at a temp dir. Production always uses Default().
//
// SECURITY: the root MUST be root-owned. A user-writable directory that root
// writes into is a classic symlink-clobber privilege-escalation vector, which is
// why config.RuntimeDir lives under /var/run and not in the user's home. Nothing
// reachable from main may build a Store at any other root — see the comment on
// daemon.Options.StateRoot.
//
// Audit — outside _test.go files there must be exactly ONE hit, the one in
// daemon.Options.store() that reads the (production-empty) StateRoot:
//
//	grep -rn 'state\.At(' --include='*.go' . | grep -v _test.go | grep -vE ':[[:space:]]*//'
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

// The two records a Store holds, as filenames within its root.
const (
	runFile = "run.json"
	dnsFile = "dns-backup.json"
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

// Store is the connection state rooted at a directory. The two records it holds
// are read and written through one pair of private helpers, so their atomicity
// and their "absent is not an error" handling cannot drift apart.
type Store struct{ root string }

// At returns a Store rooted at dir. See the package comment: in production dir
// must be root-owned.
func At(dir string) *Store { return &Store{root: dir} }

// Default is the production store, rooted at the root-owned runtime dir.
func Default() *Store { return At(config.RuntimeDir) }

// Root is the directory this Store writes into.
func (s *Store) Root() string { return s.root }

// EnsureDir creates the runtime dir (0755: root-writable, world-readable so
// non-sudo status/logs work). Must be called as root in production.
func (s *Store) EnsureDir() error { return os.MkdirAll(s.root, 0o755) }

// Run reads the active connection record. ok=false means nothing on record.
func (s *Store) Run() (Run, bool, error) {
	var r Run
	ok, err := s.read(runFile, &r)
	return r, ok, err
}

// SaveRun writes the active connection record.
func (s *Store) SaveRun(r Run) error { return s.write(runFile, r) }

// ClearRun removes the active connection record.
func (s *Store) ClearRun() error { return removeIfExists(s.path(runFile)) }

// DNS reads the pending resolver revert state. ok=false means no override is
// outstanding.
func (s *Store) DNS() (dns.Backup, bool, error) {
	var b dns.Backup
	ok, err := s.read(dnsFile, &b)
	return b, ok, err
}

// SaveDNS persists the resolver state to revert to. Written the moment DNS is
// applied, so a death before CONNECTED is still revertible on the next run.
func (s *Store) SaveDNS(b dns.Backup) error { return s.write(dnsFile, b) }

// ClearDNS removes the pending resolver revert marker.
func (s *Store) ClearDNS() error { return removeIfExists(s.path(dnsFile)) }

func (s *Store) path(name string) string { return filepath.Join(s.root, name) }

// read decodes a record into v. A missing file is (false, nil), not an error:
// "nothing on record" is an ordinary state, not a failure.
func (s *Store) read(name string, v any) (bool, error) {
	data, err := os.ReadFile(s.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, err
	}
	return true, nil
}

// write replaces a record atomically, so a crash mid-write can never leave a
// half-parsed record that the next run would read as authoritative.
func (s *Store) write(name string, v any) error {
	if err := s.EnsureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path(name), data, 0o644)
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
