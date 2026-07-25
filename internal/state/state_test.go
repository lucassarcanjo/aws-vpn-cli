package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/dns"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ovpn"
)

// A Store is a directory with two JSON files in it, and a temp directory is a
// real one — so these tests use t.TempDir() rather than faking the filesystem.

func TestRunRoundTrip(t *testing.T) {
	s := At(t.TempDir())

	want := Run{
		Profile:     "dev",
		OvpnPID:     4242,
		MgmtSocket:  "/var/run/awsvpn/mgmt.sock",
		LogPath:     "/var/run/awsvpn/awsvpn.log",
		AssignedIP:  "10.8.0.133",
		RemoteIP:    "203.0.113.10",
		Port:        "443",
		ConnectedAt: time.Now().Truncate(time.Second),
		DNS:         []string{"10.0.0.2"},
		Routes:      []ovpn.Route{{Network: "10.0.0.0", Netmask: "255.255.0.0"}},
		FullTunnel:  true,
	}
	if err := s.SaveRun(want); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.Run()
	if err != nil || !ok {
		t.Fatalf("Run() = ok:%v err:%v, want a record", ok, err)
	}
	if got.Profile != want.Profile || got.OvpnPID != want.OvpnPID {
		t.Errorf("identity did not survive: %+v", got)
	}
	if got.AssignedIP != want.AssignedIP || got.RemoteIP != want.RemoteIP || got.Port != want.Port {
		t.Errorf("assignment did not survive: %+v", got)
	}
	// Routes and DNS are what disconnect needs to undo; losing them silently
	// would leave the machine half-configured after a teardown.
	if len(got.Routes) != 1 || got.Routes[0].Network != "10.0.0.0" {
		t.Errorf("routes did not survive: %+v", got.Routes)
	}
	if len(got.DNS) != 1 || got.DNS[0] != "10.0.0.2" {
		t.Errorf("DNS did not survive: %+v", got.DNS)
	}
	if !got.ConnectedAt.Equal(want.ConnectedAt) {
		t.Errorf("ConnectedAt = %v, want %v", got.ConnectedAt, want.ConnectedAt)
	}
	if !got.FullTunnel {
		t.Error("FullTunnel did not survive")
	}
}

// TestAbsentRecordIsNotAnError: "nothing connected" is the normal state on a
// fresh machine. If it read as an error, status and disconnect would both fail
// rather than reporting the truth.
func TestAbsentRecordIsNotAnError(t *testing.T) {
	s := At(t.TempDir())

	if r, ok, err := s.Run(); err != nil || ok || r.Profile != "" {
		t.Errorf("Run() on an empty store = %+v, ok:%v, err:%v; want zero, false, nil", r, ok, err)
	}
	if b, ok, err := s.DNS(); err != nil || ok || b.ServiceID != "" {
		t.Errorf("DNS() on an empty store = %+v, ok:%v, err:%v; want zero, false, nil", b, ok, err)
	}
}

// TestClearIsIdempotent: teardown paths call Clear whether or not a record
// exists, and a spurious error there would mask the real failure.
func TestClearIsIdempotent(t *testing.T) {
	s := At(t.TempDir())
	for i := range 2 {
		if err := s.ClearRun(); err != nil {
			t.Errorf("ClearRun() #%d on an absent record: %v", i+1, err)
		}
		if err := s.ClearDNS(); err != nil {
			t.Errorf("ClearDNS() #%d on an absent record: %v", i+1, err)
		}
	}

	if err := s.SaveRun(Run{Profile: "dev"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearRun(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Run(); ok {
		t.Error("record survived ClearRun")
	}
}

// TestDNSBackupRoundTrip covers the record that makes crash-safe DNS revert
// possible: it is written the moment DNS is applied, so a death before CONNECTED
// is still revertible on the next run.
func TestDNSBackupRoundTrip(t *testing.T) {
	s := At(t.TempDir())

	want := dns.Backup{
		ServiceID: "ABC-123",
		State: dns.Dict{
			Present:         true,
			ServerAddresses: []string{"192.168.1.1"},
			SearchDomains:   []string{"lan"},
			DomainName:      "lan",
		},
		// Setup was absent before we wrote ours. Present=false is the signal that
		// revert must REMOVE the key rather than restore a dictionary, so it has
		// to survive the round trip distinctly from "present but empty".
		Setup: dns.Dict{Present: false},
	}
	if err := s.SaveDNS(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.DNS()
	if err != nil || !ok {
		t.Fatalf("DNS() = ok:%v err:%v, want a record", ok, err)
	}
	if got.ServiceID != want.ServiceID {
		t.Errorf("service id = %q, want %q", got.ServiceID, want.ServiceID)
	}
	if !got.State.Present {
		t.Error("State.Present did not survive; revert would remove the key instead of restoring it")
	}
	if got.Setup.Present {
		t.Error("Setup.Present did not survive; revert would restore a key that never existed")
	}
	if len(got.State.ServerAddresses) != 1 || got.State.ServerAddresses[0] != "192.168.1.1" {
		t.Errorf("prior resolvers did not survive: %+v", got.State.ServerAddresses)
	}
	if len(got.State.SearchDomains) != 1 || got.State.DomainName != "lan" {
		t.Errorf("search domains did not survive: %+v", got.State)
	}
}

// TestTheTwoRecordsAreIndependent: clearing one must not disturb the other.
// Connect clears the DNS backup on a failed handshake while the run record is
// still live, so a shared code path that cleared both would be a real bug.
func TestTheTwoRecordsAreIndependent(t *testing.T) {
	s := At(t.TempDir())
	if err := s.SaveRun(Run{Profile: "dev", OvpnPID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDNS(dns.Backup{ServiceID: "ABC"}); err != nil {
		t.Fatal(err)
	}

	if err := s.ClearDNS(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Run(); !ok {
		t.Error("ClearDNS removed the run record")
	}
	if _, ok, _ := s.DNS(); ok {
		t.Error("ClearDNS did not remove the DNS record")
	}
}

// TestSaveCreatesTheRootAndLeavesItReadable: the runtime dir is created by root
// but must stay world-readable, or `awsvpn status` without sudo cannot work.
func TestSaveCreatesTheRootAndLeavesItReadable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "created", "nested")
	s := At(root)
	if err := s.SaveRun(Run{Profile: "dev"}); err != nil {
		t.Fatal(err)
	}

	di, err := os.Stat(root)
	if err != nil {
		t.Fatalf("root was not created: %v", err)
	}
	if di.Mode().Perm()&0o055 != 0o055 {
		t.Errorf("root mode = %v, want world-readable/searchable so non-root status works", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(root, runFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o044 != 0o044 {
		t.Errorf("run record mode = %v, want world-readable", fi.Mode().Perm())
	}
}

// TestWriteIsAtomic: a reader must never observe a half-written record. The
// write goes to a temp file and is renamed, so no partial JSON is ever visible
// under the real name — and no .tmp litter is left behind either.
func TestWriteIsAtomic(t *testing.T) {
	root := t.TempDir()
	s := At(root)
	if err := s.SaveRun(Run{Profile: "first", OvpnPID: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRun(Run{Profile: "second", OvpnPID: 2}); err != nil {
		t.Fatal(err)
	}

	got, _, err := s.Run()
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile != "second" {
		t.Errorf("overwrite did not take effect: %+v", got)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) > 4 && e.Name()[:5] == ".tmp-" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestCorruptRecordSurfacesAsAnError: a truncated or hand-edited record must not
// be silently read as "nothing connected", which would strand a live tunnel with
// no way to tear it down.
func TestCorruptRecordSurfacesAsAnError(t *testing.T) {
	root := t.TempDir()
	s := At(root)
	if err := os.WriteFile(filepath.Join(root, runFile), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Run(); err == nil {
		t.Errorf("corrupt record read as ok:%v with no error", ok)
	}
}

func TestDefaultUsesTheRootOwnedRuntimeDir(t *testing.T) {
	if got := Default().Root(); got != "/var/run/awsvpn" {
		t.Errorf("Default() root = %q, want the root-owned runtime dir", got)
	}
}

func TestRunConnectingAndDuration(t *testing.T) {
	var fresh Run
	if !fresh.Connecting() {
		t.Error("a record with no ConnectedAt should read as connecting")
	}
	if fresh.Duration() != 0 {
		t.Errorf("duration of a connecting run = %v, want 0", fresh.Duration())
	}

	up := Run{ConnectedAt: time.Now().Add(-90 * time.Second)}
	if up.Connecting() {
		t.Error("a connected record should not read as connecting")
	}
	if d := up.Duration(); d < 89*time.Second || d > 95*time.Second {
		t.Errorf("duration = %v, want ~90s", d)
	}
}

// ---------------------------------------------------------------- liveness
//
// Alive() is the signal `status` uses to tell a live tunnel from a crashed one,
// and it is read from an UNPRIVILEGED shell against a root-owned process — which
// is why the EPERM case below is the one that actually matters.

func TestAliveNoPID(t *testing.T) {
	if (Run{}).Alive() {
		t.Error("a record with no pid should not be alive")
	}
	if (Run{OvpnPID: -1}).Alive() {
		t.Error("a negative pid should not be alive")
	}
}

func TestAliveOwnProcess(t *testing.T) {
	if !(Run{OvpnPID: os.Getpid()}).Alive() {
		t.Error("this very process should be alive")
	}
}

// The tunnel is root-owned while `status` runs unprivileged, so the null-signal
// probe comes back EPERM instead of nil — which used to read as "the process is
// gone" and made a healthy connection report as stale. pid 1 (launchd) stands in
// for the tunnel: always running, never ours.
func TestAliveProcessWeMayNotSignal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every process is signalable, so there is no EPERM to exercise")
	}
	if !(Run{OvpnPID: 1}).Alive() {
		t.Error("a running process we lack permission to signal should still count as alive")
	}
}

func TestAliveDeadProcess(t *testing.T) {
	// A pid that has exited: spawn a trivial process and reap it, so the pid is
	// known-gone (and not yet recycled) at the moment we probe it.
	p, err := os.StartProcess("/usr/bin/true", []string{"true"}, &os.ProcAttr{})
	if err != nil {
		t.Fatalf("spawning a throwaway process: %v", err)
	}
	if _, err := p.Wait(); err != nil {
		t.Fatalf("reaping the throwaway process: %v", err)
	}
	if (Run{OvpnPID: p.Pid}).Alive() {
		t.Error("an exited process should not be alive")
	}
}
