package state

import (
	"os"
	"testing"
)

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
