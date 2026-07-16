package daemon

import (
	"fmt"

	"github.com/larcanjo/awsvpn/internal/logging"
	"github.com/larcanjo/awsvpn/internal/mgmt"
	"github.com/larcanjo/awsvpn/internal/state"
	"github.com/larcanjo/awsvpn/internal/system"
)

// Disconnect tears down the active tunnel: signals acvc-openvpn to exit, reverts
// DNS, and clears the recorded state. It is safe to call when nothing is
// connected (reports so) and when the tunnel already died (still reverts DNS).
func Disconnect(home string, sys system.Port, log *logging.Logger) (string, error) {
	// Always try to revert DNS first, even if there's no run record — a prior
	// crash may have left an override behind.
	revertDNS(home, sys, log)

	r, ok, err := state.Load(home)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil // nothing connected
	}
	profile := r.Profile
	if err := teardown(home, sys, r, log); err != nil {
		return profile, err
	}
	return profile, nil
}

// teardown stops a specific recorded tunnel and clears its state.
func teardown(home string, sys system.Port, r state.Run, log *logging.Logger) error {
	// Prefer a clean management SIGTERM (openvpn removes its own routes); fall
	// back to signalling the pid directly.
	if r.MgmtSocket != "" {
		if err := mgmt.SignalTerm(r.MgmtSocket); err != nil && r.Alive() {
			_ = sys.Kill(r.OvpnPID)
		}
	} else if r.Alive() {
		_ = sys.Kill(r.OvpnPID)
	}
	revertDNS(home, sys, log)
	return state.Clear(home)
}

// CleanupStale reverts DNS and clears state left by a previous connection whose
// process has died — so a crash never leaves the resolver pointed at an
// unreachable server, and stale state never blocks the next connect.
func CleanupStale(home string, sys system.Port, log *logging.Logger) {
	r, ok, err := state.Load(home)
	if err == nil && ok && !r.Alive() {
		if log != nil {
			log.Info("cleaning up stale connection (%s: pid %d is gone)", r.Profile, r.OvpnPID)
		}
		revertDNS(home, sys, log)
		_ = state.Clear(home)
		return
	}
	// Even with no run record, a DNS override may linger from a death mid-connect.
	if !ok {
		revertDNS(home, sys, log)
	}
}

// revertDNS restores the resolver from the persisted backup, if any.
func revertDNS(home string, sys system.Port, log *logging.Logger) {
	b, ok, err := state.LoadDNSBackup(home)
	if err != nil || !ok {
		return
	}
	if err := sys.RevertDNS(b); err != nil && log != nil {
		log.Info("warning: could not revert DNS: %v", err)
	}
	_ = state.ClearDNSBackup(home)
}

// Status returns the active run and whether it is live.
func Status(home string) (state.Run, bool, error) {
	r, ok, err := state.Load(home)
	if err != nil || !ok {
		return state.Run{}, false, err
	}
	return r, r.Alive(), nil
}

// FormatStatus renders a human-readable status line.
func FormatStatus(r state.Run, live bool) string {
	if !live {
		return fmt.Sprintf("stale: %s recorded but its process is gone (run `awsvpn disconnect` to clean up)", r.Profile)
	}
	tunnel := "split-tunnel"
	if r.FullTunnel {
		tunnel = "full-tunnel"
	}
	return fmt.Sprintf("connected: %s\n  assigned IP: %s\n  endpoint:    %s:%s\n  DNS:         %v\n  mode:        %s\n  uptime:      %s",
		r.Profile, r.AssignedIP, r.RemoteIP, r.Port, r.DNS, tunnel, r.Duration().Round(1e9))
}
