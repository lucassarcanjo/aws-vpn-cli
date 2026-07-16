package daemon

import (
	"fmt"

	"github.com/larcanjo/awsvpn/internal/logging"
	"github.com/larcanjo/awsvpn/internal/mgmt"
	"github.com/larcanjo/awsvpn/internal/state"
	"github.com/larcanjo/awsvpn/internal/system"
)

// Disconnect tears down the active tunnel: signals acvc-openvpn to exit, reverts
// DNS, and clears the recorded state. Safe when nothing is connected (reverts any
// lingering DNS override) and when the tunnel already died.
func Disconnect(sys system.Port, log *logging.Logger) (string, error) {
	r, ok, err := state.Load()
	if err != nil {
		return "", err
	}
	if !ok {
		revertDNS(sys, log) // no tunnel on record, but a crash may have left an override
		return "", nil
	}
	return r.Profile, teardown(sys, r, log)
}

// teardown stops a specific recorded tunnel and clears its state. It only ever
// signals the recorded PID after confirming it is still an acvc-openvpn process,
// so a recycled PID belonging to something else is never killed.
func teardown(sys system.Port, r state.Run, log *logging.Logger) error {
	// Prefer a clean management SIGTERM (openvpn removes its own routes).
	if r.MgmtSocket != "" {
		if err := mgmt.SignalTerm(r.MgmtSocket); err != nil {
			killIfOpenVPN(sys, r)
		}
	} else {
		killIfOpenVPN(sys, r)
	}
	revertDNS(sys, log)
	return state.Clear()
}

func killIfOpenVPN(sys system.Port, r state.Run) {
	if r.Alive() && sys.IsOpenVPN(r.OvpnPID) {
		_ = sys.Kill(r.OvpnPID)
	}
}

// CleanupStale reverts DNS and clears state left by a previous connection whose
// process has died (or whose PID was recycled to something else) — so a crash
// never leaves the resolver pointed at an unreachable server, and a recycled PID
// is never mistaken for a live tunnel.
func CleanupStale(sys system.Port, log *logging.Logger) {
	r, ok, err := state.Load()
	if err != nil || !ok {
		revertDNS(sys, log) // no record, but maybe a lingering override
		return
	}
	if r.Alive() && sys.IsOpenVPN(r.OvpnPID) {
		return // genuinely live; leave it for the swap path
	}
	if log != nil {
		log.Info("cleaning up stale connection (%s: pid %d is not a live acvc-openvpn)", r.Profile, r.OvpnPID)
	}
	revertDNS(sys, log)
	_ = state.Clear()
}

// revertDNS restores the resolver from the persisted backup, if any.
func revertDNS(sys system.Port, log *logging.Logger) {
	b, ok, err := state.LoadDNSBackup()
	if err != nil || !ok {
		return
	}
	if err := sys.RevertDNS(b); err != nil && log != nil {
		log.Info("warning: could not revert DNS: %v", err)
	}
	_ = state.ClearDNSBackup()
}

// Status returns the active run and whether it is genuinely live (the recorded
// PID is still an acvc-openvpn process).
func Status(sys system.Port) (state.Run, bool, error) {
	r, ok, err := state.Load()
	if err != nil || !ok {
		return state.Run{}, false, err
	}
	live := r.Alive() && sys.IsOpenVPN(r.OvpnPID)
	return r, live, nil
}

// FormatStatus renders a human-readable status line.
func FormatStatus(r state.Run, live bool) string {
	if !live {
		if r.Connecting() {
			return fmt.Sprintf("connecting: %s (handshake in progress or interrupted)", r.Profile)
		}
		return fmt.Sprintf("stale: %s recorded but its process is gone (run `sudo awsvpn disconnect` to clean up)", r.Profile)
	}
	tunnel := "split-tunnel"
	if r.FullTunnel {
		tunnel = "full-tunnel"
	}
	return fmt.Sprintf("connected: %s\n  assigned IP: %s\n  endpoint:    %s:%s\n  DNS:         %v\n  mode:        %s\n  uptime:      %s",
		r.Profile, r.AssignedIP, r.RemoteIP, r.Port, r.DNS, tunnel, r.Duration().Round(1e9))
}
