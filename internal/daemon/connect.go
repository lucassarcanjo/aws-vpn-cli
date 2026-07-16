// Package daemon supervises the connect lifecycle: it verifies and spawns
// acvc-openvpn, drives the pure reducer over the management socket to CONNECTED,
// applies DNS, records the run so `status`/`disconnect` can control the
// background tunnel out-of-band, and cleans up stale state from a prior crash.
package daemon

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/callback"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/dns"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/mgmt"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/profile"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/reducer"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/state"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
)

const (
	// DefaultSSOTimeout bounds how long we wait for the user to complete SSO.
	DefaultSSOTimeout = 3 * time.Minute
	// connectSlack is added to the SSO timeout to bound the rest of the handshake
	// (pre-challenge and post-assertion negotiation), so connect never hangs.
	connectSlack = 2 * time.Minute
)

// Options configures a connect.
type Options struct {
	Profile         profile.Profile
	Sys             system.Port
	Logger          *logging.Logger
	LogFile         *os.File // acvc-openvpn's stdout/stderr sink (owned by the caller)
	AllowUnverified bool
	SSOTimeout      time.Duration
	ConnectTimeout  time.Duration // overall deadline; defaults to SSOTimeout + slack
}

// Connect brings up the tunnel and returns once it reaches CONNECTED, leaving
// acvc-openvpn running in the background.
func Connect(o Options) (state.Run, error) {
	if o.SSOTimeout == 0 {
		o.SSOTimeout = DefaultSSOTimeout
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = o.SSOTimeout + connectSlack
	}

	// A prior connection that already died leaves DNS pointed at an unreachable
	// resolver; clean that up first. A genuinely live one is swapped.
	CleanupStale(o.Sys, o.Logger)
	if r, ok, _ := state.Load(); ok && r.Alive() && o.Sys.IsOpenVPN(r.OvpnPID) {
		o.Logger.Info("swapping active tunnel (%s → %s)", r.Profile, o.Profile.Name)
		if err := teardown(o.Sys, r, o.Logger); err != nil {
			o.Logger.Info("warning: could not cleanly stop the previous tunnel: %v", err)
		}
	}

	// Bind the SAML callback BEFORE anything else. If :35001 is taken we abort
	// rather than risk handing the assertion to whatever holds it.
	cb, err := callback.Listen(config.CallbackAddr())
	if err != nil {
		return state.Run{}, err
	}
	defer cb.Close()

	sock := config.MgmtSocketPath()
	_ = os.Remove(sock) // clear any stale socket

	// Verify the AWS signature as the last thing before we exec the binary as
	// root, to minimise the check-to-use window.
	if o.AllowUnverified {
		o.Logger.Info("WARNING: --allow-unverified-binary set; skipping signature verification")
	} else if err := o.Sys.VerifySignature(config.ACVCOpenVPNPath, config.AWSTeamID); err != nil {
		return state.Run{}, err
	}

	o.Logger.Info("starting acvc-openvpn for profile %q", o.Profile.Name)
	pid, err := o.Sys.SpawnOpenVPN(system.SpawnSpec{
		BinPath:      config.ACVCOpenVPNPath,
		ConfigPath:   o.Profile.OvpnPath,
		SocketPath:   sock,
		LogFile:      o.LogFile,
		RestrictUser: "root",
	})
	if err != nil {
		return state.Run{}, err
	}

	// Record the PID/socket immediately so that if this wrapper is killed before
	// CONNECTED, the next run can find and tear down the orphaned tunnel.
	_ = state.Save(state.Run{
		Profile:    o.Profile.Name,
		OvpnPID:    pid,
		MgmtSocket: sock,
		LogPath:    config.LogPath(),
	})

	client, err := mgmt.Dial(sock, 10*time.Second)
	if err != nil {
		_ = o.Sys.Kill(pid)
		_ = state.Clear()
		return state.Run{}, err
	}
	defer client.Close()

	run, err := drive(o, client, pid, sock, cb)
	if err != nil {
		_ = o.Sys.Kill(pid)
		revertDNS(o.Sys, o.Logger)
		_ = state.Clear()
		return state.Run{}, err
	}
	if err := state.Save(run); err != nil {
		return state.Run{}, fmt.Errorf("recording connection state: %w", err)
	}
	return run, nil
}

// PrepareLog opens the root-owned connection log. O_NOFOLLOW (belt-and-suspenders
// — the dir is root-owned) refuses a planted symlink; O_APPEND makes the parent
// logger's and openvpn's writes to the shared fd atomic rather than interleaved.
func PrepareLog() (*os.File, error) {
	if err := state.EnsureRuntimeDir(); err != nil {
		return nil, err
	}
	return os.OpenFile(config.LogPath(),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_APPEND|syscall.O_NOFOLLOW, 0o644)
}

// drive is the event loop: it feeds management lines, the captured assertion, and
// an overall deadline into the pure reducer and performs the effects it emits.
func drive(o Options, client *mgmt.Client, pid int, sock string, cb *callback.Server) (state.Run, error) {
	st := reducer.Initial(config.CallbackPort)
	lines := client.Lines()
	var samlCh <-chan callback.Result
	var dnsBackup dns.Backup

	// Bound the WHOLE connect, not just the browser wait — otherwise a stall
	// before the challenge or after the assertion would hang forever.
	deadline := time.NewTimer(o.ConnectTimeout)
	defer deadline.Stop()

	for {
		var ev reducer.Event
		select {
		case line, ok := <-lines:
			if !ok {
				return state.Run{}, errors.New("management connection closed before the tunnel came up")
			}
			o.Logger.Debug("<< %s", line)
			ev = reducer.MgmtLine{Line: line}
		case res := <-samlCh:
			samlCh = nil
			if res.Err != nil {
				o.Logger.Info("SSO did not complete: %v", res.Err)
				ev = reducer.Timeout{}
			} else {
				o.Logger.Redactor().Add(res.SAML) // never let it into a log
				o.Logger.Info("SAML assertion captured (%d bytes)", len(res.SAML))
				ev = reducer.SAMLCaptured{Raw: res.SAML}
			}
		case <-deadline.C:
			o.Logger.Info("connect timed out after %s", o.ConnectTimeout)
			ev = reducer.Timeout{}
		}

		var effects []reducer.Effect
		st, effects = reducer.Step(st, ev)
		for _, e := range effects {
			switch eff := e.(type) {
			case reducer.SendMgmt:
				o.Logger.Debug(">> %s", eff.Cmd) // redacted by the logger
				if err := client.Send(eff.Cmd); err != nil {
					return state.Run{}, fmt.Errorf("writing to management channel: %w", err)
				}
			case reducer.OpenBrowser:
				o.Logger.Info("opening browser for single sign-on")
				if err := o.Sys.OpenBrowser(eff.URL); err != nil {
					o.Logger.Info("could not open the browser automatically: %v", err)
					fmt.Fprintf(os.Stderr, "\nOpen this URL to authenticate:\n  %s\n\n", eff.URL)
				}
				cb.Serve(o.SSOTimeout)
				samlCh = cb.Results()
			case reducer.ApplyDNS:
				b, err := o.Sys.ApplyDNS(eff.Servers)
				if err != nil {
					o.Logger.Info("warning: could not apply DNS %v: %v", eff.Servers, err)
					break
				}
				dnsBackup = b
				if err := state.SaveDNSBackup(b); err != nil {
					o.Logger.Info("warning: could not persist DNS backup: %v", err)
				}
				o.Logger.Info("applied pushed DNS: %v", eff.Servers)
			case reducer.Connected:
				o.Logger.Info("tunnel CONNECTED as %s", eff.Info.AssignedIP)
				return state.Run{
					Profile:     o.Profile.Name,
					OvpnPID:     pid,
					MgmtSocket:  sock,
					LogPath:     config.LogPath(),
					AssignedIP:  eff.Info.AssignedIP,
					RemoteIP:    eff.Info.RemoteIP,
					Port:        eff.Info.Port,
					ConnectedAt: time.Now(),
					DNS:         eff.Info.DNS,
					Routes:      eff.Info.Routes,
					FullTunnel:  eff.Info.FullTunnel,
				}, nil
			case reducer.Failed:
				if dnsBackup.ServiceID != "" {
					_ = o.Sys.RevertDNS(dnsBackup)
					_ = state.ClearDNSBackup()
				}
				return state.Run{}, fmt.Errorf("connection failed: %s", eff.Reason)
			}
		}
	}
}
