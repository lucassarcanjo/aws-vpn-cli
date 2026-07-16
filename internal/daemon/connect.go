// Package daemon supervises the connect lifecycle: it verifies and spawns
// acvc-openvpn, drives the pure reducer over the management socket to CONNECTED,
// applies DNS, records the run so `status`/`disconnect` can control the
// background tunnel out-of-band, and cleans up stale state from a prior crash.
package daemon

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/larcanjo/awsvpn/internal/callback"
	"github.com/larcanjo/awsvpn/internal/config"
	"github.com/larcanjo/awsvpn/internal/dns"
	"github.com/larcanjo/awsvpn/internal/logging"
	"github.com/larcanjo/awsvpn/internal/mgmt"
	"github.com/larcanjo/awsvpn/internal/privilege"
	"github.com/larcanjo/awsvpn/internal/profile"
	"github.com/larcanjo/awsvpn/internal/reducer"
	"github.com/larcanjo/awsvpn/internal/state"
	"github.com/larcanjo/awsvpn/internal/system"
)

// DefaultSSOTimeout bounds how long we wait for the user to complete SSO.
const DefaultSSOTimeout = 3 * time.Minute

// Options configures a connect.
type Options struct {
	Home            string
	User            privilege.User
	Profile         profile.Profile
	Sys             system.Port
	Logger          *logging.Logger
	LogFile         *os.File // acvc-openvpn's stdout/stderr sink (owned by the caller)
	AllowUnverified bool
	SSOTimeout      time.Duration
}

// Connect brings up the tunnel and returns once it reaches CONNECTED, leaving
// acvc-openvpn running in the background. It is the single entry point for the
// `connect` command.
func Connect(o Options) (state.Run, error) {
	if o.SSOTimeout == 0 {
		o.SSOTimeout = DefaultSSOTimeout
	}

	// A prior connection that already died leaves DNS pointed at an unreachable
	// resolver; clean that up before we start. A still-live one is swapped.
	CleanupStale(o.Home, o.Sys, o.Logger)
	if r, ok, _ := state.Load(o.Home); ok && r.Alive() {
		o.Logger.Info("swapping active tunnel (%s → %s)", r.Profile, o.Profile.Name)
		if err := teardown(o.Home, o.Sys, r, o.Logger); err != nil {
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

	// Verify the AWS signature right before we run the binary as root.
	if o.AllowUnverified {
		o.Logger.Info("WARNING: --allow-unverified-binary set; skipping signature verification")
	} else if err := o.Sys.VerifySignature(config.ACVCOpenVPNPath, config.AWSTeamID); err != nil {
		return state.Run{}, err
	}

	sock := config.MgmtSocketPath(o.Home)
	_ = os.Remove(sock) // clear any stale socket

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

	client, err := mgmt.Dial(sock, 10*time.Second)
	if err != nil {
		_ = o.Sys.Kill(pid)
		return state.Run{}, err
	}
	defer client.Close()

	run, err := drive(o, client, cb, pid, sock)
	if err != nil {
		_ = o.Sys.Kill(pid)
		// Immediately restore DNS if the attempt applied it before failing,
		// rather than leaving it for the next run's crash cleanup.
		revertDNS(o.Home, o.Sys, o.Logger)
		return state.Run{}, err
	}
	if err := state.Save(o.Home, run); err != nil {
		return state.Run{}, fmt.Errorf("recording connection state: %w", err)
	}
	// Hand freshly-written state/log files back to the user.
	_ = o.User.ChownTree(config.StateDir(o.Home))
	return run, nil
}

// PrepareLog opens (truncating) the connection log file and hands it back to the
// invoking user so their non-sudo `awsvpn logs` can read it. The caller owns the
// returned file; acvc-openvpn inherits the fd and keeps writing after the connect
// command exits.
func PrepareLog(home string, u privilege.User) (*os.File, error) {
	if err := os.MkdirAll(config.StateDir(home), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(config.LogPath(home), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	_ = u.Chown(config.LogPath(home))
	return f, nil
}

// drive is the event loop: it feeds management lines and the captured assertion
// into the pure reducer and performs the effects the reducer emits.
func drive(o Options, client *mgmt.Client, cb *callback.Server, pid int, sock string) (state.Run, error) {
	st := reducer.Initial(config.CallbackPort)
	lines := client.Lines()
	var samlCh <-chan callback.Result
	var dnsBackup dns.Backup

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
				// Persist immediately so a death before CONNECTED is still
				// revertible on the next run.
				if err := state.SaveDNSBackup(o.Home, b); err != nil {
					o.Logger.Info("warning: could not persist DNS backup: %v", err)
				}
				o.Logger.Info("applied pushed DNS: %v", eff.Servers)
			case reducer.Connected:
				o.Logger.Info("tunnel CONNECTED as %s", eff.Info.AssignedIP)
				return state.Run{
					Profile:     o.Profile.Name,
					OvpnPID:     pid,
					MgmtSocket:  sock,
					LogPath:     config.LogPath(o.Home),
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
					_ = state.ClearDNSBackup(o.Home)
				}
				return state.Run{}, fmt.Errorf("connection failed: %s", eff.Reason)
			}
		}
	}
}
