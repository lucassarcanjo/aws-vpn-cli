// Package daemon supervises the connect lifecycle: it verifies and spawns
// acvc-openvpn, drives the pure reducer over the management socket to CONNECTED,
// applies DNS, records the run so `status`/`disconnect` can control the
// background tunnel out-of-band, and cleans up stale state from a prior crash.
package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
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
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
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
	LogFile         *os.File    // acvc-openvpn's stdout/stderr sink (owned by the caller)
	UI              ui.Reporter // progress narration for the person waiting; nil is silent
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
	if o.UI == nil {
		o.UI = ui.Discard()
	}

	// A prior connection that already died leaves DNS pointed at an unreachable
	// resolver; clean that up first. A genuinely live one is swapped.
	CleanupStale(o.Sys, o.Logger)
	if r, ok, _ := state.Load(); ok && r.Alive() && o.Sys.IsOpenVPN(r.OvpnPID) {
		o.UI.Step("Stopping the tunnel to %s", r.Profile)
		o.Logger.Info("swapping active tunnel (%s → %s)", r.Profile, o.Profile.Name)
		if err := teardown(o.Sys, r, o.Logger); err != nil {
			o.Logger.Info("warning: could not cleanly stop the previous tunnel: %v", err)
			o.UI.Warn("could not cleanly stop the tunnel to %s: %v", r.Profile, err)
		} else {
			o.UI.OK("Stopped the tunnel to %s", r.Profile)
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
		o.UI.Warn("signature check skipped (--allow-unverified-binary)")
	} else {
		o.UI.Step("Checking the AWS VPN engine")
		if err := o.Sys.VerifySignature(config.ACVCOpenVPNPath, config.AWSTeamID); err != nil {
			return state.Run{}, err
		}
		o.UI.OK("AWS VPN engine verified (Apple team %s)", config.AWSTeamID)
	}

	o.UI.Step("Starting the VPN engine")
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
	o.UI.OK("VPN engine running (pid %d)", pid)

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

// ssoPrompt renders the sign-in block: the URL the user may need to paste
// somewhere else, and what their keyboard can do while we wait. The URL is
// dimmed — it is a thousand characters of base64 that nobody reads, but it has
// to stay on screen because `open` may have handed it to the wrong browser and
// pasting it is the way out (the log gets it only under --verbose).
func ssoPrompt(s ui.Styler, url string, timeout time.Duration, interactive bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s %s\n\n", s.Bold("Sign in to continue."),
		s.Dim("Your browser should have opened — waiting up to "+ui.Duration(timeout)+"."))
	fmt.Fprintf(&b, "  %s\n\n", s.Dim(url))
	if interactive {
		fmt.Fprintf(&b, "  %s\n\n", s.Dim("⏎ reopen the page   ·   c ⏎ copy the link   ·   ⌃C cancel"))
	}
	return b.String()
}

// handleSSOKey acts on a key typed during the sign-in wait: "c" copies the link
// to the clipboard (for the browser the user is actually signed in to), anything
// else re-opens the page. Both are safe to repeat — the callback listener stays
// bound for the whole window.
func (o Options) handleSSOKey(key, url string) {
	if key == "c" || key == "copy" {
		if err := o.Sys.CopyToClipboard(url); err != nil {
			o.Logger.Info("could not copy the sign-in link: %v", err)
			o.UI.Warn("could not copy the link (%v) — select it above instead", err)
		} else {
			o.Logger.Info("copied the sign-in link to the clipboard")
			o.UI.Note("Sign-in link copied to your clipboard")
		}
		return
	}
	o.Logger.Info("re-opening the sign-in page")
	if err := o.Sys.OpenBrowser(url); err != nil {
		o.Logger.Info("could not open the browser automatically: %v", err)
		o.UI.Warn("could not open your browser: %v", err)
		return
	}
	o.UI.Note("Reopened the sign-in page")
}

// watchKeys reports each line typed on stdin, so the connect loop can act on it
// while it waits for sign-in. Returns nil when stdin isn't a terminal (scripted
// or launchd-driven runs) — a nil channel simply never fires, and the prompt
// then omits the offer. The reader goroutine lives until the process exits;
// connect is short-lived, so there is nothing to unwind.
func watchKeys() <-chan string {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	ch := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			select {
			case ch <- strings.ToLower(strings.TrimSpace(sc.Text())):
			default: // one is already pending; coalesce impatient keys
			}
		}
	}()
	return ch
}

// drive is the event loop: it feeds management lines, the captured assertion, and
// an overall deadline into the pure reducer and performs the effects it emits.
func drive(o Options, client *mgmt.Client, pid int, sock string, cb *callback.Server) (state.Run, error) {
	st := reducer.Initial(config.CallbackPort)
	lines := client.Lines()
	var samlCh <-chan callback.Result
	var dnsBackup dns.Backup

	// Live only during the SSO window: the URL we handed the browser, and the
	// keypress channel that re-opens or copies it.
	var ssoURL string
	var keysCh <-chan string

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
		case key := <-keysCh:
			// The tab was closed, or `open` handed the URL to the wrong browser
			// (or the wrong Chrome profile). Re-open it, or put it on the
			// clipboard to paste into the browser they're actually signed in to:
			// the callback listener is still bound and the SSO window is still
			// running, so either costs nothing and saves a full reconnect.
			o.handleSSOKey(key, ssoURL)
			continue // not an event; nothing for the reducer to step on
		case res := <-samlCh:
			samlCh, keysCh = nil, nil // signed in; re-opening would hit a closed listener
			if res.Err != nil {
				o.Logger.Info("SSO did not complete: %v", res.Err)
				o.UI.Warn("sign-in did not complete: %v", res.Err)
				ev = reducer.Timeout{}
			} else {
				o.Logger.Redactor().Add(res.SAML) // never let it into a log
				o.Logger.Info("SAML assertion captured (%d bytes)", len(res.SAML))
				o.UI.OK("Signed in (assertion captured, %d bytes)", len(res.SAML))
				o.UI.Step("Bringing the tunnel up")
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
				o.Logger.Debug("SSO URL: %s", eff.URL)
				o.UI.Step("Waiting for you to sign in")
				if err := o.Sys.OpenBrowser(eff.URL); err != nil {
					o.Logger.Info("could not open the browser automatically: %v", err)
					o.UI.Warn("could not open your browser (%v) — use the link below", err)
				}
				// Whether or not the auto-open worked, keep the URL on screen for
				// the whole window: `open` may hand it to a browser (or a Chrome
				// profile) the user isn't signed in with, and once that tab is
				// closed there is otherwise nothing to go back to.
				ssoURL = eff.URL
				keysCh = watchKeys()
				o.UI.Block(ssoPrompt(o.UI.Styler(), eff.URL, o.SSOTimeout, keysCh != nil))
				cb.Serve(o.SSOTimeout)
				samlCh = cb.Results()
			case reducer.ApplyDNS:
				b, err := o.Sys.ApplyDNS(eff.Servers)
				if err != nil {
					o.Logger.Info("warning: could not apply DNS %v: %v", eff.Servers, err)
					o.UI.Warn("could not apply the pushed DNS %s: %v — internal names may not resolve",
						strings.Join(eff.Servers, ", "), err)
					break
				}
				dnsBackup = b
				if err := state.SaveDNSBackup(b); err != nil {
					o.Logger.Info("warning: could not persist DNS backup: %v", err)
					o.UI.Warn("could not record the DNS backup: %v — `disconnect` may not restore your resolver", err)
				}
				o.Logger.Info("applied pushed DNS: %v", eff.Servers)
				o.UI.Note("DNS now resolves through %s", strings.Join(eff.Servers, ", "))
			case reducer.Connected:
				o.Logger.Info("tunnel CONNECTED as %s", eff.Info.AssignedIP)
				o.UI.OK("Tunnel up as %s", eff.Info.AssignedIP)
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
