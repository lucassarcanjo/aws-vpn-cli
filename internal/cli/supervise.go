package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/daemon"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/mgmt"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/notify"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/privilege"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/state"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/supervisor"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
	"github.com/spf13/cobra"
)

// newSuperviseCmd is the hidden entry point launchd runs (as root) to watch a live
// tunnel. It is not meant to be invoked by hand — `connect` registers it and
// `disconnect` boots it out.
func newSuperviseCmd() *cobra.Command {
	var uid int
	var profileFlag string
	cmd := &cobra.Command{
		Use:    "supervise",
		Short:  "Internal: watch the active tunnel and clean up if it drops",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot("supervise", "to watch the tunnel"); err != nil {
				return err
			}
			return runSupervise(uid, profileFlag)
		},
	}
	cmd.Flags().IntVar(&uid, "uid", 0, "invoking user's uid (desktop-notification target session)")
	cmd.Flags().StringVar(&profileFlag, "profile", "", "profile being supervised (for ps/logs)")
	return cmd
}

// runSupervise attaches to the live tunnel's management channel and watches for a
// drop. On a drop that can't self-heal (or any signal that recovery would need
// re-authentication) it performs the fail-safe teardown and notifies the user.
func runSupervise(uid int, profileFlag string) error {
	// Log to the connection log so supervise events show up in `awsvpn logs`.
	logFile, err := os.OpenFile(config.LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	log := logging.New(logFile, logging.NewRedactor(), false)
	sys := system.NewReal(privilege.User{UID: uid})

	// A SIGTERM/SIGINT to *us* means "stop supervising" (e.g. `disconnect` booted
	// us out) — exit cleanly WITHOUT tearing down or notifying. Tunnel death is
	// detected separately, over the management channel. Handling it here is what
	// keeps a user-initiated disconnect from firing a bogus "connection lost".
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sigs; os.Exit(0) }()

	st := state.Default()
	run, ok, err := st.Run()
	if err != nil {
		return err
	}
	if !ok {
		log.Info("supervise: no active tunnel on record; nothing to do")
		return nil
	}
	profile := run.Profile
	if profile == "" {
		profile = profileFlag
	}
	if !(run.Alive() && sys.IsOpenVPN(run.OvpnPID)) {
		return giveUp(sys, st, log, uid, profile, "the tunnel process is no longer running")
	}

	// watchForDrop owns the management connection and closes it before returning,
	// so the teardown below (which dials a fresh management client to send
	// SIGTERM) isn't refused — openvpn's management accepts one client at a time.
	reason := watchForDrop(run, log)
	return giveUp(sys, st, log, uid, profile, reason)
}

// watchForDrop attaches to the live tunnel's management channel and blocks until
// it concludes the tunnel is gone (or beyond self-healing), returning a
// human-readable reason. It closes its own management connection before returning.
func watchForDrop(run state.Run, log *logging.Logger) string {
	client, err := mgmt.DialWatch(run.MgmtSocket, 10*time.Second)
	if err != nil {
		return "lost the management channel to the tunnel"
	}
	defer client.Close()
	log.Info("supervising %s (pid %d): will disconnect and notify if the tunnel drops", run.Profile, run.OvpnPID)

	// The Watcher decides; this loop owns only the socket and the real grace timer.
	var w supervisor.Watcher
	lines := client.Lines()
	var grace *time.Timer
	var graceC <-chan time.Time
	stopGrace := func() {
		if grace != nil {
			grace.Stop()
			grace, graceC = nil, nil
		}
	}
	for {
		var out supervisor.Outcome
		select {
		case line, ok := <-lines:
			if !ok {
				out = w.Closed()
			} else {
				out = w.Line(line)
			}
		case <-graceC:
			out = w.GraceExpired()
		}

		switch out.Action {
		case supervisor.Wait:
			// keep watching
		case supervisor.BeginGrace:
			log.Info("tunnel lost; waiting up to %s for it to recover on its own", supervisor.GraceWindow)
			grace = time.NewTimer(supervisor.GraceWindow)
			graceC = grace.C
		case supervisor.EndGrace:
			log.Info("tunnel recovered on its own; still connected")
			stopGrace()
		case supervisor.Teardown:
			stopGrace()
			return out.Reason
		}
	}
}

// giveUp runs the fail-safe teardown (revert DNS, remove routes, clear state) via
// the same path `disconnect` uses, then posts a desktop notification so the user
// knows the VPN is down and how to bring it back.
func giveUp(sys system.Port, st *state.Store, log *logging.Logger, uid int, profile, reason string) error {
	log.Info("disconnecting %s: %s", profile, reason)
	_, err := daemon.Disconnect(sys, st, log)
	msg := fmt.Sprintf("%s — %s. Reconnect with: %sawsvpn connect %s", profile, reason, sudoPrefix(), profile)
	if nerr := notify.Send(uid, "AWS VPN disconnected", msg); nerr != nil {
		log.Info("could not post desktop notification (no GUI session?): %v", nerr)
	}
	return err
}
