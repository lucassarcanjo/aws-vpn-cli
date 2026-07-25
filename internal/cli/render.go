package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/state"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
)

// runFields is the shape of a live tunnel, shared by `connect`'s closing summary
// and `status` so the same connection reads the same way in both places.
func runFields(r state.Run, withUptime bool) []ui.Field {
	f := []ui.Field{
		{Label: "IP", Value: r.AssignedIP},
		{Label: "endpoint", Value: endpoint(r)},
		{Label: "DNS", Value: strings.Join(r.DNS, ", ")},
		{Label: "mode", Value: tunnelMode(r)},
	}
	if withUptime {
		f = append(f, ui.Field{Label: "uptime", Value: ui.Duration(r.Duration())})
	}
	return f
}

func endpoint(r state.Run) string {
	if r.RemoteIP == "" {
		return ""
	}
	if r.Port == "" {
		return r.RemoteIP
	}
	return r.RemoteIP + ":" + r.Port
}

func tunnelMode(r state.Run) string {
	if r.FullTunnel {
		return "full-tunnel"
	}
	return "split-tunnel"
}

// printConnected closes a successful `connect`: what you got, and what to do
// with it. Supervised says whether the drop-watcher took, since that changes
// what we can promise about an unattended tunnel.
func printConnected(w io.Writer, r state.Run, supervised bool) {
	s := ui.For(w)
	fmt.Fprintf(w, "\n%s %s\n\n", s.Green(ui.CheckMark), s.Bold("Connected to "+r.Profile))
	s.Fields(w, runFields(r, false)...)
	fmt.Fprintln(w)
	ui.Hint(w, "Your shell is free — the tunnel runs in the background.")
	if supervised {
		ui.Hint(w, "If it drops, it is torn down automatically and you'll be notified.")
	}
	fmt.Fprintln(w)
	s.Fields(w,
		ui.Field{Label: "status", Value: s.Dim("awsvpn status")},
		ui.Field{Label: "logs", Value: s.Dim("awsvpn logs -f")},
		ui.Field{Label: "stop", Value: s.Dim("sudo awsvpn disconnect")},
	)
}

// printStatus renders the connection state as a glanceable block: a coloured
// dot for the state, then the details only when there are details to give.
func printStatus(w io.Writer, r state.Run, live bool) {
	s := ui.For(w)
	switch {
	case r.Profile == "":
		fmt.Fprintf(w, "%s %s\n", s.Dim(ui.Ring), s.Dim("disconnected"))
		ui.Hint(w, "Connect with: sudo awsvpn connect")
	case live:
		fmt.Fprintf(w, "%s %s  %s\n\n", s.Green(ui.Bullet), s.Green("connected"), s.Bold(r.Profile))
		s.Fields(w, runFields(r, true)...)
	case r.Connecting():
		fmt.Fprintf(w, "%s %s  %s\n", s.Yellow(ui.Bullet), s.Yellow("connecting"), s.Bold(r.Profile))
		ui.Hint(w, "A handshake is in progress, or was interrupted.")
	default:
		fmt.Fprintf(w, "%s %s  %s\n", s.Yellow(ui.WarnMark), s.Yellow("stale"), s.Bold(r.Profile))
		ui.Hint(w, "Recorded, but its process is gone. Clean up with: sudo awsvpn disconnect")
	}
}

// statusJSON is the machine-readable face of `status`: a flat, stable shape for
// scripts and agents, so the human rendering above is free to change.
type statusJSON struct {
	State         string   `json:"state"` // connected | connecting | stale | disconnected
	Profile       string   `json:"profile,omitempty"`
	AssignedIP    string   `json:"assigned_ip,omitempty"`
	Endpoint      string   `json:"endpoint,omitempty"`
	DNS           []string `json:"dns,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	UptimeSeconds int      `json:"uptime_seconds,omitempty"`
	PID           int      `json:"pid,omitempty"`
	LogPath       string   `json:"log_path,omitempty"`
}

func printStatusJSON(w io.Writer, r state.Run, live bool) error {
	out := statusJSON{State: "disconnected"}
	if r.Profile != "" {
		out = statusJSON{
			State:      statusState(r, live),
			Profile:    r.Profile,
			AssignedIP: r.AssignedIP,
			Endpoint:   endpoint(r),
			DNS:        r.DNS,
			Mode:       tunnelMode(r),
			PID:        r.OvpnPID,
			LogPath:    r.LogPath,
		}
		if live {
			out.UptimeSeconds = int(r.Duration().Seconds())
		}
	}
	return writeJSON(w, out)
}

func statusState(r state.Run, live bool) string {
	switch {
	case live:
		return "connected"
	case r.Connecting():
		return "connecting"
	default:
		return "stale"
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// fail prints an error the way the command surface should end: the problem on
// one line, and any guidance we attached to it kept underneath.
func fail(err error) {
	ui.Fail(os.Stderr, err)
}
