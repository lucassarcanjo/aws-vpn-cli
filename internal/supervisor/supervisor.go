// Package supervisor is the pure decision core for watching an already-CONNECTED
// tunnel. Like the connect reducer, it performs no I/O: it maps a single
// management line to a Verdict, and the runtime (cli.runSupervise) owns the socket
// and the grace timer. This keeps the "should we tear the tunnel down?" policy
// deterministic and testable against scripted management lines.
//
// The policy, from the agreed design:
//   - acvc-openvpn runs with --management-hold, so on any network-drop restart it
//     re-enters hold and waits for a management client to release it and hand it
//     fresh credentials. We deliberately do NOT release it: with AWS SAML every
//     real reconnect needs a brand-new browser SSO (a re-issued CRV1 challenge is
//     terminal, see reducer.go), which a root background daemon must not attempt.
//   - So a hold / password prompt / verification-failed after CONNECTED means
//     "re-auth required" → give up now (clean teardown + notify; the user
//     reconnects). A plain RECONNECTING opens a short grace window in case the
//     tunnel resurfaces on its own without a full re-auth; if it doesn't recover
//     within GraceWindow, give up.
package supervisor

import (
	"fmt"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/ovpn"
)

// GraceWindow bounds how long we wait for a RECONNECTING tunnel to come back to
// CONNECTED on its own before tearing it down. It is a single settle window, not
// a re-auth retry count: a hold/credential prompt (the AWS drop signal) ends it
// immediately. Kept short so a genuine outage restores the user's normal DNS and
// routing quickly rather than leaving traffic pointed into a dead tunnel.
const GraceWindow = 60 * time.Second

// Verdict is what a single management line implies for a live tunnel.
type Verdict int

const (
	// Watching: nothing that changes our posture (byte counts, log spam, states
	// we don't act on).
	Watching Verdict = iota
	// Reconnecting: the tunnel dropped and openvpn is restarting; start (or keep)
	// the grace window.
	Reconnecting
	// Reauth: openvpn re-entered the credential handshake — recovery needs a fresh
	// browser SSO we won't perform in the background. Give up now.
	Reauth
	// Recovered: back to CONNECTED; cancel any grace window.
	Recovered
	// Down: the tunnel exited or hit a fatal error. Give up now.
	Down
)

// String renders a Verdict for logs.
func (v Verdict) String() string {
	switch v {
	case Reconnecting:
		return "reconnecting"
	case Reauth:
		return "reauth"
	case Recovered:
		return "recovered"
	case Down:
		return "down"
	default:
		return "watching"
	}
}

// Classify maps one management line to a Verdict. Pure: no clock, no I/O.
func Classify(line string) Verdict {
	if name, ok := ovpn.StateName(line); ok {
		switch name {
		case "CONNECTED":
			return Recovered
		case "RECONNECTING":
			return Reconnecting
		case "EXITING":
			return Down
		default:
			return Watching
		}
	}
	switch {
	// A hold or a fresh credential prompt after we were connected means openvpn
	// restarted and wants to re-authenticate — which for AWS SAML requires the
	// browser. That is our give-up signal.
	case ovpn.IsHold(line), ovpn.IsPasswordNeed(line), ovpn.IsVerificationFailed(line):
		return Reauth
	case ovpn.IsFatal(line):
		return Down
	}
	return Watching
}

// Give-up reasons, kept here (next to the policy) so the runtime and its tests
// share one source of truth for the user-facing message.
const (
	reasonReauth = "the VPN session ended and needs re-authentication"
	reasonDown   = "the tunnel went down"
	reasonClosed = "the tunnel closed unexpectedly"
)

func reasonNoRecovery() string {
	return fmt.Sprintf("the tunnel did not recover within %s", GraceWindow)
}

// Action is what the runtime should do in response to an event. The runtime owns
// the socket and the real grace timer; the Watcher only decides.
type Action int

const (
	// Wait: keep watching, no timer change.
	Wait Action = iota
	// BeginGrace: the tunnel just dropped; start the grace window.
	BeginGrace
	// EndGrace: the tunnel came back on its own; cancel the grace window.
	EndGrace
	// Teardown: give up — tear the tunnel down. Outcome.Reason says why.
	Teardown
)

// Outcome pairs an Action with a give-up reason (set only when Action is Teardown).
type Outcome struct {
	Action Action
	Reason string
}

// Watcher turns the stream of management events for an already-CONNECTED tunnel
// into teardown decisions, tracking only whether the grace window is open. Pure
// and deterministic: driven by Line/Closed/GraceExpired, it never touches a socket
// or a clock, mirroring the connect reducer so the drop policy is testable by
// scripting an event sequence.
type Watcher struct {
	inGrace bool
}

// Line advances the Watcher on one management line.
func (w *Watcher) Line(line string) Outcome {
	switch Classify(line) {
	case Recovered:
		if w.inGrace {
			w.inGrace = false
			return Outcome{Action: EndGrace}
		}
		return Outcome{Action: Wait}
	case Reconnecting:
		if w.inGrace {
			return Outcome{Action: Wait} // already counting down; don't restart it
		}
		w.inGrace = true
		return Outcome{Action: BeginGrace}
	case Reauth:
		return Outcome{Action: Teardown, Reason: reasonReauth}
	case Down:
		return Outcome{Action: Teardown, Reason: reasonDown}
	default:
		return Outcome{Action: Wait}
	}
}

// Closed reports that the management stream ended (openvpn exited).
func (w *Watcher) Closed() Outcome {
	return Outcome{Action: Teardown, Reason: reasonClosed}
}

// GraceExpired reports that the grace window elapsed without the tunnel recovering.
func (w *Watcher) GraceExpired() Outcome {
	return Outcome{Action: Teardown, Reason: reasonNoRecovery()}
}
