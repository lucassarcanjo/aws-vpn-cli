// Package reducer is the pure heart of the connect lifecycle: a state machine of
// the form step(state, event) -> (state, []effect). It holds every
// credential- and handshake-bearing decision but performs no I/O, so the whole
// SAML→CRV1 dance is deterministic and testable by feeding it a scripted event
// sequence and asserting the emitted effects — including the real management
// transcript captured from a live endpoint.
//
// The proven handshake it encodes (from the spike):
//   - First auth sends username "N/A", password "ACS::35001" (declares the
//     callback port to the endpoint).
//   - The endpoint replies with a CRV1 challenge carrying the SAML URL.
//   - acvc-openvpn soft-restarts and re-enters hold on every restart, so we
//     release the hold on *every* >HOLD notification, not once.
//   - After reconnect we answer the next >PASSWORD:Need with username "N/A",
//     password "CRV1::<state>::<url-encoded-SAMLResponse>".
//   - >STATE:...,CONNECTED,... is success.
package reducer

import (
	"fmt"
	"net/url"

	"github.com/larcanjo/awsvpn/internal/ovpn"
)

// Phase is where we are in the handshake.
type Phase int

const (
	// PhaseInit: connected to management, awaiting the first credential prompt.
	PhaseInit Phase = iota
	// PhaseAwaitChallenge: sent the dummy first-auth creds, awaiting the CRV1
	// challenge that carries the SAML URL.
	PhaseAwaitChallenge
	// PhaseAwaitSAML: browser opened; awaiting both the captured SAML assertion
	// and the second credential prompt (they can arrive in either order).
	PhaseAwaitSAML
	// PhaseConnecting: submitted the SAML/CRV1 response, awaiting CONNECTED.
	PhaseConnecting
	// PhaseConnected is terminal success.
	PhaseConnected
	// PhaseFailed is terminal failure.
	PhaseFailed
)

// State is the reducer's immutable-by-convention state. Callers thread it
// through Step; fields are unexported so the only way to build one is Initial,
// keeping the type a black box driven purely by events.
type State struct {
	phase        Phase
	callbackPort int

	crv1State string // opaque session id echoed back in the CRV1 response
	samlURL   string
	saml      string // captured assertion (in memory only)
	realm     string // credential realm, e.g. "Auth"
	needAuth  bool   // saw the second >PASSWORD:Need prompt

	dns        []string
	routes     []ovpn.Route
	fullTunnel bool

	failReason string
}

// Initial returns the starting state, parameterised by the SAML callback port so
// the reducer needs no global configuration.
func Initial(callbackPort int) State {
	return State{phase: PhaseInit, callbackPort: callbackPort}
}

// Phase exposes the current phase (for the runtime and tests).
func (s State) Phase() Phase { return s.phase }

// FailReason returns why the handshake failed (empty unless PhaseFailed).
func (s State) FailReason() string { return s.failReason }

// Event is one input to the reducer.
type Event interface{ isEvent() }

// MgmtLine is a single line read from the openvpn management channel.
type MgmtLine struct{ Line string }

// SAMLCaptured is the assertion received on the one-shot callback.
type SAMLCaptured struct{ Raw string }

// Timeout fires when SSO/authentication takes too long.
type Timeout struct{}

func (MgmtLine) isEvent()     {}
func (SAMLCaptured) isEvent() {}
func (Timeout) isEvent()      {}

// Effect is one side effect the runtime must perform.
type Effect interface{ isEffect() }

// SendMgmt writes a command to the management channel (already includes any
// secret; the logging layer redacts before writing to a log).
type SendMgmt struct{ Cmd string }

// OpenBrowser opens the SAML URL in the invoking user's browser.
type OpenBrowser struct{ URL string }

// ApplyDNS sets the pushed DNS servers as the macOS resolver.
type ApplyDNS struct{ Servers []string }

// Connected signals the tunnel is up, carrying details for `status`.
type Connected struct{ Info ConnInfo }

// Failed signals a terminal failure with a human-readable reason.
type Failed struct{ Reason string }

func (SendMgmt) isEffect()    {}
func (OpenBrowser) isEffect() {}
func (ApplyDNS) isEffect()    {}
func (Connected) isEffect()   {}
func (Failed) isEffect()      {}

// ConnInfo describes a live tunnel.
type ConnInfo struct {
	AssignedIP string
	RemoteIP   string
	Port       string
	DNS        []string
	Routes     []ovpn.Route
	FullTunnel bool
}

// Step applies one event to the state and returns the next state plus the
// effects to perform. It is a pure function: no globals, no I/O, no clock.
func Step(s State, e Event) (State, []Effect) {
	if s.phase == PhaseConnected || s.phase == PhaseFailed {
		return s, nil // terminal: ignore further events
	}
	switch ev := e.(type) {
	case MgmtLine:
		return stepLine(s, ev.Line)
	case SAMLCaptured:
		return stepSAML(s, ev.Raw)
	case Timeout:
		return fail(s, "timed out waiting for SSO authentication")
	default:
		return s, nil
	}
}

func stepLine(s State, line string) (State, []Effect) {
	switch {
	// Release the hold on every notification — the engine re-holds on each soft
	// restart during the CRV1 dance.
	case ovpn.IsHold(line):
		return s, []Effect{SendMgmt{Cmd: "hold release"}}

	// CONNECTED is success in any phase.
	case isConnected(line):
		return connected(s, line)

	// Capture DNS/routes from the pushed config so we can apply DNS on CONNECTED.
	case ovpn.IsPushReply(line):
		if pr, ok := ovpn.ParsePushReply(line); ok {
			s.dns, s.routes, s.fullTunnel = pr.DNS, pr.Routes, pr.FullTunnel
		}
		return s, nil

	// Hard, terminal failures.
	case ovpn.IsFatal(line) || ovpn.IsAuthFailed(line) || isExiting(line):
		return fail(s, "openvpn reported a fatal error before the tunnel came up")

	// A rejected credential: either the expected CRV1 challenge (first attempt)
	// or a genuine rejection (SAML expired / wrong endpoint).
	case ovpn.IsVerificationFailed(line):
		if c, ok := ovpn.ParseCRV1Challenge(line); ok {
			if s.phase == PhaseAwaitChallenge {
				s.crv1State = c.State
				s.samlURL = c.SAMLURL
				s.phase = PhaseAwaitSAML
				return s, []Effect{OpenBrowser{URL: c.SAMLURL}}
			}
			// A CRV1 challenge arriving after we already answered means the
			// endpoint re-issued auth (assertion expired mid-flow). v1 does not
			// auto-reauthenticate; report it clearly so the user reconnects.
			return fail(s, "the VPN endpoint issued a new SAML challenge (session expired) — reconnect")
		}
		return fail(s, "the VPN endpoint rejected authentication")

	// A fresh credential prompt.
	case ovpn.IsPasswordNeed(line):
		return stepPasswordNeed(s, line)
	}
	return s, nil
}

func stepPasswordNeed(s State, line string) (State, []Effect) {
	realm := ovpn.ParsePasswordRealm(line)
	switch s.phase {
	case PhaseInit, PhaseAwaitChallenge:
		// First attempt (or a re-prompt before the challenge arrived, e.g. the
		// engine's auth window expired and it soft-restarted): send the dummy
		// creds that declare our callback port. Re-sending is idempotent; an
		// endpoint that never challenges is bounded by the connect deadline.
		s.phase = PhaseAwaitChallenge
		s.realm = realm
		return s, []Effect{
			SendMgmt{Cmd: cred("username", realm, "N/A")},
			SendMgmt{Cmd: cred("password", realm, fmt.Sprintf("ACS::%d", s.callbackPort))},
		}
	case PhaseAwaitSAML:
		// Second prompt after the soft restart. If the assertion is already in
		// hand, answer now; otherwise wait for SAMLCaptured.
		s.needAuth = true
		s.realm = realm
		if s.saml != "" {
			return submitSAML(s)
		}
		return s, nil
	default:
		return s, nil
	}
}

func stepSAML(s State, raw string) (State, []Effect) {
	s.saml = raw
	// If the second prompt already arrived, submit; otherwise hold the assertion
	// until it does.
	if s.phase == PhaseAwaitSAML && s.needAuth {
		return submitSAML(s)
	}
	return s, nil
}

// submitSAML answers the auth prompt with the CRV1 response carrying the
// url-encoded assertion, then advances to PhaseConnecting.
func submitSAML(s State) (State, []Effect) {
	password := "CRV1::" + s.crv1State + "::" + url.QueryEscape(s.saml)
	s.phase = PhaseConnecting
	return s, []Effect{
		SendMgmt{Cmd: cred("username", s.realm, "N/A")},
		SendMgmt{Cmd: cred("password", s.realm, password)},
	}
}

func connected(s State, line string) (State, []Effect) {
	ci, _ := ovpn.ParseConnected(line)
	info := ConnInfo{
		AssignedIP: ci.AssignedIP,
		RemoteIP:   ci.RemoteIP,
		Port:       ci.Port,
		DNS:        s.dns,
		Routes:     s.routes,
		FullTunnel: s.fullTunnel,
	}
	s.phase = PhaseConnected
	effects := make([]Effect, 0, 2)
	if len(s.dns) > 0 {
		effects = append(effects, ApplyDNS{Servers: s.dns})
	}
	effects = append(effects, Connected{Info: info})
	return s, effects
}

func fail(s State, reason string) (State, []Effect) {
	s.phase = PhaseFailed
	s.failReason = reason
	return s, []Effect{Failed{Reason: reason}}
}

// cred renders a management username/password command:  password "Auth" "<v>".
// Values from this handshake never contain a double quote, so simple quoting is
// safe. The password variant may carry the assertion; the logging layer redacts.
func cred(kind, realm, value string) string {
	return fmt.Sprintf("%s %q %q", kind, realm, value)
}

func isConnected(line string) bool {
	_, ok := ovpn.ParseConnected(line)
	return ok
}

func isExiting(line string) bool {
	name, ok := ovpn.StateName(line)
	return ok && name == "EXITING"
}
