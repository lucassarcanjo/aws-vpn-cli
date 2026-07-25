package reducer

import (
	"net/url"
	"strings"
	"testing"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/fixture"
)

// Management lines captured by the spike against a live endpoint. The shape is
// verbatim; addresses, endpoint ids, and session ids are synthetic. They live in
// internal/fixture so the mgmt and daemon suites drive the same transcript —
// one source of truth for the handshake contract, and one place to sanitise.
var (
	fx = fixture.Handshake()

	lineHold0        = fx.Line("hold0")
	lineHold1        = fx.Line("hold1")
	lineNeed         = fx.Line("need")
	lineReconn       = fx.Line("reconn")
	lineWait         = fx.Line("wait")
	lineConnect      = fx.Line("connect")
	linePushReply    = fx.Line("pushReply")
	lineAuthFailed   = fx.Line("authFailed")
	lineChallenge    = fx.Line("challenge")
	lineChallengeLog = fx.Line("challengeLog")

	realState        = fx.Line("realState")
	samlURL          = fx.Line("samlURL")
	rawSAMLAssertion = fx.Line("rawSAML")
)

// TestFixtureAtomsAreConsistent guards the one redundancy in handshake.txt: the
// challenge line is stored whole, and its state id and SAML URL are also stored
// separately for assertions. If they ever drift apart, every assertion built on
// the atoms would be testing something the reducer never saw.
func TestFixtureAtomsAreConsistent(t *testing.T) {
	if !strings.Contains(lineChallenge, realState) {
		t.Errorf("challenge line does not contain realState %q", realState)
	}
	if !strings.Contains(lineChallenge, samlURL) {
		t.Errorf("challenge line does not contain samlURL %q", samlURL)
	}
	if !strings.Contains(lineChallengeLog, realState) {
		t.Errorf("challenge log line does not contain realState %q", realState)
	}
}

// runner threads events through Step and accumulates every emitted effect.
type runner struct {
	state   State
	effects []Effect
}

func newRunner() *runner { return &runner{state: Initial(35001)} }

func (r *runner) send(events ...Event) *runner {
	for _, e := range events {
		var fx []Effect
		r.state, fx = Step(r.state, e)
		r.effects = append(r.effects, fx...)
	}
	return r
}

func (r *runner) line(l string) *runner { return r.send(MgmtLine{Line: l}) }

// sendMgmtCmds returns every SendMgmt command in order.
func (r *runner) sendMgmtCmds() []string {
	var out []string
	for _, e := range r.effects {
		if c, ok := e.(SendMgmt); ok {
			out = append(out, c.Cmd)
		}
	}
	return out
}

func (r *runner) firstBrowserURL() (string, bool) {
	for _, e := range r.effects {
		if b, ok := e.(OpenBrowser); ok {
			return b.URL, true
		}
	}
	return "", false
}

// TestFixture1_RealTranscript drives the reducer with the exact sequence the
// spike captured — challenge, hold-release-on-restart, SAML-after-second-prompt,
// the ~10KB assertion over the socket, CONNECTED — and asserts the whole effect
// stream. This is the golden fixture: if the handshake contract regresses, this
// breaks.
func TestFixture1_RealTranscript(t *testing.T) {
	r := newRunner()
	r.line(lineHold0). // first hold  -> release
				line(lineNeed).                            // first prompt -> dummy creds (ACS::35001)
				line(lineChallenge).                       // CRV1 challenge -> open browser
				line(lineReconn).                          // soft restart (ignored)
				line(lineHold1).                           // re-hold    -> release again
				line(lineNeed).                            // second prompt (assertion not yet in hand)
				send(SAMLCaptured{Raw: rawSAMLAssertion}). // assertion -> CRV1 response
				line(lineWait).
				line(linePushReply). // captures DNS 10.0.0.2
				line(lineConnect)    // -> ApplyDNS + Connected

	if r.state.Phase() != PhaseConnected {
		t.Fatalf("final phase = %v, want Connected (%v); fail=%q", r.state.Phase(), PhaseConnected, r.state.FailReason())
	}

	cmds := r.sendMgmtCmds()
	wantExactSubset := []string{
		"hold release",
		`username "Auth" "N/A"`,
		`password "Auth" "ACS::35001"`,
		"hold release",
		`username "Auth" "N/A"`,
	}
	for i, want := range wantExactSubset {
		if i >= len(cmds) || cmds[i] != want {
			t.Fatalf("mgmt cmd[%d] = %q, want %q\nall: %v", i, safeIdx(cmds, i), want, cmds)
		}
	}

	// The CRV1 response is the last mgmt command: the assertion, url-encoded,
	// bound to the exact state id from the challenge.
	last := cmds[len(cmds)-1]
	wantPassword := `password "Auth" "CRV1::` + realState + `::` + url.QueryEscape(rawSAMLAssertion) + `"`
	if last != wantPassword {
		t.Fatalf("CRV1 response cmd =\n  %q\nwant\n  %q", last, wantPassword)
	}
	// Sanity: the assertion really was url-encoded (its +,/,= turned into %XX).
	if strings.Contains(last, rawSAMLAssertion) {
		t.Error("assertion was sent raw, not url-encoded")
	}

	// Browser opened to the challenge's SAML URL.
	if got, ok := r.firstBrowserURL(); !ok || got != samlURL {
		t.Errorf("browser URL = %q (ok=%v), want %q", got, ok, samlURL)
	}

	// DNS applied and Connected info correct.
	var dns *ApplyDNS
	var conn *Connected
	for i := range r.effects {
		switch e := r.effects[i].(type) {
		case ApplyDNS:
			dns = &e
		case Connected:
			conn = &e
		}
	}
	if dns == nil || len(dns.Servers) != 1 || dns.Servers[0] != "10.0.0.2" {
		t.Errorf("ApplyDNS = %+v, want [10.0.0.2]", dns)
	}
	if conn == nil {
		t.Fatal("no Connected effect")
	}
	if conn.Info.AssignedIP != "10.8.0.133" {
		t.Errorf("assigned IP = %q, want 10.8.0.133", conn.Info.AssignedIP)
	}
	if conn.Info.RemoteIP != "203.0.113.10" || conn.Info.Port != "443" {
		t.Errorf("endpoint = %q:%q, want 203.0.113.10:443", conn.Info.RemoteIP, conn.Info.Port)
	}
	if len(conn.Info.Routes) != 2 {
		t.Errorf("routes = %+v, want 2", conn.Info.Routes)
	}
}

// TestSAMLBeforeSecondPrompt covers the other ordering the spike flagged: the
// assertion arrives before the second >PASSWORD:Need. The reducer must hold it,
// then submit when the prompt lands.
func TestSAMLBeforeSecondPrompt(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(lineChallenge).
		line(lineReconn).
		line(lineHold1).
		send(SAMLCaptured{Raw: rawSAMLAssertion}). // arrives BEFORE the prompt
		line(lineNeed).                            // now submit
		line(linePushReply).
		line(lineConnect)

	if r.state.Phase() != PhaseConnected {
		t.Fatalf("phase = %v, want Connected; fail=%q", r.state.Phase(), r.state.FailReason())
	}
	cmds := r.sendMgmtCmds()
	last := cmds[len(cmds)-1]
	if !strings.HasPrefix(last, `password "Auth" "CRV1::`+realState+`::`) {
		t.Errorf("expected CRV1 response as last cmd, got %q", last)
	}
}

// TestRepeatNeedBeforeChallenge: if the engine re-prompts for credentials before
// the CRV1 challenge arrives (e.g. its auth window expired and it soft-restarted),
// the reducer must re-send the dummy creds, not silently ignore the prompt.
func TestRepeatNeedBeforeChallenge(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).   // first prompt -> ACS creds
		line(lineReconn). // soft restart, no challenge delivered
		line(lineHold1).  // re-hold -> release
		line(lineNeed)    // re-prompt in PhaseAwaitChallenge -> must re-send ACS creds

	cmds := r.sendMgmtCmds()
	// Expect the ACS password to have been sent twice (once per Need).
	acs := 0
	for _, c := range cmds {
		if c == `password "Auth" "ACS::35001"` {
			acs++
		}
	}
	if acs != 2 {
		t.Fatalf("ACS creds sent %d times, want 2 (re-prompt must be answered): %v", acs, cmds)
	}
	if r.state.Phase() != PhaseAwaitChallenge {
		t.Errorf("phase = %v, want AwaitChallenge", r.state.Phase())
	}
}

// TestLateReChallengeFails: a CRV1 challenge arriving after we already submitted
// the assertion (session expired mid-flow) fails with a clear reconnect message,
// not a misleading "rejected" one, and does not loop.
func TestLateReChallengeFails(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).line(lineNeed).line(lineChallenge).line(lineHold1).
		line(lineNeed).send(SAMLCaptured{Raw: rawSAMLAssertion}). // now PhaseConnecting
		line(lineChallenge)                                       // a fresh challenge arrives late

	if r.state.Phase() != PhaseFailed {
		t.Fatalf("phase = %v, want Failed", r.state.Phase())
	}
	if !strings.Contains(r.state.FailReason(), "session expired") {
		t.Errorf("fail reason = %q, want a session-expired/reconnect message", r.state.FailReason())
	}
}

// TestChallengeLogLineNotFatal: the live transcript delivers the CRV1 challenge
// twice — first as the AUTH_FAILED,CRV1 control message echoed on a >LOG: line,
// then as the >PASSWORD:Verification Failed notification. The >LOG: variant must
// be ignored (not treated as a hard AUTH_FAILED, and not answered — the
// >PASSWORD: line is the single trigger for the browser), and the flow must
// still reach Connected.
func TestChallengeLogLineNotFatal(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(lineChallengeLog). // logged control message — must be a no-op
		line(lineChallenge).    // the real trigger -> open browser
		line(lineReconn).
		line(lineHold1).
		line(lineNeed).
		send(SAMLCaptured{Raw: rawSAMLAssertion}).
		line(linePushReply).
		line(lineConnect)

	if r.state.Phase() != PhaseConnected {
		t.Fatalf("phase = %v, want Connected; fail=%q", r.state.Phase(), r.state.FailReason())
	}
	browsers := 0
	for _, e := range r.effects {
		if _, ok := e.(OpenBrowser); ok {
			browsers++
		}
	}
	if browsers != 1 {
		t.Errorf("browser opened %d times, want exactly 1", browsers)
	}
}

// TestHardAuthFailure: a hard AUTH_FAILED (no CRV1) on the first attempt fails.
func TestHardAuthFailure(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(lineAuthFailed)

	if r.state.Phase() != PhaseFailed {
		t.Fatalf("phase = %v, want Failed", r.state.Phase())
	}
	if !hasFailed(r.effects) {
		t.Error("expected a Failed effect")
	}
}

// TestVerificationFailedNonCRV1 fails when a rejection carries no CRV1 challenge.
func TestVerificationFailedNonCRV1(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(`>PASSWORD:Verification Failed: 'Auth'`) // rejection, no challenge

	if r.state.Phase() != PhaseFailed {
		t.Fatalf("phase = %v, want Failed", r.state.Phase())
	}
}

// TestSSOTimeout: browser opened but SSO never completes -> Timeout -> Failed.
func TestSSOTimeout(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(lineChallenge). // browser opened, now waiting for SAML
		send(Timeout{})

	if r.state.Phase() != PhaseFailed {
		t.Fatalf("phase = %v, want Failed", r.state.Phase())
	}
	if !hasFailed(r.effects) {
		t.Error("expected a Failed effect on timeout")
	}
	if !strings.Contains(r.state.FailReason(), "timed out") {
		t.Errorf("fail reason = %q, want a timeout message", r.state.FailReason())
	}
}

// TestTerminalIgnoresEvents: once connected, later lines produce no effects.
func TestTerminalIgnoresEvents(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).line(lineNeed).line(lineChallenge).line(lineHold1).
		line(lineNeed).send(SAMLCaptured{Raw: rawSAMLAssertion}).
		line(linePushReply).line(lineConnect)
	before := len(r.effects)
	r.line(lineHold0).send(Timeout{}) // must be ignored post-connect
	if len(r.effects) != before {
		t.Errorf("terminal state emitted %d extra effects", len(r.effects)-before)
	}
}

func safeIdx(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return "<none>"
	}
	return s[i]
}

func hasFailed(effects []Effect) bool {
	for _, e := range effects {
		if _, ok := e.(Failed); ok {
			return true
		}
	}
	return false
}
