package reducer

import (
	"net/url"
	"strings"
	"testing"
)

// The real management lines captured by the spike against the dev endpoint.
const (
	lineHold0   = `>HOLD:Waiting for hold release:0`
	lineHold1   = `>HOLD:Waiting for hold release:1`
	lineNeed    = `>PASSWORD:Need 'Auth' username/password`
	lineReconn  = `>STATE:1784222488,RECONNECTING,auth-failure,,,,,`
	lineWait    = `>STATE:1784222494,WAIT,,,,,,`
	lineConnect = `>STATE:1784222495,CONNECTED,SUCCESS,10.8.0.133,203.0.113.10,443,,`

	linePushReply = `>LOG:1784222495,,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.2,route 10.0.0.0 255.255.0.0,route 172.16.8.0 255.255.248.0,route-gateway 10.8.0.129,topology subnet,ping 1,ping-restart 20,echo,echo,echo,ifconfig 10.8.0.133 255.255.255.224,peer-id 1,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500'`

	realState        = "instance-1/1234567890123456789/11111111-2222-3333-4444-555555555555"
	lineChallenge    = `>PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:` + realState + `:dXNlcg==:https://login.microsoftonline.com/tenant/saml2?SAMLRequest=fZJRb9s']`
	samlURL          = "https://login.microsoftonline.com/tenant/saml2?SAMLRequest=fZJRb9s"
	rawSAMLAssertion = "PHNhbWxwOlJlc3BvbnNlPmZvbytiYXIvYmF6PT0mc2lnPXh4eA==" // has +, /, = to exercise url-encoding
)

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

// TestHardAuthFailure: a hard AUTH_FAILED (no CRV1) on the first attempt fails.
func TestHardAuthFailure(t *testing.T) {
	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(`>LOG:1784222494,,AUTH: Received control message: AUTH_FAILED`)

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
