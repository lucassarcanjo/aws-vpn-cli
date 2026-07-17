package ovpn

import (
	"reflect"
	"strings"
	"testing"
)

// The CRV1 challenge line as delivered by the real dev endpoint. The state id
// carries slashes, and the SAML URL carries colons and query characters — the
// two things naive splitting gets wrong.
const realChallengeLine = `>PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:instance-1/1234567890123456789/11111111-2222-3333-4444-555555555555:dXNlcg==:https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/saml2?SAMLRequest=jVJNTwIxEL3zKzZ7h%2B1i1GQCJKvESOIHgdWDF1OWEZq007XTFfXX2y6ikihxOulhOu%2FNe5MOWBpdQ9H4Nc3wuUH2nSR5NZoY2qdh2jgCK1kxkDTI4CuYF9dX0O8JqJ31trI63QMdxkhmdF5ZiqDJeJg%2Bin9GBNyj44AdpoGqJWBucELsJflQFP2TrshDlkJAmw%2Bxaxx8KZK%2BRa69rxmyTNuVop5RlbNsn7wlrQh7lTXZbmD3l2sXWXTaj%2BTTzyWcKVoqWh12v9g2MVyW5bQ7vZ2XkaLY7eTcEjcG3Rzdi6rwbna11Rvk5v3Tnggnh6NjIfJ0FHBJMogyoN2CG8XB0sh3S7DBBW85GCqtkPxLTYPsZ%2Fc3voabIHQynlqtqre2HuPCOiP9337yoCVW1LL71LYCGql0sVw6ZE6%2FeAqt7ebcofQ4TL1rME2yUaezVbP%2F%2BUYf']`

func TestParseCRV1Challenge_Real(t *testing.T) {
	c, ok := ParseCRV1Challenge(realChallengeLine)
	if !ok {
		t.Fatal("expected the real challenge line to parse")
	}
	wantState := "instance-1/1234567890123456789/11111111-2222-3333-4444-555555555555"
	if c.State != wantState {
		t.Errorf("state = %q, want %q", c.State, wantState)
	}
	if !strings.HasPrefix(c.SAMLURL, "https://login.microsoftonline.com/00000000") {
		t.Errorf("SAML URL prefix wrong: %q", c.SAMLURL)
	}
	// The URL must survive whole, including the query string.
	if !strings.Contains(c.SAMLURL, "SAMLRequest=") {
		t.Errorf("SAML URL lost its query string: %q", c.SAMLURL)
	}
}

func TestParseCRV1Challenge_Rejections(t *testing.T) {
	for _, line := range []string{
		">PASSWORD:Verification Failed: 'Auth'",           // hard failure, no CRV1
		">PASSWORD:Need 'Auth' username/password",         // a prompt, not a challenge
		">HOLD:Waiting for hold release:0",                // unrelated
		`>PASSWORD:Verification Failed: 'Auth' ['CRV1:']`, // malformed
	} {
		if _, ok := ParseCRV1Challenge(line); ok {
			t.Errorf("expected no CRV1 for %q", line)
		}
	}
}

func TestParsePushReply_RealSplitTunnel(t *testing.T) {
	// The real split-tunnel PUSH_REPLY captured from the dev endpoint.
	const line = `>LOG:1784222495,,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.2,route 10.0.0.0 255.255.0.0,route 172.16.8.0 255.255.248.0,route-gateway 10.8.0.129,topology subnet,ping 1,ping-restart 20,echo,echo,echo,ifconfig 10.8.0.133 255.255.255.224,peer-id 1,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,tun-mtu 1500'`
	pr, ok := ParsePushReply(line)
	if !ok {
		t.Fatal("expected PUSH_REPLY to parse")
	}
	if want := []string{"10.0.0.2"}; !reflect.DeepEqual(pr.DNS, want) {
		t.Errorf("DNS = %v, want %v", pr.DNS, want)
	}
	wantRoutes := []Route{
		{Network: "10.0.0.0", Netmask: "255.255.0.0"},
		{Network: "172.16.8.0", Netmask: "255.255.248.0"},
	}
	if !reflect.DeepEqual(pr.Routes, wantRoutes) {
		t.Errorf("routes = %v, want %v", pr.Routes, wantRoutes)
	}
	if pr.Gateway != "10.8.0.129" {
		t.Errorf("gateway = %q, want 10.8.0.129", pr.Gateway)
	}
	if pr.FullTunnel {
		t.Error("split-tunnel reply should not be flagged full tunnel")
	}
}

func TestParsePushReply_FullTunnel(t *testing.T) {
	const line = `PUSH_REPLY,dhcp-option DNS 10.0.0.2,redirect-gateway def1,route-gateway 10.8.0.129`
	pr, ok := ParsePushReply(line)
	if !ok {
		t.Fatal("expected parse")
	}
	if !pr.FullTunnel {
		t.Error("expected full tunnel when redirect-gateway is pushed")
	}
}

func TestParseConnected_Real(t *testing.T) {
	const line = `>STATE:1784222495,CONNECTED,SUCCESS,10.8.0.133,203.0.113.10,443,,`
	ci, ok := ParseConnected(line)
	if !ok {
		t.Fatal("expected CONNECTED to parse")
	}
	if ci.AssignedIP != "10.8.0.133" {
		t.Errorf("assigned IP = %q", ci.AssignedIP)
	}
	if ci.RemoteIP != "203.0.113.10" {
		t.Errorf("remote IP = %q", ci.RemoteIP)
	}
	if ci.Port != "443" {
		t.Errorf("port = %q", ci.Port)
	}
}

func TestParseConnected_NotConnected(t *testing.T) {
	for _, line := range []string{
		`>STATE:1784222488,RECONNECTING,auth-failure,,,,,`,
		`>STATE:1784222494,WAIT,,,,,,`,
		`>HOLD:Waiting for hold release:1`,
	} {
		if _, ok := ParseConnected(line); ok {
			t.Errorf("did not expect CONNECTED for %q", line)
		}
	}
}

func TestClassifiers(t *testing.T) {
	cases := []struct {
		line string
		pred func(string) bool
		name string
		want bool
	}{
		{">HOLD:Waiting for hold release:0", IsHold, "IsHold", true},
		{">PASSWORD:Need 'Auth' username/password", IsPasswordNeed, "IsPasswordNeed", true},
		{">PASSWORD:Verification Failed: 'Auth'", IsVerificationFailed, "IsVerificationFailed", true},
		{">FATAL:some error", IsFatal, "IsFatal", true},
		{">LOG:1,,AUTH: Received control message: AUTH_FAILED", IsAuthFailed, "IsAuthFailed", true},
		// The soft-restart lines must NOT read as a hard auth failure.
		{">STATE:1784222488,RECONNECTING,auth-failure,,,,,", IsAuthFailed, "IsAuthFailed(soft)", false},
		{">LOG:1,I,SIGUSR1[soft,auth-failure] received, process restarting", IsAuthFailed, "IsAuthFailed(sigusr1)", false},
		// The CRV1 challenge arrives as an AUTH_FAILED control message — it is the
		// start of the SAML dance, not a hard failure.
		{">LOG:1,N,AUTH: Received control message: AUTH_FAILED,CRV1:R:instance-1/766/664:b'Ti9B':https://login.microsoftonline.com/tenant/saml2?SAMLRequest=fZJP", IsAuthFailed, "IsAuthFailed(crv1)", false},
	}
	for _, c := range cases {
		if got := c.pred(c.line); got != c.want {
			t.Errorf("%s(%q) = %v, want %v", c.name, c.line, got, c.want)
		}
	}
}

func TestParsePasswordRealm(t *testing.T) {
	if got := ParsePasswordRealm(">PASSWORD:Need 'Auth' username/password"); got != "Auth" {
		t.Errorf("realm = %q, want Auth", got)
	}
	if got := ParsePasswordRealm(">PASSWORD:Verification Failed: 'Auth' ['CRV1:...']"); got != "Auth" {
		t.Errorf("realm = %q, want Auth", got)
	}
}
