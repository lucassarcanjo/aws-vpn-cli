package supervisor

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Verdict
	}{
		{"connected", ">STATE:1784222495,CONNECTED,SUCCESS,10.8.0.133,203.0.113.10,443,,", Recovered},
		{"reconnecting", ">STATE:1784222495,RECONNECTING,ping-restart,,,,,", Reconnecting},
		{"exiting", ">STATE:1784222495,EXITING,SIGTERM,,,,,", Down},
		{"wait state is inert", ">STATE:1784222495,WAIT,,,,,,", Watching},
		{"resolve state is inert", ">STATE:1784222495,RESOLVE,,,,,,", Watching},
		{"hold means reauth", ">HOLD:Waiting for hold release", Reauth},
		{"password need means reauth", ">PASSWORD:Need 'Auth' username/password", Reauth},
		{"verification failed means reauth", ">PASSWORD:Verification Failed: 'Auth'", Reauth},
		{"fatal means down", ">FATAL: tls-error: TLS handshake failed", Down},
		{"bytecount is inert", ">BYTECOUNT:1234,5678", Watching},
		{"log line is inert", ">LOG:1784222495,I,OpenVPN 2.5.1", Watching},
		{"empty is inert", "", Watching},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.line); got != c.want {
				t.Fatalf("Classify(%q) = %v, want %v", c.line, got, c.want)
			}
		})
	}
}

func TestClassifyMalformedStateIsInert(t *testing.T) {
	// A truncated >STATE: line (no state name) must not be mistaken for anything
	// actionable; it should be ignored, not trip a teardown.
	for _, line := range []string{">STATE:", ">STATE:123", ">STATE:onlyone"} {
		if got := Classify(line); got != Watching {
			t.Errorf("Classify(%q) = %v, want Watching", line, got)
		}
	}
}

const (
	lineReconnecting = ">STATE:1,RECONNECTING,ping-restart,,,,,"
	lineConnected    = ">STATE:2,CONNECTED,SUCCESS,10.0.0.1,1.2.3.4,443,,"
	lineHold         = ">HOLD:Waiting for hold release"
)

// A brief drop that recovers on its own must NOT tear the tunnel down — the whole
// point of the grace window. This is the premature-teardown regression guard.
func TestWatcherTransientReconnectRecovers(t *testing.T) {
	var w Watcher
	if got := w.Line(lineReconnecting); got.Action != BeginGrace {
		t.Fatalf("on drop: got %v, want BeginGrace", got.Action)
	}
	if got := w.Line(lineConnected); got.Action != EndGrace {
		t.Fatalf("on recovery: got %v, want EndGrace", got.Action)
	}
	// Back in steady state; a later CONNECTED echo is inert, never a teardown.
	if got := w.Line(lineConnected); got.Action != Wait {
		t.Fatalf("steady state after recovery: got %v, want Wait", got.Action)
	}
}

func TestWatcherGraceExpiryTearsDown(t *testing.T) {
	var w Watcher
	w.Line(lineReconnecting) // opens the grace window
	got := w.GraceExpired()
	if got.Action != Teardown {
		t.Fatalf("grace expiry: got %v, want Teardown", got.Action)
	}
	if !strings.Contains(got.Reason, "did not recover") {
		t.Fatalf("reason = %q, want it to mention not recovering", got.Reason)
	}
}

func TestWatcherHoldIsImmediateReauthTeardown(t *testing.T) {
	var w Watcher
	got := w.Line(lineHold)
	if got.Action != Teardown || got.Reason != "the VPN session ended and needs re-authentication" {
		t.Fatalf("hold: got %+v, want Teardown with a re-auth reason", got)
	}
}

// A hold arriving mid-grace must short-circuit the window: for AWS a hold means a
// full re-auth is required, so waiting out the grace would be pointless.
func TestWatcherHoldDuringGraceGivesUp(t *testing.T) {
	var w Watcher
	w.Line(lineReconnecting) // grace open
	got := w.Line(lineHold)
	if got.Action != Teardown || !strings.Contains(got.Reason, "re-authentication") {
		t.Fatalf("mid-grace hold: got %+v, want a re-auth Teardown", got)
	}
}

func TestWatcherPasswordNeedIsReauth(t *testing.T) {
	var w Watcher
	got := w.Line(">PASSWORD:Need 'Auth' username/password")
	if got.Action != Teardown || !strings.Contains(got.Reason, "re-authentication") {
		t.Fatalf("password need: got %+v, want a re-auth Teardown", got)
	}
}

func TestWatcherClosedStreamTearsDown(t *testing.T) {
	var w Watcher
	got := w.Closed()
	if got.Action != Teardown || got.Reason != "the tunnel closed unexpectedly" {
		t.Fatalf("closed stream: got %+v, want a closed-unexpectedly Teardown", got)
	}
}

func TestWatcherExitingAndFatalGoDown(t *testing.T) {
	for _, line := range []string{">STATE:1,EXITING,SIGTERM,,,,,", ">FATAL: tls-error: handshake failed"} {
		var w Watcher
		got := w.Line(line)
		if got.Action != Teardown || got.Reason != "the tunnel went down" {
			t.Errorf("Line(%q) = %+v, want a went-down Teardown", line, got)
		}
	}
}

// A second RECONNECTING while the window is already open must not restart it, or a
// flapping tunnel could postpone teardown indefinitely.
func TestWatcherSecondReconnectDoesNotRestartGrace(t *testing.T) {
	var w Watcher
	if got := w.Line(lineReconnecting); got.Action != BeginGrace {
		t.Fatalf("first reconnect: got %v, want BeginGrace", got.Action)
	}
	if got := w.Line(lineReconnecting); got.Action != Wait {
		t.Fatalf("second reconnect: got %v, want Wait (window must not restart)", got.Action)
	}
}

// DialWatch's `state on` makes openvpn echo the current CONNECTED state on attach;
// that echo must be inert when we were never in a grace window.
func TestWatcherInitialConnectedEchoIsInert(t *testing.T) {
	var w Watcher
	if got := w.Line(lineConnected); got.Action != Wait {
		t.Fatalf("initial CONNECTED echo: got %v, want Wait", got.Action)
	}
}
