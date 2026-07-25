package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/profile"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/state"
)

// plainEnv strips any colour opinion from the environment so these tests assert
// on wording and layout rather than on escape sequences.
func plainEnv(t *testing.T) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
}

func liveRun() state.Run {
	return state.Run{
		Profile:     "dev",
		OvpnPID:     4242,
		AssignedIP:  "10.8.0.57",
		RemoteIP:    "203.0.113.20",
		Port:        "443",
		DNS:         []string{"10.0.0.2"},
		LogPath:     "/var/run/awsvpn/awsvpn.log",
		ConnectedAt: time.Now().Add(-12*time.Minute - 4*time.Second),
	}
}

func TestPrintStatusConnected(t *testing.T) {
	plainEnv(t)
	var buf bytes.Buffer
	printStatus(&buf, liveRun(), true)
	got := buf.String()
	for _, want := range []string{
		"● connected  dev",
		"IP        10.8.0.57",
		"endpoint  203.0.113.20:443",
		"DNS       10.0.0.2",
		"mode      split-tunnel",
		"uptime    12m 04s",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status is missing %q:\n%s", want, got)
		}
	}
}

func TestPrintStatusDistinguishesNotLive(t *testing.T) {
	plainEnv(t)
	connecting := state.Run{Profile: "dev", OvpnPID: 4242} // no ConnectedAt yet
	var buf bytes.Buffer
	printStatus(&buf, connecting, false)
	if !strings.Contains(buf.String(), "connecting") {
		t.Errorf("a handshake in progress should read as connecting:\n%s", buf.String())
	}

	buf.Reset()
	printStatus(&buf, liveRun(), false)
	got := buf.String()
	if !strings.Contains(got, "stale") || !strings.Contains(got, "sudo awsvpn disconnect") {
		t.Errorf("a dead tunnel should read as stale and say how to clean up:\n%s", got)
	}
}

func TestPrintStatusDisconnected(t *testing.T) {
	plainEnv(t)
	var buf bytes.Buffer
	printStatus(&buf, state.Run{}, false)
	if !strings.Contains(buf.String(), "disconnected") {
		t.Errorf("expected a disconnected state:\n%s", buf.String())
	}
}

func TestPrintConnectedPromisesRecoveryOnlyWhenSupervised(t *testing.T) {
	plainEnv(t)
	var supervised, bare bytes.Buffer
	printConnected(&supervised, liveRun(), true)
	printConnected(&bare, liveRun(), false)

	const promise = "torn down automatically"
	if !strings.Contains(supervised.String(), promise) {
		t.Errorf("a supervised tunnel should promise auto-teardown:\n%s", supervised.String())
	}
	if strings.Contains(bare.String(), promise) {
		t.Errorf("an unsupervised tunnel must not promise auto-teardown:\n%s", bare.String())
	}
	if !strings.Contains(bare.String(), "Connected to dev") {
		t.Errorf("the summary should name the profile:\n%s", bare.String())
	}
}

func TestStatusJSONShape(t *testing.T) {
	plainEnv(t)
	var buf bytes.Buffer
	if err := printStatusJSON(&buf, liveRun(), true); err != nil {
		t.Fatal(err)
	}
	var got statusJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("status --json is not valid JSON: %v", err)
	}
	if got.State != "connected" || got.Profile != "dev" || got.Endpoint != "203.0.113.20:443" {
		t.Fatalf("unexpected payload: %+v", got)
	}
	if got.UptimeSeconds != 724 {
		t.Fatalf("uptime_seconds = %d, want 724", got.UptimeSeconds)
	}

	buf.Reset()
	if err := printStatusJSON(&buf, state.Run{}, false); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil || got.State != "disconnected" {
		t.Fatalf("disconnected payload: %s (%v)", buf.String(), err)
	}
}

func TestPrintProfilesMarksTheActiveOne(t *testing.T) {
	plainEnv(t)
	profiles := []profile.Profile{
		{Name: "dev", Region: "us-east-2", EndpointID: "cvpn-endpoint-1", Source: profile.SourceAWS},
		{Name: "staging", EndpointID: "", Source: profile.SourceImported},
	}
	var buf bytes.Buffer
	printProfiles(&buf, profiles, "dev")

	var header, dev, staging string
	for _, l := range strings.Split(buf.String(), "\n") {
		switch {
		case strings.Contains(l, "NAME"):
			header = l
		case strings.Contains(l, "dev"):
			dev = l
		case strings.Contains(l, "staging"):
			staging = l
		}
	}
	if !strings.HasPrefix(dev, "●") {
		t.Errorf("the connected profile should be marked: %q", dev)
	}
	if !strings.HasPrefix(staging, "  ") {
		t.Errorf("an idle profile should be unmarked: %q", staging)
	}
	// The marker occupies the same screen columns as the blank prefix, so rows
	// stay aligned whether or not they are marked. Columns are counted in runes:
	// the marker is one glyph but three bytes.
	if got, want := column(dev, "us-east-2"), column(header, "REGION"); got != want {
		t.Errorf("REGION column misaligned: header at %d, row at %d\n%s", want, got, buf.String())
	}
	if got, want := column(staging, "imported"), column(header, "SOURCE"); got != want {
		t.Errorf("SOURCE column misaligned: header at %d, row at %d\n%s", want, got, buf.String())
	}
	if !strings.Contains(staging, "-") {
		t.Errorf("a missing field should render as a dash: %q", staging)
	}
}

// column reports where substr starts on screen, counting glyphs rather than bytes.
func column(line, substr string) int {
	i := strings.Index(line, substr)
	if i < 0 {
		return -1
	}
	return utf8.RuneCountInString(line[:i])
}
