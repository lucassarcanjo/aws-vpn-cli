package launchd

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestRenderPlist(t *testing.T) {
	got := renderPlist(Spec{
		Exe:     "/usr/local/bin/awsvpn",
		UID:     501,
		Profile: "prod-use2",
		LogPath: "/var/run/awsvpn/awsvpn.log",
	})

	for _, want := range []string{
		`<key>Label</key><string>` + Label + `</string>`,
		`<string>/usr/local/bin/awsvpn</string>`,
		`<string>supervise</string>`,
		`<string>--uid</string><string>501</string>`,
		`<string>--profile</string><string>prod-use2</string>`,
		`<key>RunAtLoad</key><true/>`,
		`<key>KeepAlive</key><false/>`,
		`<string>/var/run/awsvpn/awsvpn.log</string>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered plist missing %q\n---\n%s", want, got)
		}
	}
}

func TestRenderPlistEscapes(t *testing.T) {
	got := renderPlist(Spec{
		Exe:     "/opt/a & b/awsvpn",
		UID:     0,
		Profile: `weird<name>&"'`,
		LogPath: "/var/run/awsvpn/awsvpn.log",
	})
	if strings.Contains(got, "a & b") {
		t.Errorf("ampersand not escaped in exe path:\n%s", got)
	}
	if strings.Contains(got, "weird<name>") {
		t.Errorf("angle brackets not escaped in profile:\n%s", got)
	}
	if !strings.Contains(got, "&amp;") {
		t.Errorf("expected an escaped ampersand somewhere:\n%s", got)
	}
}

// A malformed plist makes launchd silently refuse to load the daemon. Parsing the
// rendered output as XML guards the template against an unbalanced-tag edit — and,
// with a hostile profile name, proves the escaping keeps the document well-formed.
func TestRenderPlistIsWellFormedXML(t *testing.T) {
	got := renderPlist(Spec{
		Exe:     "/opt/a & b/awsvpn",
		UID:     501,
		Profile: `weird<name>&"'`,
		LogPath: "/var/run/awsvpn/awsvpn.log",
	})
	if err := xml.Unmarshal([]byte(got), new(struct{})); err != nil {
		t.Fatalf("rendered plist is not well-formed XML: %v\n---\n%s", err, got)
	}
}
