// Package launchd owns the connection supervisor's macOS service lifecycle. The
// supervisor is registered as a LaunchDaemon (root) only for the duration of a
// connection: `connect` installs it, `disconnect` (and the next `connect`) tears
// it down. Nothing runs as root when no tunnel is up, preserving the tool's
// "no standing privilege" stance — root exists only while a tunnel does.
//
// launchd (rather than a plain child of `connect`) is what lets a single root
// watcher survive terminal close, logout/login, and long sleeps, and get restarted
// cleanly if it ever crashes — the macOS-blessed way to have "something as root
// that reacts to the tunnel dying."
package launchd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

const (
	// Label is the LaunchDaemon's reverse-DNS identifier.
	Label = "com.github.lucassarcanjo.awsvpn.supervisor"
	// PlistPath is where the per-connection daemon definition is written. The
	// system LaunchDaemons directory is root-owned, so a non-root user cannot
	// plant or tamper with the plist that launchd will run as root.
	PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
)

// Spec parameterises the supervisor daemon.
type Spec struct {
	Exe     string // absolute path to this awsvpn binary (from os.Executable)
	UID     int    // invoking user's uid — the notification target session
	Profile string // profile being supervised (for ps/logs)
	LogPath string // where the daemon's stdout/stderr (its log lines) go
}

// Install (re)registers the supervisor as a running LaunchDaemon. It first boots
// out any prior instance so a repeated connect can't collide with a stale job,
// writes the plist, then bootstraps it. Must be called as root.
func Install(s Spec) error {
	_ = Uninstall() // clear any prior instance (best-effort)

	if err := os.WriteFile(PlistPath, []byte(renderPlist(s)), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", PlistPath, err)
	}
	if out, err := bootstrap(); err != nil {
		// A lingering job with the same label makes bootstrap fail; force it out
		// and try once more before giving up.
		_ = bootout()
		if out2, err2 := bootstrap(); err2 != nil {
			_ = os.Remove(PlistPath)
			return fmt.Errorf("launchctl bootstrap failed: %w: %s / %s",
				err2, bytes.TrimSpace(out), bytes.TrimSpace(out2))
		}
	}
	return nil
}

// Uninstall stops the supervisor and removes its plist. Idempotent: a not-loaded
// job and a missing plist are both fine. Called by `disconnect` before tearing the
// tunnel down, so the supervisor does not observe the deliberate teardown as a
// drop and fire a spurious "connection lost" notification.
func Uninstall() error {
	_ = bootout() // ignore "not loaded"
	if err := os.Remove(PlistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func bootstrap() ([]byte, error) {
	return exec.Command("launchctl", "bootstrap", "system", PlistPath).CombinedOutput()
}

func bootout() error {
	return exec.Command("launchctl", "bootout", "system/"+Label).Run()
}

// renderPlist builds the LaunchDaemon property list. Each interpolated value is
// XML-escaped so a binary path or profile name containing &, <, or a quote can't
// corrupt the document. RunAtLoad starts it on bootstrap; KeepAlive is false
// because a give-up teardown is terminal — the daemon should exit and stay exited,
// not be relaunched into a loop.
func renderPlist(s Spec) string {
	return xml.Header +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + esc(Label) + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + esc(s.Exe) + `</string>
    <string>supervise</string>
    <string>--uid</string><string>` + strconv.Itoa(s.UID) + `</string>
    <string>--profile</string><string>` + esc(s.Profile) + `</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>` + esc(s.LogPath) + `</string>
  <key>StandardErrorPath</key><string>` + esc(s.LogPath) + `</string>
</dict>
</plist>
`
}

func esc(v string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(v))
	return b.String()
}
