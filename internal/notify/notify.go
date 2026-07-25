// Package notify posts a macOS desktop notification from a privileged, sessionless
// context. The connection supervisor runs as a root LaunchDaemon with no GUI
// session of its own, so it cannot pop a Notification Center banner directly; it
// must route the request into the logged-in user's session via `launchctl asuser`.
package notify

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Send posts a notification with the given title and body to uid's GUI session.
// Must be called as root (launchctl asuser targets another user's session).
// Best-effort by nature: on a headless machine or a logged-out user there is no
// session to reach, and the returned error is meant to be logged and ignored.
func Send(uid int, title, body string) error {
	script := fmt.Sprintf("display notification %s with title %s", appleScriptString(body), appleScriptString(title))
	out, err := exec.Command("launchctl", "asuser", strconv.Itoa(uid),
		"osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("posting notification: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// appleScriptString renders s as a quoted AppleScript string literal. It escapes
// the backslash and double-quote so a profile name with unusual characters cannot
// break out of the literal and inject script, and replaces control characters
// (e.g. a newline in an AWS-store profile name) with spaces so they cannot
// prematurely terminate the single-line `-e` literal.
func appleScriptString(s string) string {
	var b bytes.Buffer
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
