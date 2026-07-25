// Package privilege handles the consequences of running as a fully-privileged
// (sudo) wrapper: resolving the *real* invoking user so browser-open and profile
// discovery happen as them (not root), and chowning any files we create back to
// them so a sudo invocation doesn't litter root-owned files in a home directory.
package privilege

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// User is the real invoking user (the human behind a `sudo awsvpn …`), resolved
// from $SUDO_USER when present so we never mistake root's home for theirs.
type User struct {
	Name string
	UID  int
	GID  int
	Home string
}

// IsRoot reports whether the process is running as root.
func IsRoot() bool { return os.Geteuid() == 0 }

// Invoking resolves the real user. Only when we are actually root do we follow
// $SUDO_USER (so a non-root process can't set SUDO_USER to read another user's
// state/home); otherwise it is the current user.
func Invoking() (User, error) {
	if IsRoot() {
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			u, err := user.Lookup(name)
			if err != nil {
				return User{}, fmt.Errorf("resolving SUDO_USER %q: %w", name, err)
			}
			return fromOS(u)
		}
	}
	u, err := user.Current()
	if err != nil {
		return User{}, err
	}
	return fromOS(u)
}

func fromOS(u *user.User) (User, error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return User{}, fmt.Errorf("parsing uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return User{}, fmt.Errorf("parsing gid %q: %w", u.Gid, err)
	}
	return User{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir}, nil
}

// Chown gives a single path back to the user. Uses Lchown so a symlink planted at
// the path can't redirect the ownership change to an arbitrary target. A no-op if
// we're not root (nothing to hand back).
func (u User) Chown(path string) error {
	if !IsRoot() {
		return nil
	}
	return os.Lchown(path, u.UID, u.GID)
}

// ChownTree recursively hands a directory tree back to the user. filepath.Walk
// does not descend into symlinked directories (it Lstats), and we Lchown each
// entry, so no symlink is ever followed to chown an off-tree target.
func (u User) ChownTree(root string) error {
	if !IsRoot() {
		return nil
	}
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, u.UID, u.GID)
	})
}

// EnsureDir creates a directory (and parents) and, if we're root, hands it to the
// user so their own later (non-sudo) invocations can read/write it.
func (u User) EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	return u.ChownTree(path)
}

// OpenBrowser opens rawURL as the invoking user. Under root we route through the
// user's GUI session (`launchctl asuser`) so the SSO tab lands in their
// logged-in browser rather than root's non-existent session. The URL comes from
// the (authenticated, x509-verified) endpoint, but we still validate its scheme
// so a hostile endpoint can't make `open` launch a file:// or custom-scheme
// handler, or inject an `open` flag via a leading dash.
func (u User) OpenBrowser(rawURL string) error {
	if err := validateBrowserURL(rawURL); err != nil {
		return err
	}
	cmd := u.asUser("open", rawURL)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("opening browser: %w: %s", err, out)
	}
	return nil
}

// CopyToClipboard puts text on the invoking user's pasteboard, so they can paste
// the sign-in link into the browser they are actually signed in to. Routed into
// their GUI session for the same reason as OpenBrowser, and handed to `pbcopy`
// over stdin rather than argv so it never appears in the process table.
func (u User) CopyToClipboard(text string) error {
	cmd := u.asUser("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying to the clipboard: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// asUser builds a command that runs in the invoking user's GUI session. Under
// root we go through `launchctl asuser` so the action reaches their desktop
// (their browser, their pasteboard) rather than root's non-existent session.
func (u User) asUser(name string, args ...string) *exec.Cmd {
	if IsRoot() && os.Getenv("SUDO_USER") != "" && os.Getenv("SUDO_USER") != "root" {
		// launchctl asuser <uid> sudo -u <name> <cmd> <args...>
		full := append([]string{"asuser", strconv.Itoa(u.UID), "sudo", "-u", u.Name, name}, args...)
		return exec.Command("launchctl", full...)
	}
	return exec.Command(name, args...)
}

func validateBrowserURL(rawURL string) error {
	pu, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("refusing to open a malformed SSO URL: %w", err)
	}
	if pu.Scheme != "https" && pu.Scheme != "http" {
		return fmt.Errorf("refusing to open SSO URL with non-http(s) scheme %q", pu.Scheme)
	}
	return nil
}
