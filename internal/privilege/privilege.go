// Package privilege handles the consequences of running as a fully-privileged
// (sudo) wrapper: resolving the *real* invoking user so browser-open and profile
// discovery happen as them (not root), and chowning any files we create back to
// them so a sudo invocation doesn't litter root-owned files in a home directory.
package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
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

// Invoking resolves the real user. Under sudo it follows $SUDO_USER; otherwise it
// is the current user. This is the single source of truth for "as me" behaviour.
func Invoking() (User, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		u, err := user.Lookup(name)
		if err != nil {
			return User{}, fmt.Errorf("resolving SUDO_USER %q: %w", name, err)
		}
		return fromOS(u)
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

// Chown gives a single path back to the user. A no-op if we're not root (nothing
// to hand back).
func (u User) Chown(path string) error {
	if !IsRoot() {
		return nil
	}
	return os.Chown(path, u.UID, u.GID)
}

// ChownTree recursively hands a directory tree back to the user.
func (u User) ChownTree(root string) error {
	if !IsRoot() {
		return nil
	}
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, u.UID, u.GID)
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

// OpenBrowser opens url as the invoking user. Under root we route through the
// user's GUI session (`launchctl asuser`) so the SSO tab lands in their
// logged-in browser rather than root's non-existent session.
func (u User) OpenBrowser(url string) error {
	var cmd *exec.Cmd
	if IsRoot() && os.Getenv("SUDO_USER") != "" && os.Getenv("SUDO_USER") != "root" {
		// launchctl asuser <uid> sudo -u <name> open <url>
		cmd = exec.Command("launchctl", "asuser", strconv.Itoa(u.UID),
			"sudo", "-u", u.Name, "open", url)
	} else {
		cmd = exec.Command("open", url)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("opening browser: %w: %s", err, out)
	}
	return nil
}
