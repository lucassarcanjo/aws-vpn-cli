package privilege

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// ErrNoGrant reports that we cannot become root without a password prompt —
// either `install-privilege` was never run, or its rule no longer covers this
// binary (the rule names one exact path, so moving or rebuilding elsewhere
// voids it).
var ErrNoGrant = errors.New("no passwordless sudo grant for this binary")

// GrantInstalled reports whether the opt-in sudoers rule is present. The file is
// root-only readable but /etc/sudoers.d is traversable, so a stat is enough. We
// treat it as the user's explicit "yes, elevate me" marker: without it we never
// re-exec under sudo, even when a live sudo timestamp would happen to allow it.
func GrantInstalled() bool {
	_, err := os.Stat(SudoersPath)
	return err == nil
}

// Elevate re-executes this process as root through `sudo -n`, so `awsvpn connect`
// works on its own once the grant is installed instead of making the user retype
// the command under sudo. It elevates only when the grant is installed *and*
// sudo confirms it will not prompt; otherwise it returns ErrNoGrant and the
// caller prints its own guidance.
//
// On success this does not return: syscall.Exec replaces the process image, so
// stdio, the controlling terminal (the profile picker and any prompt still work)
// and the exit status all belong to the elevated run.
func Elevate() error {
	if IsRoot() {
		return nil
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return ErrNoGrant
	}
	// The same path install-privilege wrote into the rule: os.Executable()
	// resolves the real binary even when we were launched through a shim.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating this binary: %w", err)
	}
	if !GrantInstalled() || !sudoIsPasswordless(sudo, self) {
		return ErrNoGrant
	}
	argv := append([]string{sudo, "-n", "--", self}, os.Args[1:]...)
	return fmt.Errorf("re-running as root: %w", syscall.Exec(sudo, argv, os.Environ()))
}

// sudoIsPasswordless reports whether sudo will run this exact binary as root
// without asking for a password. We probe rather than exec hopefully, because
// syscall.Exec is a one-way door: past it we could no longer fall back to a
// useful error message.
//
// The probe runs the real thing — `sudo -n <self> version`, which only prints a
// string — because that is the only answer that generalises. `sudo -l` reports
// whether a command is *allowed*, not whether it is passwordless: with a normal
// admin `(ALL) ALL` line it succeeds even when the run would prompt. Stdio is
// discarded and -n is set, so this can never surface as a stray prompt or
// stray output.
func sudoIsPasswordless(sudo, self string) bool {
	c := exec.Command(sudo, "-n", "--", self, "version")
	c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
	return c.Run() == nil
}
