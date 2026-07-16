package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// SudoersPath is where the opt-in NOPASSWD rule is installed.
const SudoersPath = "/etc/sudoers.d/awsvpn"

// SudoersRule renders the narrowly-scoped passwordless-sudo rule: it lets only
// the given user run only this exact awsvpn binary as root without a password.
// It is deliberately printed verbatim before install so the user sees exactly
// what will be written.
func SudoersRule(username, binPath string) string {
	return fmt.Sprintf("# Installed by `awsvpn install-privilege`.\n"+
		"# Lets %s run this exact binary as root without a password prompt.\n"+
		"# Remove this file to revoke:  sudo rm %s\n"+
		"%s ALL=(root) NOPASSWD: %s\n",
		username, SudoersPath, username, binPath)
}

// InstallSudoers writes the rule after validating it with `visudo -c`. It must be
// run as root. The caller is responsible for having printed the rule and gotten
// confirmation first.
func InstallSudoers(rule string) error {
	if !IsRoot() {
		return fmt.Errorf("install-privilege must be run as root (try: sudo awsvpn install-privilege)")
	}
	if err := os.MkdirAll(filepath.Dir(SudoersPath), 0o755); err != nil {
		return err
	}
	// Validate into a temp file first so a malformed rule never lands in
	// /etc/sudoers.d (a broken file there can break sudo entirely).
	tmp, err := os.CreateTemp("", "awsvpn-sudoers-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(rule); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	if out, err := exec.Command("visudo", "-c", "-f", tmp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("refusing to install: rule failed validation: %w: %s", err, out)
	}

	// sudoers.d files must be mode 0440 and root-owned.
	if err := os.WriteFile(SudoersPath, []byte(rule), 0o440); err != nil {
		return err
	}
	return os.Chown(SudoersPath, 0, 0)
}
