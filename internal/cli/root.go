// Package cli is the command surface: thin verbs over the discovery, connect
// lifecycle, and privilege modules. It resolves the *real* invoking user up front
// so everything (profile discovery, state paths, browser) operates as them even
// under sudo.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/privilege"
	"github.com/spf13/cobra"
)

var verbose bool

// Execute runs the root command.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fail(err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "awsvpn",
		Short: "CLI-first AWS Client VPN for macOS",
		Long: "awsvpn is a small, auditable wrapper around AWS Client VPN (SAML/SSO).\n" +
			"It drives the AWS-signed acvc-openvpn binary over the OpenVPN management\n" +
			"interface — no GUI, no third-party VPN engine, credential kept in memory.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	root.AddCommand(
		newListCmd(),
		newConnectCmd(),
		newDisconnectCmd(),
		newStatusCmd(),
		newImportCmd(),
		newLogsCmd(),
		newVersionCmd(),
		newInstallPrivilegeCmd(),
		newUninstallPrivilegeCmd(),
		newSuperviseCmd(),
	)
	return root
}

// mustUser resolves the invoking user (following $SUDO_USER), the source of truth
// for "as me" behaviour.
func mustUser() (privilege.User, error) {
	u, err := privilege.Invoking()
	if err != nil {
		return privilege.User{}, fmt.Errorf("resolving the invoking user: %w", err)
	}
	return u, nil
}

// requireRoot returns a helpful error if the command needs privilege it lacks.
// It never elevates on its own: privilege bootstrap (`install-privilege`) stays
// an explicit `sudo` act, and `supervise` is launched by launchd as root. need
// completes "needs root ..." — say what the privilege is for.
func requireRoot(cmd, need string) error {
	if privilege.IsRoot() {
		return nil
	}
	return errors.New(rerunWithSudo(cmd, need))
}

// ensureRoot is requireRoot for the verbs a person types. When the user has
// opted into the `install-privilege` grant, it re-execs the whole command under
// `sudo -n` rather than making them retype it with sudo — that grant is
// precisely their standing "elevate this binary for me". On elevation this call
// never returns.
func ensureRoot(cmd, need string) error {
	if privilege.IsRoot() {
		return nil
	}
	if err := privilege.Elevate(); !errors.Is(err, privilege.ErrNoGrant) {
		// A successful Elevate replaces the process, so anything reaching
		// here is a real failure worth surfacing.
		return err
	}
	return notRootErr(cmd, need, privilege.GrantInstalled(), selfPath())
}

// notRootErr says how to get the privilege, and offers the fix that actually
// applies. granted says whether the rule is on disk: with no rule the offer is
// to install one; with a rule that still didn't get us root the fix is to
// re-install it, because the rule names one exact binary path — a rebuild or a
// move elsewhere leaves it pointing at a binary that is no longer this one,
// which from here is indistinguishable from having no rule at all.
func notRootErr(cmd, need string, granted bool, self string) error {
	head := rerunWithSudo(cmd, need)
	if !granted {
		return fmt.Errorf("%s\nOr run this once and drop the `sudo` prefix for good:  sudo awsvpn install-privilege", head)
	}
	return fmt.Errorf("%s\nThe install-privilege rule is installed but doesn't cover %s — re-run:  sudo awsvpn install-privilege",
		head, self)
}

func rerunWithSudo(cmd, need string) string {
	return fmt.Sprintf("`awsvpn %s` needs root %s — re-run with:\n  sudo awsvpn %s", cmd, need, invocation(cmd))
}

// selfPath names the binary the sudoers rule has to cover for elevation to work.
func selfPath() string {
	self, err := os.Executable()
	if err != nil {
		return "this binary"
	}
	return self
}

// invocation echoes back what the user actually typed (`connect dev`, not just
// `connect`) so the suggested sudo line can be copied as-is.
func invocation(cmd string) string {
	if len(os.Args) > 1 {
		return strings.Join(os.Args[1:], " ")
	}
	return cmd
}
