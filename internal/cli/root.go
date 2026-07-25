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
// an explicit `sudo` act, and `supervise` is launched by launchd as root.
func requireRoot(cmd string) error {
	if privilege.IsRoot() {
		return nil
	}
	return notRootErr(cmd)
}

// ensureRoot is requireRoot for the tunnel verbs. When the user has opted into
// the `install-privilege` grant, it re-execs the whole command under `sudo -n`
// rather than making them retype it with sudo — that grant is precisely their
// standing "elevate this binary for me". On elevation this call never returns.
func ensureRoot(cmd string) error {
	if privilege.IsRoot() {
		return nil
	}
	if err := privilege.Elevate(); !errors.Is(err, privilege.ErrNoGrant) {
		// A successful Elevate replaces the process, so anything reaching
		// here is a real failure worth surfacing.
		return err
	}
	return notRootErr(cmd)
}

func notRootErr(cmd string) error {
	return fmt.Errorf("`awsvpn %s` needs root to manage the tunnel — re-run with:\n  sudo awsvpn %s\n"+
		"Or let this binary elevate itself from now on:  sudo awsvpn install-privilege",
		cmd, invocation(cmd))
}

// invocation echoes back what the user actually typed (`connect dev`, not just
// `connect`) so the suggested sudo line can be copied as-is.
func invocation(cmd string) string {
	if len(os.Args) > 1 {
		return strings.Join(os.Args[1:], " ")
	}
	return cmd
}
