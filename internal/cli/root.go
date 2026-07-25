// Package cli is the command surface: thin verbs over the discovery, connect
// lifecycle, and privilege modules. It resolves the *real* invoking user up front
// so everything (profile discovery, state paths, browser) operates as them even
// under sudo.
package cli

import (
	"fmt"
	"os"

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
func requireRoot(cmd string) error {
	if privilege.IsRoot() {
		return nil
	}
	return fmt.Errorf("`awsvpn %s` needs root to manage the tunnel — re-run with:\n  sudo awsvpn %s", cmd, cmd)
}
