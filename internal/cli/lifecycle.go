package cli

import (
	"os"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/daemon"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/launchd"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
	"github.com/spf13/cobra"
)

func newDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect",
		Short: "Tear down the active tunnel and restore DNS",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := ensureRoot("disconnect", "to manage the tunnel"); err != nil {
				return err
			}
			u, err := mustUser()
			if err != nil {
				return err
			}
			// Stop the supervisor first so it doesn't observe this deliberate
			// teardown as a drop and fire a "connection lost" notification.
			if err := launchd.Uninstall(); err != nil {
				ui.Warn(os.Stderr, "could not remove the connection supervisor: %v", err)
			}
			logger := logging.New(os.Stderr, logging.NewRedactor(), verbose)
			profile, err := daemon.Disconnect(system.NewReal(u), logger)
			if err != nil {
				return err
			}
			if profile == "" {
				ui.Done(os.Stdout, "Nothing to disconnect — no active tunnel.")
				ui.Hint(os.Stdout, "Any DNS override left behind by a previous connection was restored.")
				return nil
			}
			ui.Done(os.Stdout, "Disconnected from %s", ui.For(os.Stdout).Bold(profile))
			ui.Hint(os.Stdout, "Routes removed, DNS restored.")
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Show the current connection state",
		Example: "  awsvpn status\n  awsvpn status --json    # for scripts and agents",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, err := mustUser()
			if err != nil {
				return err
			}
			run, live, err := daemon.Status(system.NewReal(u))
			if err != nil {
				return err
			}
			if asJSON {
				return printStatusJSON(os.Stdout, run, live)
			}
			printStatus(os.Stdout, run, live)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the connection state as JSON")
	return cmd
}
