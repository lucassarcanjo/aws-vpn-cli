package cli

import (
	"fmt"
	"os"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/daemon"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/launchd"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
	"github.com/spf13/cobra"
)

func newDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect",
		Short: "Tear down the active tunnel and restore DNS",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot("disconnect"); err != nil {
				return err
			}
			u, err := mustUser()
			if err != nil {
				return err
			}
			// Stop the supervisor first so it doesn't observe this deliberate
			// teardown as a drop and fire a "connection lost" notification.
			if err := launchd.Uninstall(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not remove the connection supervisor: %v\n", err)
			}
			logger := logging.New(os.Stderr, logging.NewRedactor(), verbose)
			profile, err := daemon.Disconnect(system.NewReal(u), logger)
			if err != nil {
				return err
			}
			if profile == "" {
				fmt.Println("Nothing to disconnect (no active tunnel). DNS restored if any override remained.")
				return nil
			}
			fmt.Printf("Disconnected from %s. Routes removed and DNS restored.\n", profile)
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the current connection state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, err := mustUser()
			if err != nil {
				return err
			}
			run, live, err := daemon.Status(system.NewReal(u))
			if err != nil {
				return err
			}
			if run.Profile == "" {
				fmt.Println("disconnected")
				return nil
			}
			fmt.Println(daemon.FormatStatus(run, live))
			return nil
		},
	}
}
