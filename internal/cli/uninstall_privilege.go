package cli

import (
	"os"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/privilege"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
	"github.com/spf13/cobra"
)

func newUninstallPrivilegeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall-privilege",
		Short:   "Revoke the passwordless-sudo rule installed by install-privilege",
		Aliases: []string{"remove-privilege"},
		Long: "Delete " + privilege.SudoersPath + ", the rule written by `install-privilege`.\n" +
			"`connect` and `disconnect` stop elevating themselves and need an explicit `sudo`\n" +
			"prefix again. Nothing else changes: an active tunnel keeps running, and the\n" +
			"grant can be re-installed at any time.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Check before elevating. With no rule there is nothing to do, and
			// asking for root first would mean prompting for a password to
			// perform no work — and, worse, printing "install the grant" advice
			// to someone who is trying to get rid of it.
			if !privilege.GrantInstalled() {
				ui.Done(os.Stdout, "Nothing to revoke — there is no rule at %s.", privilege.SudoersPath)
				return nil
			}
			// Elevate through the very grant we are about to delete: while it is
			// still in place this needs no password.
			if err := ensureRoot("uninstall-privilege", "to remove the sudoers rule"); err != nil {
				return err
			}
			removed, err := privilege.RemoveSudoers()
			if err != nil {
				return err
			}
			if !removed {
				// Someone (or something) removed it between the two checks. The
				// end state is what was asked for either way.
				ui.Done(os.Stdout, "Nothing to revoke — there is no rule at %s.", privilege.SudoersPath)
				return nil
			}
			ui.Done(os.Stdout, "Revoked the passwordless-sudo rule.")
			ui.Hint(os.Stdout, "`connect` and `disconnect` need a `sudo` prefix again.")
			ui.Hint(os.Stdout, "Re-install it any time with: sudo awsvpn install-privilege")
			return nil
		},
	}
}
