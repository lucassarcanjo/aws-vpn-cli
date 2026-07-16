package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/larcanjo/awsvpn/internal/privilege"
	"github.com/spf13/cobra"
)

func newInstallPrivilegeCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "install-privilege",
		Short: "Install a narrow passwordless-sudo rule for non-interactive use",
		Long: "Write a tightly-scoped sudoers rule so `awsvpn` can run without a password\n" +
			"prompt — useful for agents and CI. The exact rule is printed first and, unless\n" +
			"--yes is given, requires confirmation. Remove it any time with `sudo rm " + privilege.SudoersPath + "`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot("install-privilege"); err != nil {
				return err
			}
			u, err := mustUser()
			if err != nil {
				return err
			}
			self, err := os.Executable()
			if err != nil {
				return fmt.Errorf("locating this binary: %w", err)
			}

			rule := privilege.SudoersRule(u.Name, self)
			fmt.Printf("This will write %s with:\n\n%s\n", privilege.SudoersPath, indent(rule))
			fmt.Println("This grants passwordless sudo for THIS awsvpn binary only, for user " + u.Name + ".")

			if !yes {
				fmt.Print("Proceed? Type 'yes' to confirm: ")
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if strings.TrimSpace(line) != "yes" {
					fmt.Println("Aborted. Nothing was written.")
					return nil
				}
			}
			if err := privilege.InstallSudoers(rule); err != nil {
				return err
			}
			fmt.Printf("Installed. You can now run `awsvpn connect …` without a password prompt.\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}
