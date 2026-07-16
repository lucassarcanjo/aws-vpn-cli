package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/larcanjo/awsvpn/internal/profile"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available VPN profiles",
		Long:  "List profiles discovered from the AWS VPN Client (read-only) and any you have imported.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, err := mustUser()
			if err != nil {
				return err
			}
			profiles, err := profile.Discover(u.Home)
			if err != nil {
				return err
			}
			if len(profiles) == 0 {
				fmt.Println("No profiles found. Add one in the AWS VPN Client, or run `awsvpn import <file.ovpn>`.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tREGION\tENDPOINT\tSOURCE")
			for _, p := range profiles {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, dash(p.Region), dash(p.EndpointID), p.Source)
			}
			return w.Flush()
		},
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
