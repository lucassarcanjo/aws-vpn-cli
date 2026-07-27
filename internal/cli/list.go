package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/daemon"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/profile"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/state"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List available VPN profiles",
		Long:    "List profiles discovered from the AWS VPN Client (read-only) and any you have imported.",
		Example: "  awsvpn list\n  awsvpn list --json      # for scripts and agents",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, err := mustUser()
			if err != nil {
				return err
			}
			profiles, err := profile.Discover(u.Home)
			if err != nil {
				return err
			}
			// Best-effort: knowing which profile is live turns a list into an
			// answer to "where am I?", but not knowing must never fail the list.
			active := ""
			if run, live, err := daemon.Status(system.NewReal(u), state.Default()); err == nil && live {
				active = run.Profile
			}

			if asJSON {
				return printProfilesJSON(os.Stdout, profiles, active)
			}
			if len(profiles) == 0 {
				ui.Warn(os.Stdout, "No profiles found.")
				ui.Hint(os.Stdout, "Add one in the AWS VPN Client, or run `awsvpn import <file.ovpn>`.")
				return nil
			}
			printProfiles(os.Stdout, profiles, active)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the profiles as JSON")
	return cmd
}

// printProfiles renders the profile table. Alignment is computed on plain text
// first and styling applied per whole line afterwards — tabwriter measures bytes,
// so an escape sequence inside a cell would silently skew every column.
func printProfiles(w io.Writer, profiles []profile.Profile, active string) {
	s := ui.For(w)
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tREGION\tENDPOINT\tSOURCE")
	for _, p := range profiles {
		marker := "  "
		if p.Name == active {
			marker = ui.Bullet + " "
		}
		fmt.Fprintf(tw, "%s%s\t%s\t%s\t%s\n", marker, p.Name, dash(p.Region), dash(p.EndpointID), p.Source)
	}
	_ = tw.Flush()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	fmt.Fprintln(w)
	for i, line := range lines {
		switch {
		case i == 0:
			fmt.Fprintln(w, s.Dim(line))
		case strings.HasPrefix(line, ui.Bullet):
			fmt.Fprintln(w, s.Green(ui.Bullet)+s.Bold(strings.TrimPrefix(line, ui.Bullet)))
		default:
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w)
	if active != "" {
		ui.Hint(w, "%s connected · disconnect with: %sawsvpn disconnect", ui.Bullet, sudoPrefix())
		return
	}
	ui.Hint(w, "Connect with: %sawsvpn connect <name>", sudoPrefix())
}

// profileJSON is the machine-readable face of `list`.
type profileJSON struct {
	Name       string `json:"name"`
	Region     string `json:"region,omitempty"`
	EndpointID string `json:"endpoint_id,omitempty"`
	Source     string `json:"source"`
	Path       string `json:"path"`
	Active     bool   `json:"active"`
}

func printProfilesJSON(w io.Writer, profiles []profile.Profile, active string) error {
	out := make([]profileJSON, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, profileJSON{
			Name:       p.Name,
			Region:     p.Region,
			EndpointID: p.EndpointID,
			Source:     string(p.Source),
			Path:       p.OvpnPath,
			Active:     p.Name == active,
		})
	}
	return writeJSON(w, out)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
