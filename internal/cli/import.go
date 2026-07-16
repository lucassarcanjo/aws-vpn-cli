package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/larcanjo/awsvpn/internal/config"
	"github.com/larcanjo/awsvpn/internal/profile"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "import <file.ovpn>",
		Short: "Register a raw .ovpn config as a profile",
		Long:  "Copy an OpenVPN config into awsvpn's own store so you can connect to an endpoint you haven't added to the AWS VPN Client.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := mustUser()
			if err != nil {
				return err
			}
			src := args[0]
			data, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("reading %s: %w", src, err)
			}
			if !looksLikeOvpn(data) {
				return fmt.Errorf("%s does not look like an OpenVPN config (no `remote`/`client` directive)", src)
			}

			profName := name
			if profName == "" {
				profName = strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
			}
			profName = sanitizeName(profName)
			if profName == "" {
				return fmt.Errorf("could not derive a profile name; pass --name")
			}

			dir := config.ImportedProfilesDir(u.Home)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			dst := filepath.Join(dir, profName+".ovpn")
			if err := os.WriteFile(dst, data, 0o600); err != nil {
				return err
			}
			// Hand the store back to the user (in case this ran under sudo).
			_ = u.ChownTree(config.StateDir(u.Home))

			p, err := profile.Find(u.Home, profName)
			if err != nil {
				return err
			}
			fmt.Printf("Imported %q (%s). Connect with: sudo awsvpn connect %s\n", p.Name, dash(p.Region), p.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "profile name (default: the file's base name)")
	return cmd
}

func looksLikeOvpn(data []byte) bool {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "remote", "client", "dev":
			return true
		}
	}
	return false
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}
