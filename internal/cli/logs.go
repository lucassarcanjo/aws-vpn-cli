package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/larcanjo/awsvpn/internal/config"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show the current connection's log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			u, err := mustUser()
			if err != nil {
				return err
			}
			path := config.LogPath(u.Home)
			f, err := os.Open(path)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no log yet — connect first with `sudo awsvpn connect`")
				}
				return err
			}
			defer f.Close()

			if _, err := io.Copy(os.Stdout, f); err != nil {
				return err
			}
			if !follow {
				return nil
			}
			return followFile(f)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the log (like tail -f)")
	return cmd
}

// followFile polls for appended data until interrupted. Simple and dependency-free.
func followFile(f *os.File) error {
	for {
		time.Sleep(300 * time.Millisecond)
		if _, err := io.Copy(os.Stdout, f); err != nil {
			return err
		}
	}
}
