package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:     "logs",
		Short:   "Show the current connection's log",
		Example: "  awsvpn logs\n  awsvpn logs -f",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := os.Open(config.LogPath())
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no log yet — connect first with `%sawsvpn connect`", sudoPrefix())
				}
				return err
			}
			defer f.Close()
			return streamLog(f, os.Stdout, follow)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the log (like tail -f)")
	return cmd
}

// streamLog writes the log a line at a time, styling each as it goes. With
// follow it parks at EOF and resumes when more is appended — a partial last line
// is held back rather than being printed as if it were complete.
func streamLog(f *os.File, w io.Writer, follow bool) error {
	s := ui.For(w)
	r := bufio.NewReader(f)
	var partial string
	for {
		line, err := r.ReadString('\n')
		switch {
		case err == nil:
			fmt.Fprintln(w, styleLogLine(s, trimNewline(partial+line)))
			partial = ""
		case errors.Is(err, io.EOF):
			partial += line
			if !follow {
				if partial != "" {
					fmt.Fprintln(w, styleLogLine(s, partial))
				}
				return nil
			}
			time.Sleep(300 * time.Millisecond)
		default:
			return err
		}
	}
}

// logLine matches the timestamp+level prefix our own logger writes. openvpn's
// lines, which share the file, don't match and pass through untouched.
var logLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})  (\w+) (.*)$`)

// styleLogLine dims the furniture — timestamp and level — so the eye lands on
// the message. Off the terminal the Styler is a no-op, so `awsvpn logs | grep`
// still sees exactly what the file holds.
func styleLogLine(s ui.Styler, line string) string {
	m := logLine.FindStringSubmatch(line)
	if m == nil {
		return line
	}
	level := s.Dim(m[2])
	if m[2] == "INFO" {
		level = s.Cyan(m[2])
	}
	return fmt.Sprintf("%s %s %s", s.Dim(m[1]), level, m[3])
}

func trimNewline(s string) string {
	if n := len(s); n > 0 && s[n-1] == '\n' {
		return s[:n-1]
	}
	return s
}
