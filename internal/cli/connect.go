package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/config"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/daemon"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/launchd"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/privilege"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/profile"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/ui"
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	var allowUnverified bool
	cmd := &cobra.Command{
		Use:   "connect [profile]",
		Short: "Connect to a VPN profile",
		Long: "Connect to a profile by name, or with no argument pick one interactively.\n" +
			"Returns control to your shell once the tunnel is up; the tunnel runs in the\n" +
			"background until `awsvpn disconnect`.",
		Example: fmt.Sprintf("  %[1]sawsvpn connect dev\n"+
			"  %[1]sawsvpn connect          # pick a profile\n"+
			"  %[1]sawsvpn connect dev -v   # stream the raw connection log", sudoPrefix()),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ensureRoot("connect", "to manage the tunnel"); err != nil {
				return err
			}
			u, err := mustUser()
			if err != nil {
				return err
			}

			var prof profile.Profile
			if len(args) == 1 {
				prof, err = profile.Find(u.Home, args[0])
			} else {
				prof, err = pickProfile(u.Home)
			}
			if err != nil {
				return err
			}

			logFile, err := daemon.PrepareLog()
			if err != nil {
				return err
			}
			defer logFile.Close()

			// The connection log keeps the full, durable record. The terminal gets
			// a narration of the same events written for a person — unless
			// --verbose, where the raw log is mirrored to stderr as well (and the
			// narration stops animating, so the two streams don't fight over a
			// line). Both writers go through the same redactor, so the assertion
			// can't leak to either.
			red := logging.NewRedactor()
			out := io.Writer(logFile)
			report := ui.NewSteps(os.Stderr)
			if verbose {
				out = io.MultiWriter(logFile, os.Stderr)
				report = ui.NewStaticSteps(os.Stderr)
			}
			logger := logging.New(out, red, verbose)
			defer report.Stop()

			st := ui.For(os.Stderr)
			fmt.Fprintf(os.Stderr, "\n%s %s\n\n", st.Dim("connecting to"), st.Bold(prof.Name))

			// Boot out any supervisor from a prior connection BEFORE connecting.
			// daemon.Connect tears down an existing tunnel as part of the swap; if
			// its supervisor were still watching, it would see that teardown as a
			// drop and revert DNS / clear state — racing (and clobbering) the tunnel
			// we're about to bring up. Its SIGTERM handler exits cleanly, no teardown.
			if err := launchd.Uninstall(); err != nil {
				logger.Info("warning: could not clear a previous connection supervisor: %v", err)
			}

			run, err := daemon.Connect(daemon.Options{
				Profile:         prof,
				Sys:             system.NewReal(u),
				Logger:          logger,
				LogFile:         logFile,
				UI:              report,
				AllowUnverified: allowUnverified,
			})
			if err != nil {
				report.Stop()
				return fmt.Errorf("%w\nWhat happened in full: awsvpn logs", err)
			}

			// Register the connection supervisor: a root LaunchDaemon that watches
			// the tunnel and, if it drops and can't self-heal, tears it down
			// cleanly (restoring DNS/routes) and notifies — so a sleep/outage never
			// leaves the machine blackholed behind a dead tunnel. Non-fatal: the
			// tunnel is up regardless; we just warn if auto-recovery is unavailable.
			supervised := false
			if self, exeErr := os.Executable(); exeErr != nil {
				logger.Info("warning: could not locate this binary to start the supervisor: %v", exeErr)
				report.Warn("auto-recovery on drop is off: could not locate this binary (%v)", exeErr)
			} else if err := launchd.Install(launchd.Spec{
				Exe: self, UID: u.UID, Profile: run.Profile, LogPath: config.LogPath(),
			}); err != nil {
				logger.Info("warning: connection supervisor not started (auto-recovery on drop disabled): %v", err)
				report.Warn("auto-recovery on drop is off: %v", err)
			} else {
				supervised = true
			}

			report.Stop()
			printConnected(os.Stdout, run, supervised)
			suggestGrant(os.Stdout)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUnverified, "allow-unverified-binary", false,
		"skip the acvc-openvpn signature check (only for a legitimate AWS signing-identity change)")
	return cmd
}

// suggestGrant points at the one-time opt-in at the only moment it really
// lands: just after the user has typed `sudo` to get here. It stays quiet once
// the grant exists, which keeps it a nudge rather than a nag.
func suggestGrant(w io.Writer) {
	if privilege.GrantInstalled() {
		return
	}
	fmt.Fprintln(w)
	ui.Hint(w, "Skip the `sudo` prefix next time: sudo awsvpn install-privilege")
}

// pickProfile lets the user choose interactively: fzf if present, else a numbered
// prompt.
func pickProfile(home string) (profile.Profile, error) {
	profiles, err := profile.Discover(home)
	if err != nil {
		return profile.Profile{}, err
	}
	if len(profiles) == 0 {
		return profile.Profile{}, fmt.Errorf("no profiles found — add one in the AWS VPN Client or run `awsvpn import <file.ovpn>`")
	}
	if len(profiles) == 1 {
		return profiles[0], nil
	}
	if p, ok, err := pickWithFzf(profiles); err != nil {
		return profile.Profile{}, err
	} else if ok {
		return p, nil
	}
	return pickWithPrompt(profiles)
}

func pickWithFzf(profiles []profile.Profile) (profile.Profile, bool, error) {
	fzf, err := exec.LookPath("fzf")
	if err != nil {
		return profile.Profile{}, false, nil // fzf not installed; caller falls back
	}
	// Each line is a padded, human-readable column set followed by the exact
	// profile name in a hidden field. fzf shows and searches only the first
	// field (--with-nth=1); we read the name back from the second, so a profile
	// name containing spaces still round-trips exactly.
	width := nameWidth(profiles)
	var input strings.Builder
	for _, p := range profiles {
		fmt.Fprintf(&input, "%s  %-14s %s\t%s\n",
			pad(p.Name, width), dash(p.Region), dash(p.EndpointID), p.Name)
	}
	c := exec.Command(fzf,
		"--delimiter=\t", "--with-nth=1", "--no-multi", "--reverse", "--height=40%",
		"--prompt=profile "+ui.Arrow+" ",
		"--header=enter to connect · esc to cancel")
	c.Stdin = strings.NewReader(input.String())
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		// Non-zero exit means the user aborted the picker (Esc/Ctrl-C).
		return profile.Profile{}, false, fmt.Errorf("selection cancelled")
	}
	fields := strings.Split(strings.TrimRight(string(out), "\n"), "\t")
	name := fields[len(fields)-1]
	for _, p := range profiles {
		if p.Name == name {
			return p, true, nil
		}
	}
	return profile.Profile{}, false, fmt.Errorf("selection %q not found", name)
}

// pickWithPrompt is the no-fzf fallback: an arrow-key list on a terminal, and a
// typed prompt when there isn't one to drive (a pipe, a script, CI).
func pickWithPrompt(profiles []profile.Profile) (profile.Profile, error) {
	width := nameWidth(profiles)
	choices := make([]ui.Choice, len(profiles))
	for i, p := range profiles {
		choices[i] = ui.Choice{Label: pad(p.Name, width), Note: dash(p.Region)}
	}
	i, err := ui.Select(os.Stdin, os.Stderr, "Which profile?", choices)
	switch {
	case err == nil:
		return profiles[i], nil
	case errors.Is(err, ui.ErrNoTerminal):
		return pickByTyping(profiles)
	default:
		return profile.Profile{}, err
	}
}

// pickByTyping is the non-interactive form: a numbered list that accepts a number
// or the profile name, because typing "dev" is the first thing anyone tries.
func pickByTyping(profiles []profile.Profile) (profile.Profile, error) {
	s := ui.For(os.Stderr)
	width := nameWidth(profiles)
	fmt.Fprintf(os.Stderr, "\n  %s\n\n", s.Bold("Which profile?"))
	for i, p := range profiles {
		fmt.Fprintf(os.Stderr, "  %s  %s  %s\n",
			s.Dim(fmt.Sprintf("%2d", i+1)), pad(p.Name, width), s.Dim(dash(p.Region)))
	}
	fmt.Fprintf(os.Stderr, "\n  %s ", s.Cyan(ui.Arrow))

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return profile.Profile{}, fmt.Errorf("reading selection: %w", err)
	}
	fmt.Fprintln(os.Stderr)

	choice := strings.TrimSpace(line)
	if n, err := strconv.Atoi(choice); err == nil {
		if n < 1 || n > len(profiles) {
			return profile.Profile{}, fmt.Errorf("there is no profile %d — pick between 1 and %d", n, len(profiles))
		}
		return profiles[n-1], nil
	}
	for _, p := range profiles {
		if strings.EqualFold(p.Name, choice) {
			return p, nil
		}
	}
	return profile.Profile{}, fmt.Errorf("no profile matches %q — pick a number, or a name from the list", choice)
}

func nameWidth(profiles []profile.Profile) int {
	width := 0
	for _, p := range profiles {
		if len(p.Name) > width {
			width = len(p.Name)
		}
	}
	return width
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
