package cli

import (
	"bufio"
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
	"github.com/lucassarcanjo/aws-vpn-cli/internal/profile"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
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
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot("connect"); err != nil {
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

			// Log to the connection file (durable record) and mirror progress to
			// stderr so the user sees what's happening. Both go through the same
			// redactor, so the assertion can't leak to either.
			red := logging.NewRedactor()
			out := io.MultiWriter(logFile, os.Stderr)
			logger := logging.New(out, red, verbose)

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
				AllowUnverified: allowUnverified,
			})
			if err != nil {
				return err
			}

			fmt.Printf("\nConnected to %s (%s). Your shell is free — the tunnel runs in the background.\n",
				run.Profile, run.AssignedIP)

			// Register the connection supervisor: a root LaunchDaemon that watches
			// the tunnel and, if it drops and can't self-heal, tears it down
			// cleanly (restoring DNS/routes) and notifies — so a sleep/outage never
			// leaves the machine blackholed behind a dead tunnel. Non-fatal: the
			// tunnel is up regardless; we just warn if auto-recovery is unavailable.
			if self, exeErr := os.Executable(); exeErr != nil {
				logger.Info("warning: could not locate this binary to start the supervisor: %v", exeErr)
			} else if err := launchd.Install(launchd.Spec{
				Exe: self, UID: u.UID, Profile: run.Profile, LogPath: config.LogPath(),
			}); err != nil {
				logger.Info("warning: connection supervisor not started (auto-recovery on drop disabled): %v", err)
			} else {
				fmt.Println("If the connection drops, it will be torn down automatically and you'll be notified.")
			}

			fmt.Println("Check it with `awsvpn status`; tear it down with `sudo awsvpn disconnect`.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUnverified, "allow-unverified-binary", false,
		"skip the acvc-openvpn signature check (only for a legitimate AWS signing-identity change)")
	return cmd
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
	var input strings.Builder
	for _, p := range profiles {
		fmt.Fprintf(&input, "%s\t%s\t%s\n", p.Name, dash(p.Region), dash(p.EndpointID))
	}
	c := exec.Command(fzf, "--with-nth=1,2,3", "--delimiter=\t", "--prompt=profile> ", "--height=40%")
	c.Stdin = strings.NewReader(input.String())
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		// Non-zero exit means the user aborted the picker (Esc/Ctrl-C).
		return profile.Profile{}, false, fmt.Errorf("selection cancelled")
	}
	name := strings.SplitN(strings.TrimSpace(string(out)), "\t", 2)[0]
	for _, p := range profiles {
		if p.Name == name {
			return p, true, nil
		}
	}
	return profile.Profile{}, false, fmt.Errorf("selection %q not found", name)
}

func pickWithPrompt(profiles []profile.Profile) (profile.Profile, error) {
	fmt.Fprintln(os.Stderr, "Select a profile:")
	for i, p := range profiles {
		fmt.Fprintf(os.Stderr, "  %d) %s  (%s)\n", i+1, p.Name, dash(p.Region))
	}
	fmt.Fprint(os.Stderr, "> ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return profile.Profile{}, fmt.Errorf("reading selection: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(profiles) {
		return profile.Profile{}, fmt.Errorf("invalid selection %q", strings.TrimSpace(line))
	}
	return profiles[n-1], nil
}
