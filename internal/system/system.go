// Package system is the thin port over every impure side effect the connect
// driver needs: verifying + spawning acvc-openvpn, opening the browser as the
// invoking user, and applying/reverting macOS DNS. Keeping these behind one small
// interface is what lets the reducer and parsers stay pure.
package system

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/dns"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/privilege"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/signature"
)

// Port abstracts the privileged side effects. Production uses Real; tests can
// substitute a fake to exercise the driver without root, a real socket, or a
// browser.
type Port interface {
	VerifySignature(binPath, teamID string) error
	SpawnOpenVPN(spec SpawnSpec) (pid int, err error)
	OpenBrowser(url string) error
	CopyToClipboard(text string) error
	ApplyDNS(servers []string) (dns.Backup, error)
	RevertDNS(b dns.Backup) error
	Kill(pid int) error
	// IsOpenVPN reports whether pid is (still) an acvc-openvpn process, so a
	// teardown never SIGTERMs a recycled pid that now belongs to something else.
	IsOpenVPN(pid int) bool
}

// SpawnSpec configures the acvc-openvpn launch.
type SpawnSpec struct {
	BinPath      string
	ConfigPath   string
	SocketPath   string
	LogFile      *os.File
	RestrictUser string // --management-client-user; "" to skip
}

// Real is the production implementation.
type Real struct {
	User privilege.User
}

// NewReal builds a Real port bound to the invoking user (for browser open).
func NewReal(u privilege.User) *Real { return &Real{User: u} }

// VerifySignature enforces the AWS team-id pin on the binary.
func (r *Real) VerifySignature(binPath, teamID string) error {
	return signature.Verify(binPath, teamID)
}

// SpawnOpenVPN launches acvc-openvpn detached (its own session) so it outlives
// the connect command as a background tunnel, driven over the management socket.
// Its stdout/stderr (secret-free openvpn logs) go to the connection log file.
func (r *Real) SpawnOpenVPN(spec SpawnSpec) (int, error) {
	args := []string{
		"--config", spec.ConfigPath,
		"--management", spec.SocketPath, "unix",
		"--management-hold",
		"--management-query-passwords",
		"--verb", "3",
	}
	if spec.RestrictUser != "" {
		args = append(args, "--management-client-user", spec.RestrictUser)
	}
	cmd := exec.Command(spec.BinPath, args...)
	cmd.Stdout = spec.LogFile
	cmd.Stderr = spec.LogFile
	// Setsid detaches the tunnel from our process group so it is not torn down
	// when connect returns (or the terminal that launched it closes).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawning acvc-openvpn: %w", err)
	}
	return cmd.Process.Pid, nil
}

// OpenBrowser opens the SSO URL as the invoking user.
func (r *Real) OpenBrowser(url string) error { return r.User.OpenBrowser(url) }

// CopyToClipboard puts text on the invoking user's pasteboard.
func (r *Real) CopyToClipboard(text string) error { return r.User.CopyToClipboard(text) }

// ApplyDNS sets the pushed resolver and returns the state to revert to.
func (r *Real) ApplyDNS(servers []string) (dns.Backup, error) { return dns.Apply(servers) }

// RevertDNS restores the resolver captured in b.
func (r *Real) RevertDNS(b dns.Backup) error { return dns.Revert(b) }

// Kill signals a process to terminate.
func (r *Real) Kill(pid int) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}

// IsOpenVPN checks that pid currently maps to an acvc-openvpn process, guarding
// against PID reuse (the recorded openvpn died and its pid was recycled).
func (r *Real) IsOpenVPN(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "acvc-openvpn")
}
