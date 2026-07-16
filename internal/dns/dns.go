// Package dns owns the macOS resolver while a tunnel is up. acvc-openvpn applies
// routes itself but does not touch the system resolver, so internal names won't
// resolve unless we act. v1 sets the pushed DNS as the primary service's
// resolver (matching official-client behaviour) and reverts on disconnect, with
// a crash-safety net: the prior state is stashed to a backup file so the next run
// can restore DNS even if this connection died unexpectedly.
package dns

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// Backup is the resolver state to restore on disconnect. It is persisted so a
// later run can revert even after a crash.
type Backup struct {
	ServiceID       string   `json:"service_id"`
	HadDNS          bool     `json:"had_dns"`
	ServerAddresses []string `json:"server_addresses,omitempty"`
}

// Apply sets servers as the primary network service's resolver and returns the
// prior state for later reversion. A no-op backup is returned if there are no
// servers to apply.
func Apply(servers []string) (Backup, error) {
	if len(servers) == 0 {
		return Backup{}, nil
	}
	svc, err := primaryService()
	if err != nil {
		return Backup{}, err
	}
	prior, had := currentServers(svc)
	b := Backup{ServiceID: svc, HadDNS: had, ServerAddresses: prior}

	if err := setServers(svc, servers); err != nil {
		return Backup{}, err
	}
	flushCache()
	return b, nil
}

// Revert restores the resolver captured in b. If the service previously had DNS
// servers we put them back; otherwise we remove our override so macOS recomputes
// from DHCP/setup. A zero backup (no service) is a no-op.
func Revert(b Backup) error {
	if b.ServiceID == "" {
		return nil
	}
	var err error
	if b.HadDNS && len(b.ServerAddresses) > 0 {
		err = setServers(b.ServiceID, b.ServerAddresses)
	} else {
		err = removeDNS(b.ServiceID)
	}
	flushCache()
	return err
}

// primaryService returns the UUID of the primary network service.
func primaryService() (string, error) {
	out, err := scutil("show State:/Network/Global/IPv4")
	if err != nil {
		return "", fmt.Errorf("reading primary service: %w", err)
	}
	if svc := parsePrimaryService(out); svc != "" {
		return svc, nil
	}
	return "", fmt.Errorf("no primary network service found (are you online?)")
}

// parsePrimaryService extracts the PrimaryService UUID from scutil's
// `show State:/Network/Global/IPv4` output. Pure, for testability.
func parsePrimaryService(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "PrimaryService") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[len(fields)-1]
			}
		}
	}
	return ""
}

// currentServers reads the ServerAddresses currently set on a service's DNS key.
// had is false when the service has no DNS override at all.
func currentServers(svc string) (servers []string, had bool) {
	out, err := scutil("show State:/Network/Service/" + svc + "/DNS")
	if err != nil || strings.Contains(out, "No such key") {
		return nil, false
	}
	return parseServerAddresses(out), true
}

// parseServerAddresses extracts the ServerAddresses array from a scutil DNS
// dictionary dump. Pure, so it can be tested against real scutil output.
func parseServerAddresses(out string) []string {
	var servers []string
	inArray := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "ServerAddresses"):
			inArray = true
		case inArray && line == "}":
			inArray = false
		case inArray:
			// entries look like "0 : 192.168.15.1" — split on the FIRST colon
			// only, so IPv6 addresses (which contain colons) survive intact.
			if i := strings.Index(line, ":"); i >= 0 {
				if addr := strings.TrimSpace(line[i+1:]); addr != "" {
					servers = append(servers, addr)
				}
			}
		}
	}
	return servers
}

// setServers writes ServerAddresses onto a service's runtime DNS key.
func setServers(svc string, servers []string) error {
	var b strings.Builder
	b.WriteString("d.init\n")
	b.WriteString("d.add ServerAddresses * " + strings.Join(servers, " ") + "\n")
	b.WriteString("set State:/Network/Service/" + svc + "/DNS\n")
	b.WriteString("quit\n")
	return scutilStdin(b.String())
}

// removeDNS deletes our runtime DNS override for a service.
func removeDNS(svc string) error {
	return scutilStdin("remove State:/Network/Service/" + svc + "/DNS\nquit\n")
}

func flushCache() {
	// Best-effort: signal the resolver to drop cached answers so the new DNS
	// takes effect immediately. Failures are non-fatal.
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}

// scutil runs a single read command through scutil's interactive stdin.
func scutil(cmd string) (string, error) {
	return scutilOut(cmd + "\nquit\n")
}

func scutilOut(stdin string) (string, error) {
	c := exec.Command("scutil")
	c.Stdin = strings.NewReader(stdin)
	out, err := c.CombinedOutput()
	return string(out), err
}

func scutilStdin(stdin string) error {
	c := exec.Command("scutil")
	c.Stdin = strings.NewReader(stdin)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("scutil: %w: %s", err, out)
	}
	return nil
}
