// Package dns owns the macOS resolver while a tunnel is up. acvc-openvpn applies
// routes itself but does not touch the system resolver, so internal names won't
// resolve unless we act. v1 sets the pushed DNS as the primary service's
// resolver (matching official-client behaviour) and reverts on disconnect, with
// a crash-safety net: the prior state is stashed to a backup file so the next run
// can restore DNS even if this connection died unexpectedly.
//
// We capture and restore the whole DNS dictionary (server addresses AND search
// domains AND domain name), not just the servers, so a disconnect leaves
// short-name resolution exactly as it found it.
package dns

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// Backup is the resolver state to restore on disconnect. Persisted so a later run
// can revert even after a crash.
type Backup struct {
	ServiceID       string   `json:"service_id"`
	HadDNS          bool     `json:"had_dns"`
	ServerAddresses []string `json:"server_addresses,omitempty"`
	SearchDomains   []string `json:"search_domains,omitempty"`
	DomainName      string   `json:"domain_name,omitempty"`
}

func (b Backup) empty() bool {
	return len(b.ServerAddresses) == 0 && len(b.SearchDomains) == 0 && b.DomainName == ""
}

// Apply sets servers as the primary network service's resolver, preserving the
// service's existing search domains and domain name so short names keep
// resolving, and returns the prior state for later reversion. A no-op backup is
// returned if there are no servers to apply.
func Apply(servers []string) (Backup, error) {
	if len(servers) == 0 {
		return Backup{}, nil
	}
	svc, err := primaryService()
	if err != nil {
		return Backup{}, err
	}
	prior := captureDNS(svc)

	if err := setDNS(svc, servers, prior.SearchDomains, prior.DomainName); err != nil {
		return Backup{}, err
	}
	flushCache()
	return prior, nil
}

// Revert restores the resolver captured in b. If the service previously had a DNS
// dictionary we put it back verbatim; otherwise we remove our override so macOS
// recomputes from DHCP/setup. A zero backup (no service) is a no-op.
func Revert(b Backup) error {
	if b.ServiceID == "" {
		return nil
	}
	var err error
	if b.HadDNS && !b.empty() {
		err = setDNS(b.ServiceID, b.ServerAddresses, b.SearchDomains, b.DomainName)
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

// parsePrimaryService extracts the PrimaryService UUID. Pure, for testability.
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

// captureDNS reads the full DNS dictionary currently set on a service.
func captureDNS(svc string) Backup {
	b := Backup{ServiceID: svc}
	out, err := scutil("show State:/Network/Service/" + svc + "/DNS")
	if err != nil || strings.Contains(out, "No such key") {
		return b // HadDNS stays false
	}
	b.HadDNS = true
	b.ServerAddresses = parseArray(out, "ServerAddresses")
	b.SearchDomains = parseArray(out, "SearchDomains")
	b.DomainName = parseScalar(out, "DomainName")
	return b
}

// parseArray extracts a named `<key> : <array> { … }` block's values from a scutil
// dictionary dump. Pure, tested against real scutil output.
func parseArray(out, key string) []string {
	var vals []string
	inArray := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !inArray {
			if strings.HasPrefix(line, key+" :") && strings.Contains(line, "<array>") {
				inArray = true
			}
			continue
		}
		if line == "}" {
			inArray = false
			continue
		}
		// entries look like "0 : 192.168.15.1" — split on the first colon so
		// IPv6 addresses (which contain colons) survive intact.
		if i := strings.Index(line, ":"); i >= 0 {
			if v := strings.TrimSpace(line[i+1:]); v != "" {
				vals = append(vals, v)
			}
		}
	}
	return vals
}

// parseScalar extracts a named scalar (e.g. "DomainName : Home") value. Pure.
func parseScalar(out, key string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, key+" :") && !strings.Contains(line, "<array>") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

// setDNS writes a DNS dictionary onto a service's runtime DNS key, including only
// the non-empty components.
func setDNS(svc string, servers, searchDomains []string, domainName string) error {
	var b strings.Builder
	b.WriteString("d.init\n")
	if len(servers) > 0 {
		b.WriteString("d.add ServerAddresses * " + strings.Join(servers, " ") + "\n")
	}
	if len(searchDomains) > 0 {
		b.WriteString("d.add SearchDomains * " + strings.Join(searchDomains, " ") + "\n")
	}
	if domainName != "" {
		b.WriteString("d.add DomainName " + domainName + "\n")
	}
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
	c := exec.Command("scutil")
	c.Stdin = strings.NewReader(cmd + "\nquit\n")
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
