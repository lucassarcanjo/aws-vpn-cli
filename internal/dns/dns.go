// Package dns owns the macOS resolver while a tunnel is up. acvc-openvpn applies
// routes itself but does not touch the system resolver, so internal names won't
// resolve unless we act.
//
// v1 writes the pushed DNS to BOTH the primary service's State: and Setup:
// resolver keys. State: alone (the classic OpenVPN up-script approach) is owned
// by configd and is rewritten from DHCP/IPv6-RA data on any network event — on
// networks whose router advertises RDNSS that clobbered the override within
// minutes, sending queries back to the LAN resolver mid-session. The Setup: key
// is manual ("static") configuration, which IPMonitor ranks above anything
// derived from DHCP or RAs, so the override survives those events; keeping the
// State: write covers the rarer case of a preferences re-sync rewriting Setup:.
// Both writes go to the dynamic store only, so a reboot clears them regardless.
//
// Both keys are captured in full (server addresses AND search domains AND domain
// name) before the write and restored verbatim on disconnect, with a
// crash-safety net: the prior state is stashed to a backup file so the next run
// can restore DNS even if this connection died unexpectedly.
package dns

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Dict is one resolver key's captured DNS dictionary. Present distinguishes "the
// key existed" from "the key existed but was empty" so revert can tell whether to
// restore a dictionary or remove ours.
type Dict struct {
	Present         bool     `json:"present"`
	ServerAddresses []string `json:"server_addresses,omitempty"`
	SearchDomains   []string `json:"search_domains,omitempty"`
	DomainName      string   `json:"domain_name,omitempty"`
}

func (d Dict) empty() bool {
	return len(d.ServerAddresses) == 0 && len(d.SearchDomains) == 0 && d.DomainName == ""
}

// Backup is the resolver state to restore on disconnect: the State: and Setup:
// DNS dictionaries as they were before Apply. Persisted so a later run can
// revert even after a crash.
type Backup struct {
	ServiceID string `json:"service_id"`
	State     Dict   `json:"state"`
	Setup     Dict   `json:"setup"`
}

// Apply sets servers as the primary network service's resolver on both the
// State: and Setup: keys, preserving each key's existing search domains and
// domain name so short names keep resolving, and returns the prior state for
// later reversion. A no-op backup is returned if there are no servers to apply.
func Apply(servers []string) (Backup, error) {
	if len(servers) == 0 {
		return Backup{}, nil
	}
	svc, err := primaryService()
	if err != nil {
		return Backup{}, err
	}
	b := Backup{
		ServiceID: svc,
		State:     captureDNS("State", svc),
		Setup:     captureDNS("Setup", svc),
	}
	if err := setDNS("State", svc, servers, b.State.SearchDomains, b.State.DomainName); err != nil {
		return Backup{}, err
	}
	if err := setDNS("Setup", svc, servers, b.Setup.SearchDomains, b.Setup.DomainName); err != nil {
		// Don't leave a half-applied override behind.
		_ = restoreKey("State", svc, b.State)
		return Backup{}, err
	}
	flushCache()
	return b, nil
}

// Revert restores both resolver keys captured in b. A key that previously held a
// DNS dictionary is put back verbatim; otherwise our override is removed so
// macOS recomputes from DHCP/setup. A zero backup (no service) is a no-op.
func Revert(b Backup) error {
	if b.ServiceID == "" {
		return nil
	}
	err := errors.Join(
		restoreKey("State", b.ServiceID, b.State),
		restoreKey("Setup", b.ServiceID, b.Setup),
	)
	flushCache()
	return err
}

// restoreKey puts one resolver key back to its captured contents.
func restoreKey(prefix, svc string, d Dict) error {
	if d.Present && !d.empty() {
		return setDNS(prefix, svc, d.ServerAddresses, d.SearchDomains, d.DomainName)
	}
	return removeDNS(prefix, svc)
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

// captureDNS reads the full DNS dictionary currently set on one of a service's
// resolver keys (prefix is "State" or "Setup").
func captureDNS(prefix, svc string) Dict {
	out, err := scutil("show " + prefix + ":/Network/Service/" + svc + "/DNS")
	if err != nil || strings.Contains(out, "No such key") {
		return Dict{} // Present stays false
	}
	return Dict{
		Present:         true,
		ServerAddresses: parseArray(out, "ServerAddresses"),
		SearchDomains:   parseArray(out, "SearchDomains"),
		DomainName:      parseScalar(out, "DomainName"),
	}
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

// setDNS writes a DNS dictionary onto one of a service's resolver keys,
// including only the non-empty components.
func setDNS(prefix, svc string, servers, searchDomains []string, domainName string) error {
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
	b.WriteString("set " + prefix + ":/Network/Service/" + svc + "/DNS\n")
	b.WriteString("quit\n")
	return scutilStdin(b.String())
}

// removeDNS deletes our override from one of a service's resolver keys.
func removeDNS(prefix, svc string) error {
	return scutilStdin("remove " + prefix + ":/Network/Service/" + svc + "/DNS\nquit\n")
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
