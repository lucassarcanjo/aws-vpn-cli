package ovpn

import "strings"

// Route is a single pushed route (network + netmask).
type Route struct {
	Network string
	Netmask string
}

// PushReply is the subset of an OpenVPN PUSH_REPLY that awsvpn acts on: the DNS
// servers (which we must apply to the macOS resolver ourselves, since
// acvc-openvpn does not) and the routes (which acvc-openvpn applies itself; we
// only record them for `status`).
type PushReply struct {
	DNS        []string
	Routes     []Route
	Gateway    string
	FullTunnel bool
}

// ParsePushReply parses a PUSH_REPLY control message. It accepts either the bare
// control message ("PUSH_REPLY,dhcp-option DNS 10.0.0.2,...") or a full
// management log line that contains one; the payload may be wrapped in quotes.
// Observed shape (split-tunnel, single internal DNS):
//
//	PUSH_REPLY,dhcp-option DNS 10.0.0.2,route 10.0.0.0 255.255.0.0,
//	route 172.16.8.0 255.255.248.0,route-gateway 10.8.0.129,topology subnet,...
func ParsePushReply(s string) (PushReply, bool) {
	idx := strings.Index(s, "PUSH_REPLY")
	if idx < 0 {
		return PushReply{}, false
	}
	s = s[idx:]
	// The control message is quoted in log lines; cut at the closing quote.
	// s starts with PUSH_REPLY (no quote), so the first quote is the terminator.
	if end := strings.IndexAny(s, "'\""); end >= 0 {
		s = s[:end]
	}

	var pr PushReply
	for _, tok := range strings.Split(s, ",") {
		fields := strings.Fields(tok)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "dhcp-option":
			if len(fields) >= 3 && strings.EqualFold(fields[1], "DNS") {
				pr.DNS = append(pr.DNS, fields[2])
			}
		case "route":
			if len(fields) >= 3 {
				pr.Routes = append(pr.Routes, Route{Network: fields[1], Netmask: fields[2]})
				// A default route pushed as a plain route also means full tunnel.
				if fields[1] == "0.0.0.0" {
					pr.FullTunnel = true
				}
			}
		case "route-gateway":
			if len(fields) >= 2 {
				pr.Gateway = fields[1]
			}
		case "redirect-gateway":
			pr.FullTunnel = true
		}
	}
	return pr, true
}
