package ovpn

import "strings"

// The management channel prefixes real-time notifications with ">". These
// predicates classify the lines the connection reducer cares about; everything
// else (log spam, byte counts, intermediate states) is ignored by the reducer.

// IsHold reports whether the line is a hold notification. acvc-openvpn re-enters
// hold on every soft restart, so the reducer must release on each one.
func IsHold(line string) bool {
	return strings.HasPrefix(line, ">HOLD:")
}

// IsPasswordNeed reports a fresh credential prompt, e.g.
// ">PASSWORD:Need 'Auth' username/password".
func IsPasswordNeed(line string) bool {
	return strings.HasPrefix(line, ">PASSWORD:Need '")
}

// IsVerificationFailed reports a rejected credential, e.g.
// ">PASSWORD:Verification Failed: 'Auth' ['CRV1:...']". This carries the CRV1
// challenge on the first (dummy) attempt and a hard rejection thereafter.
func IsVerificationFailed(line string) bool {
	return strings.HasPrefix(line, ">PASSWORD:Verification Failed")
}

// IsFatal reports a fatal error notification.
func IsFatal(line string) bool {
	return strings.HasPrefix(line, ">FATAL:")
}

// IsAuthFailed reports a hard authentication failure control message. Matched on
// the exact uppercase token so the soft-restart lines ("auth-failure",
// "SIGUSR1[soft,auth-failure]") — which are expected, not terminal — do not trip
// it. AWS delivers the first-attempt SAML challenge as "AUTH_FAILED,CRV1:...",
// which with `log on` reaches us as a >LOG: line before the >PASSWORD:
// notification that carries the same challenge; that variant is the start of the
// auth dance, not a failure, so it must not match either.
func IsAuthFailed(line string) bool {
	return strings.Contains(line, "AUTH_FAILED") &&
		!strings.Contains(line, "AUTH_FAILED,CRV1:")
}

// IsPushReply reports whether the line carries a PUSH_REPLY control message.
func IsPushReply(line string) bool {
	return strings.Contains(line, "PUSH_REPLY")
}

// ParsePasswordRealm returns the realm named in a >PASSWORD: line — the text
// between the first pair of single quotes (e.g. "Auth"). Used to echo the realm
// back in the username/password reply.
func ParsePasswordRealm(line string) string {
	start := strings.IndexByte(line, '\'')
	if start < 0 {
		return ""
	}
	rest := line[start+1:]
	end := strings.IndexByte(rest, '\'')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// ConnInfo is the endpoint/assignment data carried on the CONNECTED state line.
type ConnInfo struct {
	AssignedIP string
	RemoteIP   string
	Port       string
}

// StateName returns the state name from a >STATE: line (field index 1), e.g.
// "CONNECTED", "RECONNECTING", "EXITING". ok=false if the line is not a state.
func StateName(line string) (string, bool) {
	if !strings.HasPrefix(line, ">STATE:") {
		return "", false
	}
	fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
	if len(fields) < 2 {
		return "", false
	}
	return fields[1], true
}

// ParseConnected parses a CONNECTED state line, e.g.
//
//	>STATE:1784222495,CONNECTED,SUCCESS,10.8.0.133,203.0.113.10,443,,
//
// Field layout: time,name,description,localIP,remoteIP,port,... Returns
// ok=false unless the line names the CONNECTED state.
func ParseConnected(line string) (ConnInfo, bool) {
	name, ok := StateName(line)
	if !ok || name != "CONNECTED" {
		return ConnInfo{}, false
	}
	fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
	var ci ConnInfo
	if len(fields) > 3 {
		ci.AssignedIP = fields[3]
	}
	if len(fields) > 4 {
		ci.RemoteIP = fields[4]
	}
	if len(fields) > 5 {
		ci.Port = fields[5]
	}
	return ci, true
}
