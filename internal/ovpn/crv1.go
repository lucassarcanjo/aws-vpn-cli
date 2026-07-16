// Package ovpn holds pure parsers for the OpenVPN management protocol as spoken
// by AWS's acvc-openvpn: the CRV1/SAML challenge, PUSH_REPLY, and the handful of
// real-time notifications the connection reducer reacts to. Everything here is a
// pure function of its input string so it can be unit-tested against transcripts
// captured from a real endpoint.
package ovpn

import "strings"

// CRV1Challenge is the parsed dynamic-challenge the endpoint returns after the
// first (dummy) auth attempt. Only the state id and SAML URL matter to us.
type CRV1Challenge struct {
	// State is the opaque session id echoed back in the CRV1 response. Real
	// values contain slashes, e.g. "instance-1/<serial>/<uuid>".
	State string
	// SAMLURL is the IdP URL to open in the browser.
	SAMLURL string
}

// ParseCRV1Challenge extracts the CRV1 state id and SAML URL from a management
// line of the documented form:
//
//	>PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:<state>:<b64user>:<samlURL>']
//
// The payload is OpenVPN's standard dynamic-challenge encoding
// (CRV1:<flags>:<state>:<base64-user>:<challenge-text>); AWS puts the SAML URL
// in the trailing challenge-text field, which itself contains colons, so it is
// kept whole. Returns ok=false if the line carries no parseable CRV1 payload.
func ParseCRV1Challenge(line string) (CRV1Challenge, bool) {
	idx := strings.Index(line, "CRV1:")
	if idx < 0 {
		return CRV1Challenge{}, false
	}
	payload := line[idx:]

	// Drop the documented wrapper: ['CRV1:...'] → strip a trailing quote+bracket.
	payload = strings.TrimSuffix(payload, "']")
	payload = strings.TrimSuffix(payload, "\"]")

	// CRV1:<flags>:<state>:<b64user>:<challenge-text>. The challenge-text (the
	// SAML URL) is the remainder, so cap the split at 5 fields.
	parts := strings.SplitN(payload, ":", 5)
	if len(parts) < 5 {
		return CRV1Challenge{}, false
	}
	c := CRV1Challenge{State: parts[2], SAMLURL: parts[4]}
	if c.State == "" || c.SAMLURL == "" {
		return CRV1Challenge{}, false
	}
	return c, true
}
