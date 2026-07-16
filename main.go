// Command awsvpn is a CLI-first, trust-minimal macOS wrapper around AWS Client
// VPN (SAML/SSO). It drives the AWS-signed acvc-openvpn binary over the OpenVPN
// management interface; the SAML assertion is captured in memory and handed to
// the tunnel over the management socket — never to disk or a process argument.
package main

import "github.com/larcanjo/awsvpn/internal/cli"

func main() {
	cli.Execute()
}
