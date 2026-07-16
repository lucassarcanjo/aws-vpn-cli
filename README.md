# awsvpn

Connect to a SAML/SSO AWS Client VPN endpoint from your macOS terminal.

```sh
sudo awsvpn connect dev
```

`awsvpn` starts the AWS-signed VPN engine installed by the official AWS VPN
Client, then returns control to your shell. Use it from a terminal, script, or
agent without a menu bar app or a manually opened browser tab.

## Why awsvpn

VPN clients run as root, change DNS and routes, and handle a bearer credential.
`awsvpn` keeps the privileged part small and inspectable:

- It runs the AWS-signed `acvc-openvpn` binary from the official AWS VPN Client.
  Before root executes it, `awsvpn` verifies its Apple signature and pins AWS's
  team identifier, `94KV3E626L`.
- It keeps the SAML assertion in memory. The assertion never appears in a file
  or process argument; `awsvpn` passes it to OpenVPN over its management socket.
- It vendors its small dependency set and builds from source. Each connection
  uses `sudo`; `install-privilege` is an explicit opt-in for automation.

Read the [security model](docs/security.md) before using it on a system you care
about.

## Requirements

- macOS.
- The [official AWS VPN Client](https://aws.amazon.com/vpn/client-vpn-download/),
  which provides the signed `acvc-openvpn` binary.
- Go 1.24 or later.

## Install

Build it from source:

```sh
go install github.com/lucassarcanjo/aws-vpn-cli@latest
```

Or install from a clone:

```sh
git clone https://github.com/lucassarcanjo/aws-vpn-cli && cd aws-vpn-cli
make install
```

`Formula/awsvpn.rb` provides a Homebrew formula that also builds from source.

## Usage

```sh
awsvpn list                     # profiles from AWS VPN Client + imports
sudo awsvpn connect dev         # connect by name
sudo awsvpn connect             # choose a profile
awsvpn status                   # profile, assigned IP, uptime
sudo awsvpn disconnect          # remove routes and restore DNS
awsvpn logs -f                  # follow the connection log
awsvpn import ./client.ovpn     # register a config outside the AWS client
awsvpn version
sudo awsvpn install-privilege   # opt-in NOPASSWD rule for automation
```

`awsvpn` reads profiles from the AWS VPN Client without changing its store and
merges them with imported profiles. It supports one active connection; a new
connection replaces the current tunnel.

## Security

- `awsvpn` verifies the AWS VPN binary immediately before it runs as root.
- It binds the SAML callback to `127.0.0.1:35001` before opening your browser
  and aborts if another process already owns the port.
- Root-owned runtime state lives in `/var/run/awsvpn`; imported profiles remain
  in your home directory.
- The fixed AWS callback port, running the wrapper as root, and a passwordless
  sudo rule each carry residual risk.

See the [full threat model and connection flow](docs/security.md).

## Development

```sh
make test
make vet
make vuln        # requires: go install golang.org/x/vuln/cmd/govulncheck@latest
make build
```

## License

MIT. See [LICENSE](LICENSE).
