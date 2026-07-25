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
awsvpn status                   # state, IP, endpoint, DNS, tunnel mode, uptime
sudo awsvpn disconnect          # remove routes and restore DNS
awsvpn logs -f                  # follow the connection log
awsvpn import ./client.ovpn     # register a config outside the AWS client
awsvpn version
sudo awsvpn install-privilege   # opt-in NOPASSWD rule; connect/disconnect then
                                # elevate themselves, no `sudo` prefix needed
awsvpn uninstall-privilege      # revoke that rule
```

`awsvpn` reads profiles from the AWS VPN Client without changing its store and
merges them with imported profiles. It supports one active connection; a new
connection replaces the current tunnel.

While `connect` waits for single sign-on, press `Enter` to re-open the page or
`c` then `Enter` to copy the link — useful when `open` hands it to a browser you
aren't signed in with. `connect -v` streams the raw connection log instead of
the progress summary.

`list` and `status` take `--json` for scripts and agents. `status` reports
`connected`, `connecting`, `stale`, or `disconnected`. Colour follows the
terminal and respects [`NO_COLOR`](https://no-color.org).

Other flags: `import --name` sets the profile name, `install-privilege --yes`
skips the confirmation prompt, and `connect --allow-unverified-binary` skips the
signature check — only for a signing-identity change you have verified yourself.

## If the tunnel drops

A successful `connect` registers a supervisor: a root LaunchDaemon that watches
the tunnel's management channel for the rest of the session. If the connection
drops and cannot come back on its own within a minute — or comes back needing a
fresh browser sign-in, which no background daemon should attempt — the
supervisor tears the tunnel down, restores your DNS and routes, and posts a
desktop notification. A laptop that sleeps through an outage wakes up with
working networking rather than traffic pointed into a dead tunnel.

The supervisor exists only while a connection does: `disconnect` (and the next
`connect`) removes it. If it cannot be started, `connect` says so and the tunnel
still comes up — you just clean up by hand.

## Security

- `awsvpn` verifies the AWS VPN binary immediately before it runs as root.
- It binds the SAML callback to `127.0.0.1:35001` before opening your browser
  and aborts if another process already owns the port.
- Root-owned runtime state lives in `/var/run/awsvpn`; imported profiles remain
  in your home directory.
- Nothing of `awsvpn` runs as root between connections: the drop supervisor is
  registered on connect and removed on disconnect.
- The fixed AWS callback port, running the wrapper as root, the root supervisor
  while connected, and a passwordless sudo rule each carry residual risk.

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
