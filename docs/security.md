# Security model

`awsvpn` connects to AWS Client VPN as root. It can change your routes and DNS,
and it handles a SAML assertion that authenticates you until it expires. Read
the source before granting it that access.

## Trust boundary

`awsvpn` does not ship or patch a VPN engine. It starts the AWS-signed
`acvc-openvpn` binary installed with the official AWS VPN Client. Before it
executes that binary as root, it verifies the Apple code signature and pins
AWS's team identifier, `94KV3E626L`.

The SAML assertion stays in memory. `awsvpn` receives it through a one-shot
loopback callback, sends it to OpenVPN over the management socket, then drops
it. It does not write the assertion to disk or pass it through `argv`.

The project vendors `cobra` and its two transitive dependencies. `go build` can
build the source tree without fetching dependencies. Connections use `sudo` per
run unless you explicitly install a narrow passwordless-sudo rule.

## Connection flow

1. `awsvpn` verifies `acvc-openvpn` and starts it with a management socket.
2. OpenVPN requests SAML authentication and returns a CRV1 challenge with the
   SAML URL.
3. `awsvpn` binds `127.0.0.1:35001`, opens the URL in your browser, and accepts
   one callback.
4. `awsvpn` sends the assertion through the management socket to complete the
   CRV1 handshake.
5. After OpenVPN connects, `awsvpn` applies pushed DNS through `scutil` and
   records state so it can restore DNS after a disconnect or crash.

The connection reducer in `internal/reducer` is a pure state machine. Tests
drive it with real management transcripts. Signature verification, socket I/O,
browser launch, `scutil`, and daemonization sit behind a thin system port.

## Mitigated risks

### Untrusted VPN code running as root

The privileged tunnel engine is AWS's signed binary. `awsvpn` verifies its
signature and root ownership immediately before execution. It rejects a binary
that is writable by its group or other users. Use
`--allow-unverified-binary` only when AWS has changed its signing identity and
you have verified the replacement.

### Assertions and secrets leaking

`awsvpn` stores the SAML assertion and management password in memory. It
redacts them from its own logs, including with `--verbose`; redacted output shows
only the length. The assertion never reaches a file or process argument.

### Sending the assertion to an unexpected listener

Before `awsvpn` opens your browser, it binds `127.0.0.1:35001`. If the port is
in use, the connection stops. The callback accepts one request and times out.

### DNS left behind after a crash

When `awsvpn` applies DNS, it records the current resolver state. On the next
run it restores DNS if a previous connection did not clean up. It preserves the
resolver's servers, search domains, and domain name.

### Root writing through a planted symlink

Active-tunnel state, DNS rollback data, the management socket, and the
connection log live under root-owned `/var/run/awsvpn`, not a user-writable
directory. Imported profiles remain in your home directory. `awsvpn` uses
`Lchown` and opens logs with `O_NOFOLLOW`.

### Signalling a reused PID

Before it signals the stored tunnel PID, `awsvpn` confirms the process remains
`acvc-openvpn`. It does not signal a process that only reused the PID.

## Residual risks

### A local process wins the callback port race

AWS fixes the SAML consumer at `http://127.0.0.1:35001`. A hostile local process
that binds that port before `awsvpn` can receive an assertion. The official AWS
client shares this constraint. Binding before the browser opens prevents
`awsvpn` from continuing when another process owns the port, but it cannot stop
a process that wins the race first.

### The wrapper runs as root

`awsvpn` keeps root for the connection process. It runs browser opening and
profile discovery as your user, and it changes ownership of files it creates
back to you. The wrapper still has root access while it connects.

### `install-privilege` creates a standing grant

The command prints the rule before writing it, validates the file with
`visudo -c`, and limits the rule to one binary and user. While the rule is
installed, `connect` and `disconnect` re-execute themselves as root through
`sudo -n` instead of refusing to run — they check for the rule file first and
never elevate without it, so removing the file restores sudo-per-invocation. A
NOPASSWD rule remains persistent attack surface. Remove it with:

```sh
sudo rm /etc/sudoers.d/awsvpn
```

Install `awsvpn` in a root-owned location that your user cannot write before you
enable this option.

### A writable parent directory can race signature verification

`awsvpn` verifies `acvc-openvpn` immediately before execution and requires a
root-owned, non-writable binary. A group member could still replace that binary
between verification and execution if its parent directory is writable by the
group or other users. Keep the AWS VPN Client in its default root-owned
location.

### Network changes and unsupported DNS modes

`awsvpn` applies DNS to the primary network service that macOS selects when the
tunnel connects. If you switch from Wi-Fi to Ethernet during a session, internal
names can stop resolving until you reconnect. Disconnect still restores the
original DNS configuration.

Version 1 supports the dynamic `State:` resolver and IPv4 `dhcp-option DNS`.
It does not support manually configured `Setup:` resolvers, IPv6 `DNS6`, or
split DNS.

### OpenVPN's log redaction

`acvc-openvpn` writes its stdout directly to the connection log so logging
survives after `connect` returns. At the pinned `--verb 3`, it masks password
commands. Review that behaviour before raising the OpenVPN verbosity level.
