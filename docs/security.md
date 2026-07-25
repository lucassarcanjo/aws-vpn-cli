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
5. After OpenVPN connects, `awsvpn` applies pushed DNS through `scutil` — to the
   primary service's `State:` and `Setup:` resolver keys — and records the prior
   state so it can restore DNS after a disconnect or crash.
6. `awsvpn` registers the connection supervisor as a root LaunchDaemon, then
   returns your shell. `disconnect` removes it.

The connection reducer in `internal/reducer` is a pure state machine. Tests
drive it with captured management transcripts. Signature verification, socket I/O,
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

When `awsvpn` applies DNS, it records the current resolver state — both the
`State:` and `Setup:` dictionaries, in full. On the next run it restores DNS if
a previous connection did not clean up. It preserves each key's servers, search
domains, and domain name, and rolls back a half-applied override. Both writes go
to the dynamic store, so a reboot clears them regardless.

`awsvpn` writes the override to `Setup:` as well as `State:` because `State:`
alone is owned by configd, which rewrites it from DHCP and IPv6-RA data on any
network event. On a network whose router advertises RDNSS, a `State:`-only
override was reverted within minutes and queries silently went back to the LAN
resolver mid-session — split-horizon names then resolved to public addresses.

### A dead tunnel left in place

If the tunnel drops, its routes and DNS override outlive it, and traffic for
internal names goes nowhere. The connection supervisor watches the management
channel for the rest of the session and tears the tunnel down cleanly — routes,
DNS, state — when it drops and does not recover within a 60-second grace window.
It gives up immediately on anything that would need re-authentication: with AWS
SAML, recovery means a fresh browser sign-in, which a root background daemon
must never attempt on your behalf. It never releases OpenVPN's management hold
and never handles a credential itself.

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
NOPASSWD rule remains persistent attack surface. Revoke it with:

```sh
awsvpn uninstall-privilege   # or: sudo rm /etc/sudoers.d/awsvpn
```

`uninstall-privilege` elevates through the grant it is deleting, so it needs no
`sudo` prefix while the rule is in place; it only removes the file, and leaves an
active tunnel alone.

Install `awsvpn` in a root-owned location that your user cannot write before you
enable this option.

### The supervisor is a root LaunchDaemon

While a tunnel is up, `awsvpn` runs a second copy of itself as root under
launchd: `awsvpn supervise`, defined by a plist at
`/Library/LaunchDaemons/com.github.lucassarcanjo.awsvpn.supervisor.plist`. That
directory is root-owned, so a non-root user cannot plant or edit the definition
launchd will run as root. The job is registered by `connect` and booted out by
`disconnect` and by the next `connect`, so no `awsvpn` process holds root
between connections. It watches one socket and takes one action — teardown — and
it neither reads nor requests a credential.

To notify you, the supervisor reaches your GUI session through
`launchctl asuser <uid> osascript`, because a sessionless root daemon cannot
post a banner itself. The profile name reaches AppleScript as a quoted string
literal with backslashes, quotes, and control characters escaped, so a profile
name from the AWS store cannot break out and inject script. Notification is
best-effort: with no logged-in session there is nothing to reach, and the
teardown happens either way. You can review the plist while connected, and audit
the job's activity in `awsvpn logs` — the supervisor writes there.

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

Version 1 handles IPv4 `dhcp-option DNS` and overrides the primary service's
`State:` and `Setup:` resolvers for the duration of the tunnel. A resolver you
configured by hand in System Settings is captured and restored on disconnect,
but it is overridden while connected. IPv6 `DNS6` and split DNS are not
supported.

### OpenVPN's log redaction

`acvc-openvpn` writes its stdout directly to the connection log so logging
survives after `connect` returns. At the pinned `--verb 3`, it masks password
commands. Review that behaviour before raising the OpenVPN verbosity level.
