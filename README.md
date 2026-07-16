# awsvpn — CLI-first AWS Client VPN for macOS

Connect to a SAML/SSO AWS Client VPN endpoint from your terminal:

```sh
sudo awsvpn connect dev
```

No GUI app, no menu-bar icon, no clicking through a browser tab you launched by
hand. One command brings up the tunnel and returns control to your shell (or your
script, or your agent); `status` and `disconnect` control it out of band.

`awsvpn` is deliberately small and **source-first**: you are meant to build it
yourself and read it before trusting it with root.

---

## Why this exists (the trust story)

A VPN client is close to the worst thing to run untrusted. It runs **as root**,
it **rewrites your routing table and DNS** (so a malicious one can silently
intercept all your traffic), and it **handles a bearer credential** (the SAML
assertion — whoever holds it can authenticate as you until it expires). The
open-source AWS VPN CLIs on the web ask you to run exactly that much power on
trust.

`awsvpn` narrows what you have to trust:

- **It does not ship or patch its own VPN engine.** The privileged tunnelling is
  done by the **AWS-signed `acvc-openvpn`** binary already installed with the
  official AWS VPN Client (OpenVPN 2.6.12). Before executing it as root, `awsvpn`
  **verifies its Apple code signature and pins AWS's team identifier**
  (`94KV3E626L`). A swapped binary can't run as root under your name.
- **The SAML assertion never touches disk or a process argument.** It is captured
  in memory on a one-shot loopback callback and handed to the tunnel over the
  OpenVPN **management socket**, then dropped. (Both reference projects write it
  to `saml-response.txt`; we don't.)
- **The code is small and stdlib-first.** The only third-party dependencies are
  `cobra` (command surface) and its two small transitive deps — all **vendored**
  in-repo, so `go build` is hermetic and the whole tree is right there to read.
- **No standing privilege by default.** You run `sudo awsvpn …` per connection.
  There is an explicit, opt-in `install-privilege` command for non-interactive
  use that installs a *narrowly-scoped* passwordless-sudo rule — and prints
  exactly what it will write first.

The threat this defends against is *running third-party VPN code as root*.
Authoring a tiny layer you can read end-to-end retires that threat.

## How it works

```
        you ──sudo──▶ awsvpn (root)
                        │
      verify signature  │  ── codesign --verify --strict -R=<team-pinned> acvc-openvpn
                        ▼
        spawn ────▶ acvc-openvpn  ──management unix socket──▶  awsvpn drives the
        (detached, its own tun)                                SAML→CRV1 handshake
                        │
   ┌────────────────────┴─────────────────────────────────────────────┐
   │  1. first auth:  user "N/A", pass "ACS::35001"  (declares callback)│
   │  2. endpoint returns a CRV1 challenge carrying the SAML URL        │
   │  3. open the URL in *your* browser; capture the assertion on       │
   │     127.0.0.1:35001 (in memory, one-shot, times out)              │
   │  4. answer with  "CRV1::<state>::<url-encoded-assertion>"          │
   │  5. CONNECTED → apply pushed DNS via scutil, record run state      │
   └───────────────────────────────────────────────────────────────────┘
```

The credential- and handshake-bearing logic is a **pure state machine**
(`internal/reducer`) with no I/O, driven by the real management transcript in
tests. Everything impure — signature verify, socket I/O, browser, `scutil`,
daemonize — lives behind a thin system port.

## Requirements

- **macOS** (only). No Linux/Windows.
- The **official AWS VPN Client** installed (for the signed `acvc-openvpn`
  binary): <https://aws.amazon.com/vpn/client-vpn-download/>. Its GUI is the pain
  you're escaping; the install is a one-time prerequisite.
- **Go 1.24+** to build from source.

## Install

Source-first — you build it, so you never run someone else's prebuilt binary as
root:

```sh
go install github.com/larcanjo/awsvpn@latest
```

or from a clone:

```sh
git clone https://github.com/larcanjo/awsvpn && cd awsvpn
make install          # builds with version metadata, installs to $GOBIN
```

A Homebrew tap that **compiles from source** is provided in `Formula/awsvpn.rb`.

## Usage

```sh
awsvpn list                     # profiles (auto-discovered + imported)
sudo awsvpn connect dev         # connect by name
sudo awsvpn connect             # pick interactively (fzf if present, else a prompt)
awsvpn status                   # profile, assigned IP, uptime
sudo awsvpn disconnect          # tear down, remove routes, restore DNS
awsvpn logs -f                  # follow the current connection's log
awsvpn import ./client.ovpn     # register a raw config you haven't added to the app
awsvpn version
sudo awsvpn install-privilege   # opt-in: narrow NOPASSWD rule for non-interactive use
```

Profiles are auto-discovered from the AWS VPN Client's store (read strictly
**read-only** — we never write into it) and merged with anything you `import`.
There is a **single active connection**; connecting while a tunnel is up swaps to
the new one.

## Threat model

What `awsvpn` protects you from, and — honestly — what it doesn't.

**Mitigated**

- *Running untrusted VPN code as root.* The privileged crypto is AWS's own signed
  binary; our code is a small, vendored, readable layer.
- *A swapped/tampered `acvc-openvpn`.* Verified against a pinned Apple team id
  right before exec; hard-fail with an `--allow-unverified-binary` escape hatch
  for a legitimate AWS identity change.
- *The assertion recovered from disk or the process table.* It is kept in memory
  and passed over the management socket — never a file, never argv.
- *Secrets leaking into logs.* The SAML assertion and management password are
  **hard-redacted** everywhere, even at `--verbose`; redacted forms show length
  only.
- *Handing the credential to the wrong listener.* The callback binds
  `127.0.0.1:35001` **before** the browser opens and **aborts** if the port is
  already taken (e.g. the official client is running), so we never proceed into a
  hand-off we didn't initiate. It is loopback-only, one-shot, and times out.
- *A crash leaving your resolver broken.* DNS revert state is persisted the moment
  DNS is applied; the next `awsvpn` run restores your DNS if a prior connection
  died.

**Residual — documented, not solved**

- **The localhost-callback race.** AWS fixes the SAML consumer at
  `http://127.0.0.1:35001`. A hostile *local* process that binds that port
  *before* us could receive your assertion. This is inherent to the fixed
  loopback callback and is **shared by the official AWS client**. Our
  bind-before-browser-or-abort guard ensures *we* never silently hand off, but it
  cannot stop an attacker who wins the port race. On a single-user machine this is
  low risk (such a process could already do worse).
- **`awsvpn` runs fully as root.** This is a deliberate simplicity trade: the
  whole wrapper is small enough to audit. It de-escalates to your user for
  browser-open and profile discovery, and chowns any files it creates back to
  you, but the process itself holds root while connecting.
- **`install-privilege` is a standing grant.** It's opt-in, prints the exact rule,
  validates with `visudo -c`, and is scoped to this one binary for one user — but
  a NOPASSWD rule is still persistent attack surface. Remove it with
  `sudo rm /etc/sudoers.d/awsvpn`. Prefer installing `awsvpn` to a root-owned,
  non-user-writable location before using it.

## The two AWS-owned constants

Both live in `internal/config` so a future AWS change is a one-line update:

- **Team identifier** pinned for the signature check: `94KV3E626L`
- **Callback port** the endpoint expects: `35001`

## Development

```sh
make test        # go test ./... (reducer transcript fixtures, parsers, callback, signature)
make vet
make vuln        # govulncheck (requires: go install golang.org/x/vuln/cmd/govulncheck@latest)
make build
```

The primary tested module is the connection reducer, fed scripted event sequences
(including the real management transcript captured against a live endpoint) and
asserted against emitted effects. The impure system port is validated end-to-end
against a real endpoint, not unit-tested.

## License

MIT — see [LICENSE](LICENSE).
