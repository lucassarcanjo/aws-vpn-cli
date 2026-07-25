# Reporting a vulnerability

Report privately through GitHub: **Security → Advisories → Report a vulnerability**
on this repository. That opens a draft advisory only you and the maintainers can
read. Do not open a public issue for a vulnerability.

Expect an acknowledgement within a week. This is a personal project with no paid
support and no bug bounty; fixes land on a best-effort basis, and the advisory is
published once a fix is released.

## What is in scope

`awsvpn` runs as root, starts a VPN engine, rewrites your routes and DNS, and
handles a SAML assertion. Findings that matter most:

- A path to root through `awsvpn` that its trust boundary is supposed to close —
  a bypass of the `acvc-openvpn` signature and team-identifier check, a way to
  widen the `install-privilege` sudoers rule, or a write into the root-owned
  state directory.
- A leak of the SAML assertion or the management password — to disk, to `argv`,
  to a log, or to another local process.
- Routes or a DNS override that outlive the tunnel and send traffic somewhere
  unintended, including after a crash.
- Command or script injection through a profile name, a `.ovpn` file, or a
  management line.

[`docs/security.md`](docs/security.md) states the trust boundary, the mitigated
risks, and the residual risks. A report that matches something already listed
under **Residual risks** is a known limitation rather than a new finding, though
a concrete escalation of one is worth reporting.

## What is out of scope

- Vulnerabilities in AWS's `acvc-openvpn` binary or the AWS VPN Client. Report
  those to AWS.
- Anything that assumes an attacker who is already root, or who can write to the
  installed `awsvpn` binary or its parent directory.
- The fixed `127.0.0.1:35001` callback port. AWS pins it; `awsvpn` binds it
  before opening your browser and refuses to continue if it is taken.

## Supported versions

Fixes go to the latest release. There are no maintained release branches.
