# `awsvpn` — CLI-first AWS Client VPN for macOS

> Status: ready to build. The core handshake has been proven end-to-end by a throwaway spike (see **Further Notes**); the risky unknowns are retired.

## Problem Statement

Connecting to an AWS Client VPN endpoint that uses SAML/SSO federated authentication today means installing the official **AWS VPN Client** and driving it through a macOS GUI app: open the app, pick a profile, click connect, wait for a browser tab, click through SSO, watch a menu-bar icon. This is slow for a human and effectively unusable for an automated agent or a shell script — there is no first-class command to say "connect me to the `dev` endpoint" and get a tunnel.

The obvious escape hatch — the handful of open-source AWS VPN CLI projects on the web — is exactly what a security-conscious user should *not* reach for. A VPN client runs as root, rewrites the routing table and DNS resolver (so a malicious one can silently intercept all traffic), and handles a bearer credential (the SAML assertion). Running a stranger's code with that much power is precisely the risk we want to avoid.

## Solution

A small, auditable, **CLI-first** wrapper — `awsvpn` — that a human or an agent can drive with one command (`awsvpn connect dev`) and that a security-conscious person can read end-to-end before trusting it with root.

The wrapper does **not** ship or patch its own VPN engine. It reuses the **AWS-signed `acvc-openvpn` binary** already installed with the official AWS VPN Client, verifies that binary's Apple code signature (pinned to AWS's team) before executing it, and drives it over OpenVPN's **management interface**. The **SAML assertion is captured in memory** on a one-shot localhost callback and handed to the tunnel over the management socket — it never touches disk or a process argument. The result is a background tunnel controlled by `connect` / `status` / `disconnect`, with the trust surface reduced to a tiny layer of first-party Go plus the Go standard library and a couple of vetted, vendored dependencies.

The project is open source, source-first (you are meant to build it yourself), and macOS-only.

## User Stories

1. As a developer, I want to connect to an AWS Client VPN **profile** by name from my terminal (`awsvpn connect dev`), so that I don't have to open a GUI app.
2. As a developer, I want `awsvpn connect` with no argument to let me pick a profile interactively, so that I don't have to remember exact names.
3. As a developer, I want the tool to **auto-discover the profiles I already configured** in the official AWS VPN Client, so that I don't re-enter endpoint details I already have.
4. As a developer, I want to **import a raw `.ovpn` file** (`awsvpn import ./client.ovpn`), so that I can use an endpoint I haven't added to the official app.
5. As a developer, I want `awsvpn list` to show my available profiles (name, endpoint, region), so that I know what I can connect to.
6. As a developer, I want `connect` to open my browser to the SSO page automatically, so that I can authenticate without copy-pasting a URL.
7. As a developer, I want a friendly "authentication received — you can close this tab" page after SSO, so that the browser step feels finished.
8. As a developer, I want `connect` to **return control to my shell once the tunnel is up**, so that I can keep working (or let a script continue) without a blocked terminal.
9. As an automation agent, I want a non-interactive, scriptable connect/disconnect lifecycle, so that I can bring the tunnel up, run tasks, and tear it down programmatically.
10. As a developer, I want `awsvpn status` to tell me whether a tunnel is up, which profile, the assigned IP, and how long it has been connected, so that I can confirm my state at a glance.
11. As a developer, I want `awsvpn disconnect` to cleanly tear down the tunnel, remove its routes, and restore my DNS, so that my machine returns to its prior state.
12. As a developer, I want internal hostnames to resolve while connected, so that the VPN is actually useful (not just a tunnel with broken DNS).
13. As a developer, I want my normal DNS restored the moment I disconnect, so that browsing isn't broken after I'm done.
14. As a developer, I want the tool to **restore my DNS even if the tunnel process dies unexpectedly**, so that a crash doesn't leave my resolver pointed at an unreachable server.
15. As a security-conscious user, I want the tool to **verify that `acvc-openvpn` is genuinely AWS-signed** (pinned team identifier) before running it as root, so that a swapped binary can't run as root under my name.
16. As a security-conscious user, I want the tool to refuse to run and tell me why if the signature check fails, so that I'm not silently exposed — with a documented override flag for the rare case AWS changes its signing identity.
17. As a security-conscious user, I want my **SAML assertion to never be written to disk or passed as a command-line argument**, so that the bearer credential can't be recovered from a file or the process table.
18. As a security-conscious user, I want the SAML callback listener to **bind only to loopback, accept exactly one response, and time out**, so that its exposure window is minimal.
19. As a security-conscious user, I want the tool to **refuse to start rather than proceed** if `:35001` is already taken (e.g. the official client is running), so that it never hands my credential to something else by accident.
20. As a security-conscious user, I want secrets (SAML assertion, management password) **redacted from all logs**, so that turning on verbose logging can't leak my credential.
21. As a security-conscious user, I want the tool to be small enough to read in one sitting and buildable from source, so that "trust" means "I read it," not "I hoped."
22. As a security-conscious user, I want a documented threat model — including the residual localhost-callback race that the official client shares — so that I understand exactly what I am and am not protected against.
23. As a developer, I want to run `awsvpn` with `sudo` per connection by default (no standing privilege), so that the tool holds no persistent root grant unless I ask for one.
24. As an automation agent, I want an explicit, opt-in `awsvpn install-privilege` command that installs a **narrowly scoped** passwordless-sudo rule (and prints exactly what it will write), so that I can run non-interactively without granting broad root.
25. As a developer, I want files the tool creates (state, logs) to be **owned by me, not root**, so that a `sudo` invocation doesn't litter root-owned files in my home directory.
26. As a developer, I want the browser and profile discovery to operate as *me* even when the tool runs under `sudo`, so that SSO lands in my logged-in browser and discovery reads my profiles, not root's.
27. As a developer, I want `awsvpn logs` (and `-f` to follow), so that I can see what the current connection is doing when something goes wrong.
28. As a developer, I want clear, actionable error messages when the AWS VPN Client isn't installed, a profile doesn't exist, or SSO times out, so that I can fix the problem myself.
29. As a developer, I want connecting to a profile while another tunnel is up to swap cleanly to the new one, so that I don't end up in an ambiguous half-connected state.
30. As a developer, I want `awsvpn version` to report the tool version, so that I can file useful bug reports.
31. As an open-source user, I want to install via `go install` or a Homebrew formula that **builds from source**, so that I never have to run someone else's prebuilt binary as root.
32. As an open-source contributor, I want the dependency tree vendored and pinned with vulnerability scanning in CI, so that the supply chain is auditable and doesn't drift.
33. As a developer, I want the tool to reconnect-or-fail clearly when the SAML session expires (rather than hang), so that I know I need to re-authenticate.
34. As a developer, I want a stale/half-dead previous connection to be cleaned up automatically on the next `connect`, so that a prior crash doesn't block me.

## Implementation Decisions

### Foundation
- **Reuse, don't rebuild, the VPN engine.** The privileged tunnelling is done by the AWS-signed `acvc-openvpn` binary bundled with the official AWS VPN Client (OpenVPN 2.6.12). We do not ship or patch our own OpenVPN. This makes the AWS app a hard prerequisite — acceptable, since the target user already has it installed; their pain is the GUI, not the install.
- **Platform: macOS only.** No Linux/Windows and no cross-platform abstraction layer.
- **Language & dependencies: Go**, standard library first, with a small set of vetted third-party libraries where they clearly help (`cobra` for the command surface; optional `fzf` **shell-out** — only if present — for interactive selection, degrading to a numbered prompt). All dependencies are **pinned and vendored**; CI runs `govulncheck` and Dependabot.

### Trust & privilege model
- **Signature verification before every privileged exec.** Before executing `acvc-openvpn`, verify its Apple code signature *and* pin AWS's team identifier. Hard-fail (refuse to run) on mismatch, with an `--allow-unverified-binary` escape hatch for the rare AWS-identity-change case. The proven check is a single `codesign` invocation combining integrity + team pin.
- **Fully-privileged wrapper.** The wrapper runs as root (`sudo awsvpn …`). This is a deliberate simplicity-for-security trade the owner accepts: the threat being defended against is *running third-party VPN code as root*, which building a tiny, self-authored, auditable layer retires. Default is sudo-per-invocation (no standing privilege); `install-privilege` optionally writes a **narrowly scoped** `sudoers.d` NOPASSWD rule (for the tool only), after printing the exact rule and requiring confirmation.
- **De-escalate for user-context actions.** Because the process runs as root, opening the browser and discovering profiles must be performed as the invoking user (`$SUDO_USER`), and any state/log files the tool creates are `chown`ed back to that user. The tool must resolve the real user's home, not root's.

### Modules
- **Connection reducer (the core, and the primary test seam).** The entire connect lifecycle is modelled as a **pure state machine**: `step(state, event) -> (state, []effect)`. This isolates all credential- and handshake-bearing logic from I/O so it is deterministic and transcript-testable. Shape (derived from the spike, trimmed to the decision):

  ```
  events:   MgmtLine(">…")   // one line from the openvpn management channel
            SAMLCaptured(raw) // assertion received on the callback
            Timeout
  effects:  SendMgmt(cmd)     // e.g. "hold release", username/password
            OpenBrowser(url)
            ApplyDNS(ips)
            Connected(info) | Failed(reason)
  ```

- **Management client (impure runtime).** Owns the connection to `acvc-openvpn`'s management interface and pumps lines into the reducer / commands out of it. Transport is a **unix-domain socket** in a root-owned state dir with `--management-client-user` restriction (no open TCP port); the spike proved loopback-TCP-plus-password-file as a working fallback.
- **Callback server.** One-shot HTTP listener bound to `127.0.0.1:35001`. **Binds before the browser is opened; if the port is unavailable, the connect aborts loudly.** Extracts the `SAMLResponse` form field, keeps it in memory only, serves the existing `web/callback_success.html` / `web/callback_error.html` pages, then stops listening. Enforces a hard timeout.
- **Profile discovery (pure).** Reads the official client's `ConnectionProfiles` JSON and `OpenVpnConfigs/` **read-only** (never mutated) and merges in profiles the user has `import`ed into our own state directory. Yields `[]Profile{name, ovpnPath, endpointId, region}`.
- **Push-reply parser (pure).** Parses the OpenVPN `PUSH_REPLY` control message into resolved settings: DNS servers, routes, and tunnel mode (split vs. full). Observed reality: endpoints may push split-tunnel routes and a single internal DNS server, and `acvc-openvpn` applies routes itself but does **not** touch the macOS resolver.
- **DNS manager (impure, root).** Applies the pushed DNS server(s) to the macOS resolver via `scutil` and reverts on disconnect. **v1 sets the pushed DNS as the primary resolver while connected** (matching official-client behaviour) rather than doing split-DNS. Includes a **crash-safety revert**: on the next run, restore any DNS state a previous, dead connection left behind. Routing itself is left to `acvc-openvpn`.
- **Daemon supervisor.** `connect` starts `acvc-openvpn` and the wrapper's own supervision, returns once the tunnel reaches `CONNECTED`, and records PID/socket/state so `status` and `disconnect` can control it out-of-band. Stale state from a dead prior connection is detected and cleaned on the next `connect`.
- **System port.** A thin interface over all impure side effects (signature-verify + exec `acvc-openvpn`, socket I/O, browser open, `scutil`, daemonize). Kept deliberately small so the reducer and parsers stay pure.
- **CLI.** `list`, `connect [profile]`, `disconnect`, `status`, `import <file.ovpn>`, `logs [-f]`, `version`, `install-privilege`. **Single active connection** in v1 (connecting swaps the active tunnel).

### Proven handshake contract (encodes the reducer's expected behaviour)
- First auth attempt sends username `N/A`, password `ACS::35001` (declares the callback port to the endpoint).
- The endpoint replies with a **CRV1 challenge** delivered as a management line of the form
  `>PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:<state>:<b64user>:<samlURL>']`.
  Parse `<state>` and `<samlURL>` from it.
- The engine then does a soft restart (`SIGUSR1[auth-failure]`) and **re-enters hold on every restart** — so the reducer must **release the hold on every `>HOLD:` notification**, not once.
- After re-connect, respond to the next `>PASSWORD:Need 'Auth'` with username `N/A`, password `CRV1::<state>::<url-encoded-SAMLResponse>`. The assertion is ~10 KB and transits the management socket intact.
- `>STATE:…,CONNECTED,…` is success; teardown is `signal SIGTERM`.

### Logging & secrets
- Hard **redaction**: the SAML assertion and the management password never appear in logs, even at high verbosity. Redacted forms show length only.

### Distribution
- **Source-first**: primary install is `go install` and a Homebrew tap whose formula **compiles from source**. License **MIT**. Signed/notarized release binaries are a later convenience, not the front door. CI publishes checksums + build provenance (SLSA) and runs `govulncheck`.

## Testing Decisions

- **What a good test is here:** it asserts *external behaviour* through a seam, not internal structure. For this project that means driving the connection reducer with a sequence of events and asserting the sequence of emitted effects and the terminal state — never reaching into private fields or mocking internal calls.
- **Primary tested module — the connection reducer.** Fed scripted event sequences and asserted against emitted effects. **Fixture #1 is the real management transcript captured by the spike** (challenge line, hold-release-on-restart, the redacted 10 KB `password`, `CONNECTED`). Additional fixtures cover: hard `AUTH_FAILED` (non-CRV1) → `Failed`; SSO timeout → `Timeout` → `Failed`; SAML arriving before vs. after the second `>PASSWORD:Need` (the ordering the spike exposed).
- **Pure parsers tested directly** (no seam, no fixtures beyond captured strings): profile discovery against a fixture profile directory; push-reply parsing against the real split-tunnel `PUSH_REPLY` string; CRV1 challenge parsing against the real challenge line (including the slash-bearing `state` id).
- **The impure shell (System port) is not unit-tested.** It is validated end-to-end via `/verify` against a live endpoint (root + real SSO), because signature-verify/exec, `scutil`, browser open, and socket I/O cannot be meaningfully exercised without them. The spike is the standing proof that this boundary works.
- **Prior art:** none in-repo (greenfield). The reducer/effect pattern is chosen precisely so the risky logic is testable without the untestable parts.

## Out of Scope

- Linux and Windows support.
- Full-tunnel-aware **split-DNS** (resolving only VPN domains via the pushed resolver). v1 sets the pushed DNS as primary while connected.
- **Multiple simultaneous tunnels.** v1 supports a single active connection.
- Automatic re-authentication when the SAML session expires (v1 reports the disconnect; the user reconnects).
- Shipping or patching our own OpenVPN build (the "cut the cord from the AWS app" endgame is explicitly a later milestone, not v1).
- A persistent privileged helper / `SMAppService` daemon and signed/notarized prebuilt binaries as the primary install path.
- Any GUI, menu-bar item, or TUI beyond a simple selection prompt.

## Further Notes

- **The design was validated by a throwaway spike** (a single-file Go program driving `acvc-openvpn` over the management interface against a real `dev` endpoint). It reached `CONNECTED` via the full SAML→CRV1 flow, confirming: the management interface is present and drives the handshake in a single process; a ~10 KB SAML assertion transits the socket without truncation (the exact limitation that forces the OpenVPN patch, sidestepped here by using AWS's own patched binary); the endpoint's server certificate verifies to Amazon's CA and matches the config's `verify-x509-name`; `acvc-openvpn` applies routes but not macOS DNS; and clean teardown via `SIGTERM` leaves no residue. The spike's driver is ~90% of the real management client and should seed that module rather than be discarded.
- **Residual risk to document in the README threat model:** a hostile *local* process that binds `:35001` before us could receive the user's SAML assertion. This is inherent to AWS's fixed loopback callback and is shared by the official client; our bind-before-browser-or-abort guard ensures *we* never proceed into a hand-off we didn't initiate, but it cannot stop an attacker who wins the port race.
- **AWS team identifier** to pin for the signature check and **the fixed callback port** `35001` are the two external constants the tool depends on; both are documented so a future AWS change is a one-line update, not a mystery failure.
