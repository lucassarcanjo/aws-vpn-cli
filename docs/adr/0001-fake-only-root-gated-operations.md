# ADR-0001 — Fake only root-gated operations; use the real resource for everything else

- **Status:** accepted
- **Date:** 2026-07-24
- **Supersedes:** the "the impure shell is not unit-tested" bullet in `SPEC.md`, which is narrowed rather than dropped.

## Context

`internal/system` defined a `Port` interface over the privileged side effects, and
its doc comment promised that "tests can substitute a fake to exercise the driver
without root". No fake was ever written. One adapter means a hypothetical seam:
the interface was paid for and earning nothing.

Meanwhile `internal/daemon` took a `system.Port` but reached *past* it for three
of the things `SPEC.md` claimed the port covered — socket I/O (`mgmt.Dial`),
persisted state (package-level `state.Load`/`Save` over hard-wired paths), and
daemonizing (`launchd`, called from `internal/cli`). The result was that
`daemon/connect.go` — 286 lines carrying every ordering guarantee the threat
model rests on — had no test surface at all, while the pure reducer beneath it
was richly transcript-tested.

The obvious fix was to add ports for the remaining dependencies: a line-channel
interface for `mgmt`, a `Store` interface for `state`, a supervisor slot for
`launchd`. That was rejected. This is a security tool whose stated value is being
"small enough to read in one sitting", and every interface added is code an
auditor must read. Three new interfaces to make one package testable is a poor
trade against that value.

Looking at what the repo already did settled it. `callback.Listen(addr)` takes its
address as a parameter and `callback_test.go` binds a real TCP listener on
`127.0.0.1:0`. `signature_test.go` shells out to the real `codesign`.
`profile_test.go` reads a real `t.TempDir()`. Nothing in this repository mocks
anything. The idiom was already *parameterize the resource, use the real one* —
it just had not been applied to `state` or `daemon`.

## Decision

**Fake only the operations that genuinely require root or a live endpoint. Use
the real resource for everything else.**

Behind `system.Port`, faked in tests:

| Operation | Why it cannot be real in a test |
| --- | --- |
| `VerifySignature` | needs the AWS-signed binary present |
| `SpawnOpenVPN` | executes a root-only binary |
| `ApplyDNS` / `RevertDNS` | `scutil` rewrites the machine's resolver |
| `Kill` / `IsOpenVPN` | signals real processes |
| `OpenBrowser` | opens a GUI in the user's session |
| `CopyToClipboard` | writes the logged-in user's pasteboard |

Not faked — tests use the real thing:

| Resource | How |
| --- | --- |
| management channel | a real unix socket in a temp dir, replaying the captured transcript |
| connection state | a real directory via `t.TempDir()` |
| SAML callback | a real loopback bind on an ephemeral port, driven with a real HTTP POST |

Supporting changes:

- `internal/state` exposes a `Store` rooted at a directory (`state.At(dir)`,
  `state.Default()`), replacing package-level functions over hard-wired paths.
  Its two records share one read/write pair, so their atomicity and their
  "absent is not an error" handling cannot drift apart.
- `daemon.Options` gains `StateRoot`, `MgmtSocketPath` and `CallbackAddr`, each
  empty in production and each documented with the invariant it carries. The
  field is `MgmtSocketPath`, not `MgmtSocket`, so that it does not collide with
  `state.Run.MgmtSocket` and the audit grep below stays precise — a grep-enforced
  invariant is worth only as much as the grep.

### Assertion style

The fake records **whether** an operation happened, never the **order**.
Ordering guarantees are asserted as observable outcomes:

- callback port already bound → `Connect` errors **and nothing was spawned**
- signature verification fails → `Connect` errors **and nothing was spawned**

Each of those also catches the corresponding reorder, because a spawn that
happened before its guard shows up as a spawn that should not have occurred.
Both were confirmed by making the reordering and watching the test go red. A
full call-sequence assertion was rejected: it goes red on harmless restructuring,
which is the change-detector shape `SPEC.md` warns against.

## Consequences

**Good.** `daemon.Connect` is transcript-tested end to end — the happy path, both
prompt-ordering variants, and every failure-cleanup path. The tested code is the
real `internal/mgmt`, `internal/state` and `internal/callback`, not a stand-in.

The audit surface barely moved, which was the point. **Zero new interfaces.**
Non-comment lines in the code that actually links into the binary went from 785
to 798 — **+13** — as `internal/state` gave back 10 and `internal/config` 2,
against 22 added to `internal/daemon` for the three Options fields and their
defaulting. `internal/fixture` adds 28 more, but only `_test.go` files import it,
so nothing reachable from main pulls it in. Every fake, replayer and fixture
lives in `_test.go` files.

**Costs.** Two invariants moved from compiler-enforced to grep-enforced:

```sh
# The test-only Options fields. Every hit must be in a _test.go file.
grep -rn --include='*.go' -e 'StateRoot:' -e 'MgmtSocketPath:' \
    -e 'CallbackAddr:' . | grep -v _test.go | grep -vE ':[[:space:]]*//'

# Building a Store at a non-default root. Outside tests there must be exactly
# ONE hit: daemon.Options.store(), which reads the production-empty StateRoot.
grep -rn 'state\.At(' --include='*.go' . | grep -v _test.go | grep -vE ':[[:space:]]*//'
```

This is weaker than making the fields unexported and reachable only through an
`export_test.go` constructor, which the compiler would enforce. It was chosen
anyway: this codebase carries its invariants in prose comments next to the code
(see `internal/config`), and a reader who already has to trust what they read is
better served by a plain field with the reason beside it than by machinery.

Tests now touch the filesystem and bind loopback ports, so they are slower and
need a working temp dir. On macOS the ~104-byte `sun_path` limit means socket
paths cannot use `t.TempDir()` (it embeds the test name); the suites use a short
`os.MkdirTemp` instead.

**Still uncovered.** `system.Real` remains `/verify`-only. That the signature
check sits *immediately* before the exec is a reading-level guarantee — the width
of the TOCTOU window is not observable. The press-Enter-to-reopen path reads
`os.Stdin` directly and is inert under `go test`; widening `Options` for it was
judged not worth the audit surface.

## Alternatives considered

**Ports and adapters throughout** — a line-channel port for `mgmt`, a `Store`
interface for `state`, a `Supervisor` port for `launchd`. Rejected: three new
interfaces on the audit surface of a tool whose selling point is readability,
to gain fakeability the real resources already provide for free.

**Harvest only; leave `daemon` uncovered** — write the tests that need no
production change and stop. Rejected once it was clear the residue included every
failure-cleanup path and both spawn guards, which are the parts of the codebase
where a regression is silent and dangerous. Worth noting the harvest was real and
was taken: the redaction property is now tested by composing `reducer` and
`logging` with no seam at all, and it found a genuine gap — `drive` registers the
*raw* assertion with the redactor, but the wire form is `url.QueryEscape`d, so the
literal-secret path never matches it and the structural password-command regex is
the only thing scrubbing the credential.
