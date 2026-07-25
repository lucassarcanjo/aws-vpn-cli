package daemon_test

import (
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/daemon"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/dns"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/fixture"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/profile"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/state"
)

var fx = fixture.Handshake()

type result struct {
	run state.Run
	err error
}

// harness wires one Connect against a real unix socket, a real state directory
// and a real loopback callback, with only the root-gated operations faked.
type harness struct {
	t       *testing.T
	sys     *fakeSys
	root    string
	sock    string
	addr    string
	log     *logBuf
	verbose bool
	timeout time.Duration
	engines chan *engine
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:       t,
		sys:     newFakeSys(),
		root:    t.TempDir(),
		sock:    socketPath(t),
		addr:    freeAddr(t),
		log:     &logBuf{},
		timeout: 20 * time.Second,
		engines: make(chan *engine, 1),
	}
	// The engine's socket appears only once Connect "launches" it, exactly as
	// acvc-openvpn's does — so mgmt.Dial's retry loop is exercised for real.
	h.sys.onSpawn = func(sock string) {
		if e := newEngine(t, sock); e != nil {
			h.engines <- e
		}
	}
	return h
}

func (h *harness) options() daemon.Options {
	return daemon.Options{
		Profile:        profile.Profile{Name: "dev", OvpnPath: "/tmp/dev.ovpn", Region: "us-east-2"},
		Sys:            h.sys,
		Logger:         logging.New(h.log, logging.NewRedactor(), h.verbose),
		StateRoot:      h.root,
		MgmtSocketPath: h.sock,
		CallbackAddr:   h.addr,
		SSOTimeout:     h.timeout,
		ConnectTimeout: h.timeout,
	}
}

// start runs Connect on its own goroutine so the test can drive the engine.
func (h *harness) start() <-chan result {
	ch := make(chan result, 1)
	o := h.options()
	go func() {
		r, err := daemon.Connect(o)
		ch <- result{r, err}
	}()
	return ch
}

// engine waits for Connect to spawn, and returns the management socket it bound.
func (h *harness) engine() *engine {
	h.t.Helper()
	select {
	case e := <-h.engines:
		return e
	case <-time.After(10 * time.Second):
		h.t.Fatal("Connect never spawned acvc-openvpn")
		return nil
	}
}

func (h *harness) store() *state.Store { return state.At(h.root) }

func (h *harness) await(ch <-chan result) result {
	h.t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(30 * time.Second):
		h.t.Fatalf("Connect never returned; log:\n%s", h.log.String())
		return result{}
	}
}

// handshake drives the captured transcript through to CONNECTED. samlFirst
// selects the ordering variant: whether the assertion lands before or after the
// engine's second credential prompt.
func (h *harness) handshake(e *engine, assertion string, samlFirst bool) {
	h.t.Helper()

	e.Emit(fx.Line("hold0"))
	e.WaitFor(`^hold release$`)

	e.Emit(fx.Line("need"))
	e.WaitFor(`password .*ACS::35001`)

	e.Emit(fx.Line("challenge"))
	h.sys.waitBrowsed(h.t) // the callback is bound and about to serve

	e.Emit(fx.Line("reconn"))
	e.Emit(fx.Line("hold1"))

	if samlFirst {
		postSAML(h.t, h.addr, assertion) // returns once the callback has it
		e.Emit(fx.Line("need"))
	} else {
		e.Emit(fx.Line("need"))
		postSAML(h.t, h.addr, assertion)
	}

	e.WaitFor(`password .*CRV1::`)
	e.Emit(fx.Line("pushReply"))
	e.Emit(fx.Line("connect"))
}

// -------------------------------------------------------------- happy path

func TestConnectReachesConnectedAndRecordsTheRun(t *testing.T) {
	h := newHarness(t)
	done := h.start()
	e := h.engine()
	assertion := inflate(fx.Line("rawSAML"), 10_000)

	h.handshake(e, assertion, false)
	res := h.await(done)

	if res.err != nil {
		t.Fatalf("Connect failed: %v\nlog:\n%s", res.err, h.log.String())
	}

	// The returned run is what `status` will show (SPEC.md story 10).
	if res.run.Profile != "dev" {
		t.Errorf("profile = %q, want dev", res.run.Profile)
	}
	if res.run.AssignedIP != "10.8.0.133" {
		t.Errorf("assigned IP = %q, want 10.8.0.133", res.run.AssignedIP)
	}
	if res.run.RemoteIP != "203.0.113.10" || res.run.Port != "443" {
		t.Errorf("endpoint = %s:%s, want 203.0.113.10:443", res.run.RemoteIP, res.run.Port)
	}
	if len(res.run.Routes) != 2 {
		t.Errorf("routes = %d, want the 2 pushed routes", len(res.run.Routes))
	}
	if res.run.ConnectedAt.IsZero() {
		t.Error("ConnectedAt not stamped; status would report this as still connecting")
	}

	// And it is on disk, so `status` and `disconnect` can find the tunnel
	// out-of-band after this process exits.
	got, ok, err := h.store().Run()
	if err != nil || !ok {
		t.Fatalf("no run record persisted: ok=%v err=%v", ok, err)
	}
	if got.OvpnPID != h.sys.pid || got.MgmtSocket != h.sock {
		t.Errorf("persisted record cannot control the tunnel: %+v", got)
	}

	// The pushed resolver was applied, and its revert record persisted so a
	// crash from here on is still recoverable (SPEC.md story 14).
	applied := h.sys.appliedDNS()
	if len(applied) != 1 || len(applied[0]) != 1 || applied[0][0] != "10.0.0.2" {
		t.Errorf("ApplyDNS called with %v, want [[10.0.0.2]]", applied)
	}
	if _, ok, _ := h.store().DNS(); !ok {
		t.Error("no DNS revert record persisted")
	}
}

func TestConnectSpawnsTheEngineWithTheExpectedSpec(t *testing.T) {
	h := newHarness(t)
	done := h.start()
	e := h.engine()
	h.handshake(e, fx.Line("rawSAML"), false)
	if res := h.await(done); res.err != nil {
		t.Fatalf("Connect failed: %v", res.err)
	}

	spec := h.sys.spawnedSpec()
	if spec.ConfigPath != "/tmp/dev.ovpn" {
		t.Errorf("config path = %q, want the profile's ovpn file", spec.ConfigPath)
	}
	if spec.SocketPath != h.sock {
		t.Errorf("socket path = %q, want %q", spec.SocketPath, h.sock)
	}
	// The management channel controls a root process; restricting it to root is
	// what stops a non-root user driving the tunnel.
	if spec.RestrictUser != "root" {
		t.Errorf("management-client-user = %q, want root", spec.RestrictUser)
	}
}

// ---------------------------------------------------- refusing to spawn

// TestCallbackPortTakenNeverSpawns is SPEC.md story 19 as an outcome. If :35001
// is already held — the official client is running, or something hostile is
// squatting — we must abort rather than proceed into a hand-off we did not
// initiate. Asserting "nothing was spawned" also catches the callback bind being
// moved AFTER the spawn, which would leave an orphaned root process behind.
func TestCallbackPortTakenNeverSpawns(t *testing.T) {
	h := newHarness(t)

	squatter, err := net.Listen("tcp", h.addr)
	if err != nil {
		t.Fatalf("could not occupy %s: %v", h.addr, err)
	}
	defer squatter.Close()

	res := h.await(h.start())
	if res.err == nil {
		t.Fatal("Connect proceeded even though the callback port was taken")
	}
	if h.sys.didSpawn() {
		t.Error("acvc-openvpn was spawned despite the callback port being unavailable")
	}
	if _, ok, _ := h.store().Run(); ok {
		t.Error("a run record was left behind by a connect that never started")
	}
}

// TestSignatureFailureNeverSpawns is SPEC.md story 15/16 as an outcome. A binary
// that does not verify against AWS's pinned team id must never be executed as
// root. Asserting "nothing was spawned" is also what catches the verify being
// reordered to AFTER the spawn — in which case openvpn would already be running
// as root by the time the check failed.
func TestSignatureFailureNeverSpawns(t *testing.T) {
	h := newHarness(t)
	h.sys.verifyErr = os.ErrPermission

	res := h.await(h.start())
	if res.err == nil {
		t.Fatal("Connect proceeded despite a failed signature check")
	}
	if h.sys.didSpawn() {
		t.Error("acvc-openvpn was executed as root despite failing signature verification")
	}
}

// TestAllowUnverifiedSkipsTheCheck covers the documented escape hatch for a
// legitimate AWS signing-identity change — and asserts it is genuinely a skip,
// not a check whose result is ignored.
func TestAllowUnverifiedSkipsTheCheck(t *testing.T) {
	h := newHarness(t)
	h.sys.verifyErr = os.ErrPermission // would abort, if it were consulted

	ch := make(chan result, 1)
	o := h.options()
	o.AllowUnverified = true
	go func() { r, err := daemon.Connect(o); ch <- result{r, err} }()

	e := h.engine()
	h.handshake(e, fx.Line("rawSAML"), false)
	if res := h.await(ch); res.err != nil {
		t.Fatalf("Connect failed with --allow-unverified-binary: %v", res.err)
	}
	if h.sys.didVerify() {
		t.Error("signature was still verified despite --allow-unverified-binary")
	}
	if !strings.Contains(h.log.String(), "WARNING") {
		t.Error("skipping verification was not warned about in the log")
	}
}

// ---------------------------------------------------------- failure cleanup

// TestDialFailureKillsTheOrphan: if the engine never opens its management socket
// it is running as root with nothing driving it. Connect must kill it and clear
// the record rather than leave an orphan behind.
func TestDialFailureKillsTheOrphan(t *testing.T) {
	h := newHarness(t)
	h.sys.onSpawn = nil // spawn "succeeds", but no socket ever appears
	h.timeout = 2 * time.Second

	res := h.await(h.start())
	if res.err == nil {
		t.Fatal("Connect succeeded without ever reaching the management socket")
	}
	if killed := h.sys.killedPids(); len(killed) == 0 || killed[0] != h.sys.pid {
		t.Errorf("killed = %v, want the orphaned pid %d", killed, h.sys.pid)
	}
	if _, ok, _ := h.store().Run(); ok {
		t.Error("run record survived a failed connect; status would report a phantom tunnel")
	}
}

// TestHandshakeFailureTearsDown: a hard AUTH_FAILED leaves a root process
// running with no tunnel. It must be killed and its record cleared.
func TestHandshakeFailureTearsDown(t *testing.T) {
	h := newHarness(t)
	done := h.start()
	e := h.engine()

	e.Emit(fx.Line("hold0"))
	e.WaitFor(`^hold release$`)
	e.Emit(fx.Line("need"))
	e.WaitFor(`password .*ACS::35001`)
	e.Emit(fx.Line("authFailed"))

	res := h.await(done)
	if res.err == nil {
		t.Fatal("Connect reported success after AUTH_FAILED")
	}
	if killed := h.sys.killedPids(); len(killed) == 0 {
		t.Error("the engine was left running after a failed handshake")
	}
	if _, ok, _ := h.store().Run(); ok {
		t.Error("run record survived a failed handshake")
	}
}

// TestDeadlineTearsDown: SPEC.md story 33 — an SSO that never completes must
// fail clearly rather than hang, and must not leave a root process behind.
func TestDeadlineTearsDown(t *testing.T) {
	h := newHarness(t)
	h.timeout = 1500 * time.Millisecond
	done := h.start()
	e := h.engine()

	e.Emit(fx.Line("hold0"))
	e.WaitFor(`^hold release$`)
	e.Emit(fx.Line("need"))
	e.WaitFor(`password .*ACS::35001`) // the challenge is only valid once we have asked
	e.Emit(fx.Line("challenge"))
	h.sys.waitBrowsed(t)
	// The user never completes sign-in.

	res := h.await(done)
	if res.err == nil {
		t.Fatal("Connect hung past its deadline and then reported success")
	}
	if killed := h.sys.killedPids(); len(killed) == 0 {
		t.Error("the engine was left running after the deadline expired")
	}
	if _, ok, _ := h.store().Run(); ok {
		t.Error("run record survived a timed-out connect")
	}
}

// TestFailedConnectRevertsAPriorDNSOverride: a previous connection that died
// mid-flight leaves the resolver pointing at a VPN-only server. If this connect
// also fails, that override must still be undone — otherwise the machine is left
// with broken DNS and no tunnel (SPEC.md story 14).
func TestFailedConnectRevertsAPriorDNSOverride(t *testing.T) {
	h := newHarness(t)
	stranded := dns.Backup{
		ServiceID: "STRANDED",
		State:     dns.Dict{Present: true, ServerAddresses: []string{"192.168.1.1"}},
	}
	if err := h.store().SaveDNS(stranded); err != nil {
		t.Fatal(err)
	}

	h.sys.onSpawn = nil // fail at the dial
	h.timeout = 2 * time.Second
	if res := h.await(h.start()); res.err == nil {
		t.Fatal("expected the connect to fail")
	}

	reverted := h.sys.revertedDNS()
	if len(reverted) == 0 {
		t.Fatal("the stranded DNS override was never reverted")
	}
	if reverted[0].ServiceID != "STRANDED" {
		t.Errorf("reverted %q, want the persisted STRANDED backup", reverted[0].ServiceID)
	}
	if _, ok, _ := h.store().DNS(); ok {
		t.Error("the DNS revert record survived; the next run would revert again")
	}
}

// ------------------------------------------------- prior-connection handling

// TestPartialRecordExistsBeforeTheHandshakeCompletes: connect.go writes the
// PID/socket immediately after spawn so that if this wrapper is killed mid
// handshake, the next run can still find and tear down the orphan. Losing that
// write would strand a root process with nothing recording it.
func TestPartialRecordExistsBeforeTheHandshakeCompletes(t *testing.T) {
	h := newHarness(t)
	done := h.start()
	e := h.engine()

	// Once a command has come back over the socket, Connect is past the spawn
	// and the partial record must already be on disk.
	e.Emit(fx.Line("hold0"))
	e.WaitFor(`^hold release$`)

	mid, ok, err := h.store().Run()
	if err != nil || !ok {
		t.Fatalf("no record written before the handshake completed: ok=%v err=%v", ok, err)
	}
	if mid.OvpnPID != h.sys.pid {
		t.Errorf("partial record pid = %d, want %d — it could not kill the orphan", mid.OvpnPID, h.sys.pid)
	}
	if mid.MgmtSocket != h.sock {
		t.Errorf("partial record socket = %q, want %q", mid.MgmtSocket, h.sock)
	}
	if !mid.Connecting() {
		t.Error("partial record does not read as still connecting; status would call it stale")
	}

	h.handshake2(e, fx.Line("rawSAML"))
	if res := h.await(done); res.err != nil {
		t.Fatalf("Connect failed: %v", res.err)
	}
}

// handshake2 completes a handshake whose first hold/prompt the caller drove.
func (h *harness) handshake2(e *engine, assertion string) {
	h.t.Helper()
	e.Emit(fx.Line("need"))
	e.WaitFor(`password .*ACS::35001`)
	e.Emit(fx.Line("challenge"))
	h.sys.waitBrowsed(h.t)
	e.Emit(fx.Line("hold1"))
	postSAML(h.t, h.addr, assertion)
	e.Emit(fx.Line("need"))
	e.WaitFor(`password .*CRV1::`)
	e.Emit(fx.Line("pushReply"))
	e.Emit(fx.Line("connect"))
}

// TestStaleRecordIsCleanedUpFirst: a previous connection whose process is gone
// must be cleared, and any resolver override it left behind reverted, before the
// new tunnel comes up (SPEC.md story 34).
func TestStaleRecordIsCleanedUpFirst(t *testing.T) {
	h := newHarness(t)
	h.sys.isOpenVPN = false // the recorded pid is not a live acvc-openvpn

	if err := h.store().SaveRun(state.Run{
		Profile: "old", OvpnPID: 999999, ConnectedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.store().SaveDNS(dns.Backup{ServiceID: "OLD"}); err != nil {
		t.Fatal(err)
	}

	done := h.start()
	e := h.engine()
	h.handshake(e, fx.Line("rawSAML"), false)
	res := h.await(done)
	if res.err != nil {
		t.Fatalf("Connect failed: %v\nlog:\n%s", res.err, h.log.String())
	}

	var sawOld bool
	for _, b := range h.sys.revertedDNS() {
		if b.ServiceID == "OLD" {
			sawOld = true
		}
	}
	if !sawOld {
		t.Error("the dead connection's DNS override was never reverted")
	}
	if res.run.Profile != "dev" {
		t.Errorf("connected profile = %q, want the new one", res.run.Profile)
	}
	if !strings.Contains(h.log.String(), "stale") {
		t.Error("cleaning up a stale connection was not logged")
	}
}

// TestSwapTearsDownTheLiveTunnelFirst: SPEC.md story 29 — connecting while
// another tunnel is up must swap cleanly, not leave two engines running.
func TestSwapTearsDownTheLiveTunnelFirst(t *testing.T) {
	h := newHarness(t)
	h.sys.isOpenVPN = true // the recorded pid IS a live acvc-openvpn

	// The pid must belong to a process that genuinely exists, or CleanupStale
	// classifies the record as stale and clears it before the swap path ever
	// sees it. This test process will do; the fake's Kill only records.
	oldPID := os.Getpid()
	if err := h.store().SaveRun(state.Run{
		Profile: "prod", OvpnPID: oldPID, ConnectedAt: time.Now().Add(-time.Minute),
		// No MgmtSocket, so teardown goes down the kill path rather than
		// attempting a management SIGTERM to a socket that is not there.
	}); err != nil {
		t.Fatal(err)
	}

	done := h.start()
	e := h.engine()
	h.handshake(e, fx.Line("rawSAML"), false)
	res := h.await(done)
	if res.err != nil {
		t.Fatalf("Connect failed: %v\nlog:\n%s", res.err, h.log.String())
	}

	var killedOld bool
	for _, p := range h.sys.killedPids() {
		if p == oldPID {
			killedOld = true
		}
	}
	if !killedOld {
		t.Errorf("the previous tunnel (pid %d) was left running; killed = %v", oldPID, h.sys.killedPids())
	}
	if !strings.Contains(h.log.String(), "swapping") {
		t.Error("the swap was not logged")
	}
	if res.run.Profile != "dev" {
		t.Errorf("connected profile = %q, want dev", res.run.Profile)
	}
}

// ------------------------------------------------------------ handshake shape

// TestSAMLArrivingBeforeTheSecondPrompt covers the ordering the spike exposed:
// the assertion can land before the engine re-prompts for credentials. Connect
// must hold it and answer when the prompt arrives, not drop it.
func TestSAMLArrivingBeforeTheSecondPrompt(t *testing.T) {
	h := newHarness(t)
	done := h.start()
	e := h.engine()
	assertion := inflate(fx.Line("rawSAML"), 10_000)

	h.handshake(e, assertion, true) // assertion first, prompt second
	res := h.await(done)

	if res.err != nil {
		t.Fatalf("Connect failed on the SAML-first ordering: %v\nlog:\n%s", res.err, h.log.String())
	}
	if res.run.AssignedIP != "10.8.0.133" {
		t.Errorf("assigned IP = %q", res.run.AssignedIP)
	}

	// The assertion really did cross the socket, url-encoded and whole.
	var crv1 string
	for _, c := range e.Sent() {
		if strings.Contains(c, "CRV1::") {
			crv1 = c
		}
	}
	if crv1 == "" {
		t.Fatal("no CRV1 response reached the engine")
	}
	if !strings.Contains(crv1, url.QueryEscape(assertion)) {
		t.Error("the assertion did not arrive intact and url-encoded")
	}
	if len(crv1) < 10_000 {
		t.Errorf("CRV1 response is %d bytes; the assertion was truncated in transit", len(crv1))
	}
}

// --------------------------------------------------------------- the secret

// TestAssertionNeverReachesTheLog is the end-to-end form of the redaction
// property: not "Redact() works" but "nothing Connect writes anywhere contains
// the credential", at the verbosity a user turns on when debugging — which is
// exactly when the CRV1 command gets logged.
func TestAssertionNeverReachesTheLog(t *testing.T) {
	h := newHarness(t)
	h.verbose = true
	done := h.start()
	e := h.engine()

	assertion := inflate(fx.Line("rawSAML"), 10_000)
	h.handshake(e, assertion, false)
	if res := h.await(done); res.err != nil {
		t.Fatalf("Connect failed: %v", res.err)
	}

	escaped := url.QueryEscape(assertion)
	h.log.mustNotContain(t, assertion, "the raw assertion")
	h.log.mustNotContain(t, escaped, "the url-encoded assertion")
	h.log.mustNotContain(t, escaped[len(escaped)-512:], "the tail of the url-encoded assertion")

	out := h.log.String()
	if !strings.Contains(out, "<redacted len=") {
		t.Errorf("nothing was redacted at all — the CRV1 command may not be reaching the logger:\n%s", out)
	}
	// Verbose really was on, so the assertion had every chance to leak.
	if !strings.Contains(out, "DBG") {
		t.Error("no debug lines logged; this test would pass vacuously")
	}
}
