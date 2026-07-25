package daemon_test

// The harness for driving daemon.Connect end to end without root.
//
// The rule it follows: fake ONLY what genuinely needs root. Spawning
// acvc-openvpn, running codesign, driving scutil, killing a pid and opening a
// browser all do, so they sit behind system.Port and get a recording fake here.
// Everything else does not — a unix socket, a state directory and a loopback
// port all cost nothing to create for real — so the tests use the real thing and
// exercise the real code in internal/mgmt, internal/state and internal/callback
// rather than a stand-in for it. See docs/adr/0001.
//
// The fake records WHETHER things happened, never the ORDER they happened in.
// Ordering guarantees are asserted as outcomes instead ("the port was taken, so
// nothing was spawned"), which survives refactoring in a way that asserting a
// call sequence would not.

import (
	"bufio"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/dns"
	"github.com/lucassarcanjo/aws-vpn-cli/internal/system"
)

// ---------------------------------------------------------------- fake system

// fakeSys stands in for the privileged operations. Canned outcomes go in; what
// happened comes out.
type fakeSys struct {
	mu sync.Mutex

	// Canned behaviour, set by the test before Connect runs.
	verifyErr error
	spawnErr  error
	applyErr  error
	revertErr error
	pid       int
	isOpenVPN bool // what IsOpenVPN reports for any live pid

	// onSpawn runs when SpawnOpenVPN is called, and is how a test starts the
	// engine on the management socket — mirroring acvc-openvpn, which creates
	// its socket shortly AFTER launch (which is why mgmt.Dial has to retry).
	onSpawn func(sock string)

	// browsed carries each URL passed to OpenBrowser. Buffered, because drive
	// calls OpenBrowser inline and would deadlock on an unbuffered send.
	browsed chan string

	// Recorded outcomes.
	verified      bool
	verifiedBin   string
	verifiedTeam  string
	spawned       bool
	spawnSpec     system.SpawnSpec
	dnsApplied    [][]string
	dnsReverted   []dns.Backup
	killed        []int
	isOpenVPNPids []int
	copied        []string
}

func newFakeSys() *fakeSys {
	return &fakeSys{pid: 4242, browsed: make(chan string, 8)}
}

func (f *fakeSys) VerifySignature(binPath, teamID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified, f.verifiedBin, f.verifiedTeam = true, binPath, teamID
	return f.verifyErr
}

func (f *fakeSys) SpawnOpenVPN(spec system.SpawnSpec) (int, error) {
	f.mu.Lock()
	if f.spawnErr != nil {
		err := f.spawnErr
		f.mu.Unlock()
		return 0, err
	}
	f.spawned, f.spawnSpec = true, spec
	onSpawn, pid := f.onSpawn, f.pid
	f.mu.Unlock()

	if onSpawn != nil {
		onSpawn(spec.SocketPath)
	}
	return pid, nil
}

func (f *fakeSys) OpenBrowser(u string) error {
	select {
	case f.browsed <- u:
	default: // a test that does not care about the browser must not be blocked
	}
	return nil
}

// CopyToClipboard is offered during the sign-in wait so the user can paste the
// link into the browser they are actually signed in to. It handles the SSO URL,
// not the assertion, so there is no secret to guard here — but it is recorded so
// a test can assert the link really was the one we opened.
func (f *fakeSys) CopyToClipboard(text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copied = append(f.copied, text)
	return nil
}

func (f *fakeSys) ApplyDNS(servers []string) (dns.Backup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return dns.Backup{}, f.applyErr
	}
	f.dnsApplied = append(f.dnsApplied, servers)
	// A non-empty ServiceID is what marks a backup as real; drive checks it
	// before reverting on the failure path.
	return dns.Backup{
		ServiceID: "TEST-SERVICE",
		State:     dns.Dict{Present: true, ServerAddresses: []string{"192.168.1.1"}},
	}, nil
}

func (f *fakeSys) RevertDNS(b dns.Backup) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsReverted = append(f.dnsReverted, b)
	return f.revertErr
}

func (f *fakeSys) Kill(pid int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, pid)
	return nil
}

func (f *fakeSys) IsOpenVPN(pid int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.isOpenVPNPids = append(f.isOpenVPNPids, pid)
	return f.isOpenVPN
}

// --- accessors, so assertions never read the recorded fields under a race ---

func (f *fakeSys) didSpawn() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.spawned
}

func (f *fakeSys) didVerify() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verified
}

func (f *fakeSys) killedPids() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.killed...)
}

func (f *fakeSys) appliedDNS() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.dnsApplied...)
}

func (f *fakeSys) revertedDNS() []dns.Backup {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dns.Backup(nil), f.dnsReverted...)
}

func (f *fakeSys) spawnedSpec() system.SpawnSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.spawnSpec
}

// waitBrowsed returns the URL Connect opened, or fails the test.
func (f *fakeSys) waitBrowsed(t *testing.T) string {
	t.Helper()
	select {
	case u := <-f.browsed:
		return u
	case <-time.After(10 * time.Second):
		t.Fatal("Connect never opened the browser")
		return ""
	}
}

// ---------------------------------------------------------------- fake engine

// engine is a real unix socket standing in for acvc-openvpn's management
// interface. The test drives it a line at a time, so each interleaving of the
// handshake is explicit rather than a timing accident.
type engine struct {
	t    *testing.T
	path string
	ln   net.Listener

	mu       sync.Mutex
	sent     []string // commands Connect wrote to us
	conn     net.Conn
	accepted chan struct{}
	once     sync.Once

	// writes is drained by a single goroutine so emitted lines reach Connect in
	// the order the test emitted them. Writing from a goroutine per Emit would
	// let the engine deliver PUSH_REPLY after CONNECTED, which no real endpoint
	// does and which the reducer is not required to tolerate.
	writes chan string
}

// newEngine binds the management socket. Call it from onSpawn so the socket
// appears only after Connect has "launched" the engine.
func newEngine(t *testing.T, path string) *engine {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Errorf("binding management socket %s: %v", path, err)
		return nil
	}
	e := &engine{
		t: t, path: path, ln: ln,
		accepted: make(chan struct{}),
		writes:   make(chan string, 64),
	}
	t.Cleanup(e.close)
	go e.accept()
	go e.writer()
	return e
}

// writer serializes emitted lines onto the socket, in order.
func (e *engine) writer() {
	<-e.accepted
	e.mu.Lock()
	conn := e.conn
	e.mu.Unlock()
	for line := range e.writes {
		// A line larger than the socket buffer blocks until Connect drains it;
		// the deadline stops a dead reader from wedging the test forever.
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			return
		}
	}
}

func (e *engine) accept() {
	conn, err := e.ln.Accept()
	if err != nil {
		return
	}
	e.mu.Lock()
	e.conn = conn
	e.mu.Unlock()
	e.once.Do(func() { close(e.accepted) })

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		e.mu.Lock()
		e.sent = append(e.sent, sc.Text())
		e.mu.Unlock()
	}
}

func (e *engine) close() {
	e.mu.Lock()
	conn := e.conn
	e.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	_ = e.ln.Close()
}

// waitAccepted blocks until Connect has dialled us.
func (e *engine) waitAccepted() {
	e.t.Helper()
	select {
	case <-e.accepted:
	case <-time.After(10 * time.Second):
		e.t.Fatal("Connect never dialled the management socket")
	}
}

// Emit queues one management line for delivery to Connect. Lines are delivered
// in the order they are emitted, and Emit never blocks the test.
func (e *engine) Emit(line string) {
	e.t.Helper()
	select {
	case e.writes <- line:
	default:
		e.t.Fatalf("emit queue is full; Connect is not draining the socket. Queued: %.60q", line)
	}
}

// WaitFor blocks until Connect has sent a command matching pattern, and returns
// it. Failing here means the handshake stalled, so the message names what was
// expected and what actually arrived.
func (e *engine) WaitFor(pattern string) string {
	e.t.Helper()
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range e.Sent() {
			if re.MatchString(c) {
				return c
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("Connect never sent a command matching %q; it sent: %v", pattern, e.Sent())
	return ""
}

// Sent is every command Connect has written to the management channel.
func (e *engine) Sent() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.sent...)
}

// ------------------------------------------------------------------- plumbing

// socketPath returns a short path for a unix socket. t.TempDir() embeds the test
// name, which can push the path past the ~104-byte sun_path limit on macOS.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "avd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "m")
	if len(p) > 100 {
		t.Fatalf("socket path is %d bytes, over the platform limit: %s", len(p), p)
	}
	return p
}

// freeAddr picks a loopback address nothing is listening on. Connect binds the
// callback itself, so the test has to know the address in advance to post to it.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// postSAML delivers an assertion to the callback the way the IdP does: an HTTP
// POST body, never a query string. Returns once the callback has responded, so
// the caller knows the assertion is in hand.
func postSAML(t *testing.T, addr, assertion string) {
	t.Helper()
	resp, err := http.PostForm("http://"+addr+"/", url.Values{"SAMLResponse": {assertion}})
	if err != nil {
		t.Fatalf("posting the assertion to %s: %v", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("callback returned %d, want 200", resp.StatusCode)
	}
}

// inflate grows the fixture assertion to the ~10KB an endpoint really sends, so
// the assertion crosses the socket at its real size.
func inflate(atom string, size int) string {
	return strings.Repeat(atom, size/len(atom)+1)
}

// logBuf collects everything Connect logs, so tests can assert on what did and
// did not reach a log. Safe for concurrent writes.
type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (l *logBuf) mustNotContain(t *testing.T, secret, what string) {
	t.Helper()
	if strings.Contains(l.String(), secret) {
		t.Errorf("%s reached the log", what)
	}
}
