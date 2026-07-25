package mgmt

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/fixture"
)

// A management socket is a plain unix socket, and a unix socket costs nothing to
// create locally — so these tests use a real one rather than a fake. What they
// exercise is exactly what cannot be exercised any other way: the retry-until-it-
// appears loop, the scanner's line ceiling, and the channel's close semantics.

// fakeEngine stands in for acvc-openvpn: a real unix socket that records the
// commands written to it and emits lines on demand.
type fakeEngine struct {
	t    *testing.T
	path string
	ln   net.Listener

	mu       sync.Mutex
	received []string

	conn     net.Conn
	accepted chan struct{}
}

// socketPath returns a short path for a unix socket. t.TempDir() embeds the test
// name, which can push the path past the ~104-byte sun_path limit on macOS, so
// these tests use their own short temp dir instead.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "avm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "m")
	if len(path) > 100 {
		t.Fatalf("socket path is %d bytes, over the platform limit: %s", len(path), path)
	}
	return path
}

// listen binds a management socket on a short temp path.
func listen(t *testing.T) *fakeEngine {
	t.Helper()
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("binding %s: %v", path, err)
	}
	e := &fakeEngine{t: t, path: path, ln: ln, accepted: make(chan struct{})}
	t.Cleanup(func() { _ = ln.Close() })
	go e.accept()
	return e
}

func (e *fakeEngine) accept() {
	conn, err := e.ln.Accept()
	if err != nil {
		return
	}
	e.conn = conn
	close(e.accepted)
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		e.mu.Lock()
		e.received = append(e.received, sc.Text())
		e.mu.Unlock()
	}
}

// waitAccepted blocks until the client has connected.
func (e *fakeEngine) waitAccepted() {
	e.t.Helper()
	select {
	case <-e.accepted:
	case <-time.After(5 * time.Second):
		e.t.Fatal("client never connected")
	}
}

// emit writes one management line to the connected client.
//
// The write happens on its own goroutine under a deadline because a line larger
// than the socket buffer blocks until the client drains it — and if the client's
// scanner has given up (the very failure these tests look for), a synchronous
// write would hang the test rather than fail it.
func (e *fakeEngine) emit(line string) {
	e.t.Helper()
	e.waitAccepted()
	_ = e.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	go func() {
		if _, err := e.conn.Write([]byte(line + "\n")); err != nil {
			e.t.Logf("emit of %d bytes did not complete: %v", len(line), err)
		}
	}()
}

// gotWithin waits for at least n received commands and returns them.
func (e *fakeEngine) gotWithin(n int, d time.Duration) []string {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		got := append([]string(nil), e.received...)
		e.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.t.Fatalf("only %d commands received in %s, want %d: %v", len(e.received), d, n, e.received)
	return nil
}

func (e *fakeEngine) closeConn() {
	e.waitAccepted()
	_ = e.conn.Close()
}

// TestDialEnablesStateAndLog: the reducer needs both notification streams —
// PUSH_REPLY only ever arrives as a log line, so `log on` is not optional.
func TestDialEnablesStateAndLog(t *testing.T) {
	e := listen(t)
	c, err := Dial(e.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	got := e.gotWithin(2, 2*time.Second)
	want := []string{"state on", "log on"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("setup cmd[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// TestDialWatchEnablesOnlyState: the supervisor must not turn the log stream on,
// whose replayed backlog could echo an earlier handshake line and read as a drop.
func TestDialWatchEnablesOnlyState(t *testing.T) {
	e := listen(t)
	c, err := DialWatch(e.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	got := e.gotWithin(1, 2*time.Second)
	if len(got) != 1 || got[0] != "state on" {
		t.Errorf("setup cmds = %v, want exactly [state on]", got)
	}
	// Give a stray `log on` time to show up before declaring it absent.
	time.Sleep(100 * time.Millisecond)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.received {
		if c == "log on" {
			t.Error("DialWatch enabled the log stream")
		}
	}
}

// TestLongLinesSurvive guards internal/mgmt's whole reason for existing. The
// SAML assertion rides the socket as a ~10KB password command and is echoed back
// on log lines. Truncating it is the exact failure that forces other projects to
// patch OpenVPN, and it would surface as an unexplained auth rejection rather
// than an obvious error.
//
// Two sizes, because they catch different mistakes (each verified by actually
// making the mutation and watching the case go red):
//   - ~10KB is the real-world requirement. It catches shrinking the scanner's
//     initial buffer to below an assertion's size.
//   - 256KB catches REMOVING the sc.Buffer call (bufio then tops out at its 64KB
//     default) and catches lowering maxTokenSize alone. Neither of those is
//     visible at 10KB, because a 10KB token fits in the 64KB initial buffer
//     without ever entering the grow path where maxTokenSize is enforced — so
//     without this case, deleting that line is silent.
func TestLongLinesSurvive(t *testing.T) {
	fx := fixture.Handshake()
	atom := fx.Line("rawSAML")

	for _, tc := range []struct {
		name string
		size int
	}{
		{"real assertion (~10KB)", 10_000},
		{"headroom beyond bufio's 64KB default", 256_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := listen(t)
			c, err := Dial(e.path, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			long := ">LOG:1784222495,,ECHO: " + strings.Repeat(atom, tc.size/len(atom)+1)
			if len(long) < tc.size {
				t.Fatalf("test line is %d bytes, wanted >= %d", len(long), tc.size)
			}
			e.emit(long)

			select {
			case got := <-c.Lines():
				if got != long {
					t.Errorf("line truncated: got %d bytes, want %d", len(got), len(long))
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("no line delivered for a %d-byte line — the scanner most "+
					"likely dropped it as too long", len(long))
			}
		})
	}
}

// TestDialWaitsForALateSocket: acvc-openvpn creates its socket some time after
// launch, so Dial must poll rather than fail on the first miss.
func TestDialWaitsForALateSocket(t *testing.T) {
	path := socketPath(t)

	ready := make(chan *fakeEngine, 1)
	go func() {
		time.Sleep(250 * time.Millisecond) // socket appears well after the first attempt
		ln, err := net.Listen("unix", path)
		if err != nil {
			ready <- nil
			return
		}
		e := &fakeEngine{t: t, path: path, ln: ln, accepted: make(chan struct{})}
		go e.accept()
		ready <- e
	}()

	start := time.Now()
	c, err := Dial(path, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial gave up on a socket that appeared after 250ms: %v", err)
	}
	defer c.Close()
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("connected in %s — earlier than the socket existed", elapsed)
	}
	if e := <-ready; e != nil {
		_ = e.ln.Close()
	}
}

// TestDialTimesOutWhenTheSocketNeverAppears: a spawn that died must surface as a
// dial error so connect can kill the process and clear state, not hang.
func TestDialTimesOutWhenTheSocketNeverAppears(t *testing.T) {
	path := socketPath(t) + "-absent"
	start := time.Now()
	if _, err := Dial(path, 300*time.Millisecond); err == nil {
		t.Fatal("expected an error when the socket never appears")
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Errorf("gave up after %s, before the timeout elapsed", elapsed)
	}
}

// TestLinesClosesWhenTheEngineGoesAway: drive and the supervisor both treat a
// closed Lines() channel as "the tunnel is gone", so the close must actually
// happen when the peer disconnects.
func TestLinesClosesWhenTheEngineGoesAway(t *testing.T) {
	e := listen(t)
	c, err := Dial(e.path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	e.emit(">HOLD:Waiting for hold release:0")
	select {
	case <-c.Lines():
	case <-time.After(2 * time.Second):
		t.Fatal("no line delivered")
	}

	e.closeConn()
	select {
	case _, ok := <-c.Lines():
		if ok {
			// Drain one more, then the channel must close.
			select {
			case _, ok := <-c.Lines():
				if ok {
					t.Error("Lines() stayed open after the engine disconnected")
				}
			case <-time.After(2 * time.Second):
				t.Error("Lines() never closed after the engine disconnected")
			}
		}
	case <-time.After(2 * time.Second):
		t.Error("Lines() never closed after the engine disconnected")
	}
}

// TestSignalTermSendsTheSignal: disconnect relies on this to make openvpn remove
// its own routes, rather than falling back to a kill that leaves them behind.
func TestSignalTermSendsTheSignal(t *testing.T) {
	e := listen(t)
	if err := SignalTerm(e.path); err != nil {
		t.Fatal(err)
	}
	got := e.gotWithin(1, 2*time.Second)
	if got[0] != "signal SIGTERM" {
		t.Errorf("sent %q, want %q", got[0], "signal SIGTERM")
	}
}

// TestSignalTermOnAMissingSocketErrors: teardown must be able to tell that the
// clean path is unavailable so it can fall back to killing the pid.
func TestSignalTermOnAMissingSocketErrors(t *testing.T) {
	if err := SignalTerm(socketPath(t) + "-absent"); err == nil {
		t.Error("expected an error for a socket that does not exist")
	}
}
