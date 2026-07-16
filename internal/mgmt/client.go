// Package mgmt is the impure runtime that owns the connection to acvc-openvpn's
// management interface: it pumps lines out of the socket (into the reducer) and
// commands in (out of the reducer). The driving logic that decides *what* to send
// lives in the pure reducer; this package only moves bytes. The spike's driver
// was ~90% of this module.
package mgmt

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

// Client is a connected management channel.
type Client struct {
	conn  net.Conn
	lines chan string
}

// Dial connects to the unix-domain management socket, retrying until it appears
// (acvc-openvpn creates it shortly after launch) or the deadline passes. On
// success it enables the real-time notifications the reducer needs.
func Dial(socketPath string, timeout time.Duration) (*Client, error) {
	deadline := time.Now().Add(timeout)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(socketPath); statErr == nil {
			conn, err = net.Dial("unix", socketPath)
			if err == nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		if err == nil {
			err = fmt.Errorf("management socket %s never appeared", socketPath)
		}
		return nil, fmt.Errorf("connecting to management socket: %w", err)
	}

	c := &Client{conn: conn, lines: make(chan string, 64)}
	go c.read()

	// Enable state notifications and the log stream (PUSH_REPLY arrives as a log
	// line). >HOLD and >PASSWORD prompts are emitted without extra opt-in.
	if err := c.Send("state on"); err != nil {
		c.Close()
		return nil, err
	}
	if err := c.Send("log on"); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Lines is the stream of raw management lines. Closed when the connection ends.
func (c *Client) Lines() <-chan string { return c.lines }

// Send writes a single management command (newline-terminated).
func (c *Client) Send(cmd string) error {
	_, err := c.conn.Write([]byte(cmd + "\n"))
	return err
}

// Close ends the management connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) read() {
	defer close(c.lines)
	sc := bufio.NewScanner(c.conn)
	// SAML responses ride the socket as a ~10KB password command echoed back in
	// some log lines; allow generously large lines so nothing is truncated.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		c.lines <- sc.Text()
	}
}

// SignalTerm asks a possibly-out-of-band tunnel to exit cleanly, by dialing its
// management socket and sending "signal SIGTERM". Used by `disconnect` when no
// live client is held.
func SignalTerm(socketPath string) error {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("signal SIGTERM\n"))
	// Give openvpn a moment to act on it before the socket closes.
	time.Sleep(200 * time.Millisecond)
	return err
}
