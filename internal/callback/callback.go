// Package callback is the one-shot loopback HTTP listener that captures the SAML
// assertion. It binds 127.0.0.1:35001 *before* the browser is opened (so if the
// port is taken — e.g. the official client is running — connect aborts rather
// than handing the credential to something else), accepts exactly one response,
// keeps the assertion in memory only, and enforces a hard timeout.
package callback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/larcanjo/awsvpn/web"
)

// Result carries the captured assertion or the reason capture failed.
type Result struct {
	SAML string
	Err  error
}

// Server is a bound, not-yet-serving one-shot listener.
type Server struct {
	ln      net.Listener
	srv     *http.Server
	results chan Result
	done    chan struct{}
	once    sync.Once
}

// Listen binds the loopback callback address. Returns an error (to abort the
// connect loudly) if the port is unavailable.
func Listen(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot bind %s (is the official AWS VPN Client running?): %w", addr, err)
	}
	return &Server{ln: ln, results: make(chan Result, 1), done: make(chan struct{})}, nil
}

// Addr is the bound address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Results delivers the single capture result.
func (s *Server) Results() <-chan Result { return s.results }

// Serve starts handling requests and returns after the first assertion (or a
// bad callback) is delivered to Results, then stops listening. ssoTimeout bounds
// how long we wait for the user to complete SSO. Safe to call once.
func (s *Server) Serve(ssoTimeout time.Duration) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() {
		// Serve blocks until Close; errors other than the expected shutdown are
		// surfaced as a capture failure if nothing was captured first.
		if err := s.srv.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.deliver(Result{Err: fmt.Errorf("callback server error: %w", err)})
		}
	}()

	go func() {
		timer := time.NewTimer(ssoTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.deliver(Result{Err: fmt.Errorf("timed out after %s waiting for SSO", ssoTimeout)})
		case <-s.done: // capture already happened; exit promptly instead of lingering
		}
	}()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// The IdP delivers the assertion via the SAML HTTP POST binding. We accept it
	// ONLY from a POST body and never from the query string, so a local web page
	// the user happens to load during the SSO window cannot inject an
	// attacker-chosen assertion (or DoS the capture) via <img src=".../?SAMLResponse=…">.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	saml := r.PostFormValue("SAMLResponse")
	if saml == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(web.ErrorPage())
		s.deliver(Result{Err: errors.New("callback POST had no SAMLResponse")})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(web.SuccessPage())
	s.deliver(Result{SAML: saml})
}

// deliver sends the first result and schedules the listener to stop. Subsequent
// deliveries are dropped (one-shot).
func (s *Server) deliver(r Result) {
	s.once.Do(func() {
		s.results <- r
		close(s.done) // let the timeout goroutine exit promptly
		// Give the response a moment to flush before tearing the listener down.
		go func() {
			time.Sleep(150 * time.Millisecond)
			s.Close()
		}()
	})
}

// Close stops listening immediately. Idempotent.
func (s *Server) Close() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
		return
	}
	_ = s.ln.Close()
}
