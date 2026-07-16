package callback

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCaptureSAMLResponse(t *testing.T) {
	s, err := Listen("127.0.0.1:0") // ephemeral port to avoid clashing with :35001
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Serve(2 * time.Second)

	// The IdP posts the assertion form-encoded; special chars must decode.
	raw := "PHNhbWxwOlJlc3BvbnNlPnh4eA==+extra/bytes"
	resp, err := http.PostForm("http://"+s.Addr()+"/", url.Values{"SAMLResponse": {raw}})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Authenticated") {
		t.Errorf("expected the success page, got: %.80s", body)
	}

	select {
	case res := <-s.Results():
		if res.Err != nil {
			t.Fatalf("unexpected error: %v", res.Err)
		}
		if res.SAML != raw {
			t.Errorf("captured %q, want %q", res.SAML, raw)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result delivered")
	}
}

func TestPostWithoutSAMLIsError(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Serve(2 * time.Second)

	resp, err := http.PostForm("http://"+s.Addr()+"/", url.Values{"nope": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	select {
	case res := <-s.Results():
		if res.Err == nil {
			t.Error("expected an error result for a SAML-less POST")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result delivered")
	}
}

func TestTimeout(t *testing.T) {
	s, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Serve(100 * time.Millisecond) // no request will arrive

	select {
	case res := <-s.Results():
		if res.Err == nil {
			t.Error("expected a timeout error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout was not delivered")
	}
}

func TestPortInUseAborts(t *testing.T) {
	s1, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	// A second bind of the same address must fail (this is the guard that stops
	// us proceeding when the official client already holds :35001).
	if _, err := Listen(s1.Addr()); err == nil {
		t.Error("expected the second bind to fail")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}
