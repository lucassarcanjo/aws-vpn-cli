package reducer

import (
	"net/url"
	"strings"
	"testing"

	"github.com/lucassarcanjo/aws-vpn-cli/internal/logging"
)

// TestAssertionNeverSurvivesRedaction is the security property that spans the
// reducer and the logger, and belongs to neither alone.
//
// daemon.drive registers the RAW assertion with the redactor the moment it is
// captured, then logs every management command it sends at Debug. But the
// command the reducer emits carries url.QueryEscape(assertion) — a DIFFERENT
// string from the one registered — so the literal-secret path never matches it.
// The only thing standing between a ~10KB bearer credential and the log file at
// --verbose is the structural password-command regex.
//
// This drives the real captured handshake and asserts that neither form of the
// assertion survives redaction of any emitted command. It fails if the regex is
// weakened, if the command shape changes so the regex stops matching it, or if
// someone assumes registering the raw assertion is sufficient.
func TestAssertionNeverSurvivesRedaction(t *testing.T) {
	// The real assertion is ~10KB. Inflate the fixture to that scale so the test
	// exercises the size the socket and the log actually see.
	assertion := rawSAMLAssertion + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo/+", 220)
	if len(assertion) < 8000 {
		t.Fatalf("inflated assertion is only %d bytes; expected ~10KB", len(assertion))
	}
	escaped := url.QueryEscape(assertion)
	if escaped == assertion {
		t.Fatal("fixture assertion has no characters that url-encoding changes")
	}

	r := newRunner()
	r.line(lineHold0).
		line(lineNeed).
		line(lineChallenge).
		line(lineReconn).
		line(lineHold1).
		line(lineNeed).
		send(SAMLCaptured{Raw: assertion}).
		line(linePushReply).
		line(lineConnect)

	if r.state.Phase() != PhaseConnected {
		t.Fatalf("phase = %v, want Connected; fail=%q", r.state.Phase(), r.state.FailReason())
	}

	// Prime the redactor exactly as daemon.drive does: the raw assertion only.
	red := logging.NewRedactor()
	red.Add(assertion)

	cmds := r.sendMgmtCmds()
	var sawCRV1 bool
	for i, cmd := range cmds {
		if strings.Contains(cmd, "CRV1::") {
			sawCRV1 = true
		}
		out := red.Redact(cmd)
		if strings.Contains(out, assertion) {
			t.Errorf("cmd[%d]: raw assertion survived redaction", i)
		}
		if strings.Contains(out, escaped) {
			t.Errorf("cmd[%d]: URL-ENCODED assertion survived redaction — "+
				"registering the raw form is not enough; the password-command "+
				"regex is the only thing scrubbing the wire form", i)
		}
		// A long tail of the encoded form must not leak either: a regex that
		// matched only a prefix would pass the checks above while still spilling
		// most of the credential.
		if tail := escaped[len(escaped)-512:]; strings.Contains(out, tail) {
			t.Errorf("cmd[%d]: tail of the encoded assertion survived redaction", i)
		}
	}
	if !sawCRV1 {
		t.Fatal("transcript never produced a CRV1 response; the test asserted nothing")
	}
}

// TestAssertionNeverSurvivesTheLogWritePath is the same property one level out:
// through the Logger, as daemon.drive actually emits it. Redact() being correct
// is worth nothing if the write path forgets to call it.
func TestAssertionNeverSurvivesTheLogWritePath(t *testing.T) {
	assertion := rawSAMLAssertion + strings.Repeat("c2VjcmV0", 1200)
	escaped := url.QueryEscape(assertion)

	r := newRunner()
	r.line(lineHold0).line(lineNeed).line(lineChallenge).line(lineHold1).
		line(lineNeed).send(SAMLCaptured{Raw: assertion}).
		line(linePushReply).line(lineConnect)

	var log strings.Builder
	red := logging.NewRedactor()
	// verbose=true: the leak this guards against is only reachable at high
	// verbosity, which is exactly when a user turns logging up to debug a problem.
	lg := logging.New(&log, red, true)

	red.Add(assertion)
	lg.Info("SAML assertion captured (%d bytes)", len(assertion))
	for _, cmd := range r.sendMgmtCmds() {
		lg.Debug(">> %s", cmd)
	}

	out := log.String()
	if strings.Contains(out, assertion) {
		t.Error("raw assertion reached the log")
	}
	if strings.Contains(out, escaped) {
		t.Error("url-encoded assertion reached the log")
	}
	if strings.Contains(out, escaped[len(escaped)-512:]) {
		t.Error("tail of the url-encoded assertion reached the log")
	}
	if !strings.Contains(out, "<redacted len=") {
		t.Errorf("nothing was redacted at all; the write path may not be calling Redact:\n%s", out)
	}
}
