// Package logging is a tiny leveled logger with hard secret redaction. The SAML
// assertion and any management password must never reach a log file even at high
// verbosity — redacted forms show length only, so verbose logging can't leak the
// bearer credential.
package logging

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// passwordCmdRe matches a management password command and captures the quoted
// value so it can be replaced with its length. Case-insensitive on the keyword.
var passwordCmdRe = regexp.MustCompile(`(?i)(password\s+"[^"]*"\s+")([^"]*)(")`)

// Redactor replaces registered secrets and structurally-detected password
// commands with a length-only form. Safe for concurrent use.
type Redactor struct {
	mu      sync.Mutex
	secrets []string
}

// NewRedactor returns an empty redactor.
func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a literal secret (e.g. the raw SAML assertion) to scrub from all
// future output. Empty strings are ignored.
func (r *Redactor) Add(secret string) {
	if secret == "" {
		return
	}
	r.mu.Lock()
	r.secrets = append(r.secrets, secret)
	r.mu.Unlock()
}

// Redact scrubs known secrets and password commands from s.
func (r *Redactor) Redact(s string) string {
	r.mu.Lock()
	secrets := append([]string(nil), r.secrets...)
	r.mu.Unlock()

	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, placeholder(len(sec)))
		}
	}
	s = passwordCmdRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := passwordCmdRe.FindStringSubmatch(m)
		return sub[1] + placeholder(len(sub[2])) + sub[3]
	})
	return s
}

func placeholder(n int) string { return fmt.Sprintf("<redacted len=%d>", n) }

// Logger writes timestamped, redacted lines to an io.Writer.
type Logger struct {
	mu      sync.Mutex
	w       io.Writer
	red     *Redactor
	verbose bool
}

// New returns a logger writing to w. If verbose is false, Debug lines are
// dropped. The redactor is shared so callers can register secrets as they learn
// them.
func New(w io.Writer, red *Redactor, verbose bool) *Logger {
	if red == nil {
		red = NewRedactor()
	}
	return &Logger{w: w, red: red, verbose: verbose}
}

// Redactor exposes the shared redactor for secret registration.
func (l *Logger) Redactor() *Redactor { return l.red }

// Info logs an always-visible line.
func (l *Logger) Info(format string, args ...any) { l.write("INFO", format, args...) }

// Debug logs only when verbose.
func (l *Logger) Debug(format string, args ...any) {
	if l.verbose {
		l.write("DBG", format, args...)
	}
}

func (l *Logger) write(level, format string, args ...any) {
	line := l.red.Redact(fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s  %-4s %s\n", time.Now().Format("2006-01-02 15:04:05.000"), level, line)
}
