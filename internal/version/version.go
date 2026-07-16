// Package version carries build metadata, overridable at link time with -ldflags
// so `awsvpn version` reports something useful in bug reports.
package version

import "fmt"

var (
	// Version is the semantic version; overridden at build time.
	Version = "0.1.0-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build date.
	Date = "unknown"
)

// String renders the full version line.
func String() string {
	return fmt.Sprintf("awsvpn %s (commit %s, built %s)", Version, Commit, Date)
}
