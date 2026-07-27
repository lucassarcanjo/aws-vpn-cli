package cli

import "github.com/lucassarcanjo/aws-vpn-cli/internal/privilege"

// grantInstalled reports whether the install-privilege rule is on disk. It is a
// variable so the rendering tests can pin the answer rather than depending on
// whether the machine running them happens to have the grant.
var grantInstalled = privilege.GrantInstalled

// sudoPrefix is the `sudo ` a suggested command still needs — and nothing once
// the user has installed the grant, because from then on `connect` and
// `disconnect` elevate themselves. Telling someone to type `sudo` after they
// opted out of typing it reads as if the opt-in never took.
//
// It keys off the rule being present rather than probing sudo, the same signal
// `suggestGrant` uses: a suggestion is not the place to spend a subprocess, and
// a rule that no longer covers this binary is diagnosed properly by notRootErr
// on the run that actually needs root.
func sudoPrefix() string {
	if grantInstalled() {
		return ""
	}
	return "sudo "
}
