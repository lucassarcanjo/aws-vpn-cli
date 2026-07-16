// Package web embeds the two static pages the one-shot SAML callback serves.
// Embedding them keeps awsvpn a single self-contained binary with no runtime
// file dependencies.
package web

import _ "embed"

//go:embed callback_success.html
var successPage []byte

//go:embed callback_error.html
var errorPage []byte

// SuccessPage is shown after the SAML assertion is captured.
func SuccessPage() []byte { return successPage }

// ErrorPage is shown when the callback POST is missing or malformed.
func ErrorPage() []byte { return errorPage }
