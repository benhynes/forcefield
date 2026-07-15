// Package headersafety centralizes conservative classifications used at the
// HTTP credential boundary.
package headersafety

import "strings"

// CredentialBearing reports whether a header name conventionally carries a
// credential, session, signature, or key. Such fields may be used as an
// explicit Forcefield client/injection carrier, but must never pass through as
// an ordinary forwarded or static header: that would let a caller select a
// second upstream principal or put an unscanned secret in configuration.
//
// Custom provider names cannot be recognized perfectly. This intentionally
// errs toward requiring a dedicated adapter for ambiguous *-Key fields while
// preserving the common non-secret Idempotency-Key request header.
func CredentialBearing(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "cookie", "cookie2", "set-cookie":
		return true
	}
	parts := strings.FieldsFunc(name, func(value rune) bool { return value == '-' || value == '_' })
	for index, part := range parts {
		switch part {
		case "apikey", "auth", "authentication", "authorization", "bearer", "credential", "credentials",
			"jwt", "password", "passwd", "secret", "session", "signature", "token":
			return true
		case "key":
			if index == 0 || parts[index-1] != "idempotency" {
				return true
			}
		}
	}
	return false
}
