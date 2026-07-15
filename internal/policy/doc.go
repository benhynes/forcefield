// Package policy compiles and evaluates Forcefield request policies.
//
// A compiled Policy is immutable and safe for concurrent use. Evaluation is
// default-deny: an explicit deny wins over every allow, an evaluation error is
// a deny, and a request which matches no rule is denied.
//
// Callers should forward the CanonicalPath and CanonicalQuery returned in the
// Decision, rather than the request's original spelling. This makes the value
// inspected by the policy the value sent upstream.
package policy
