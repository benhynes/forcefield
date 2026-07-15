// Package gitadapter provides the protocol-aware core of a Git smart-HTTP
// adapter.
//
// It intentionally does not know about providers, repository names, protected
// branch names, credentials, or HTTP transports. Callers first classify a
// canonical HTTP route, then parse receive-pack requests before opening a
// credentialed upstream request, and finally evaluate an immutable Policy.
// Policies are default-deny, explicit denies win over allows, and every ref in
// a multi-ref push must be allowed.
package gitadapter
