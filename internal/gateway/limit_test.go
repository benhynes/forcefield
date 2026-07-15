package gateway

import (
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/tokens"
)

func TestLimitManagerEnforcesDelegationChainAtomically(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newLimitManager()
	m.now = func() time.Time { return now }
	expires := now.Add(time.Hour)
	root := limitScope{key: "root/grant", limits: tokens.Limits{RequestsPerSecond: 10, Burst: 10, RequestBudget: 3, ByteBudget: 8}, expiresAt: expires}
	child := limitScope{key: "child/grant", limits: tokens.Limits{RequestsPerSecond: 1, Burst: 2, RequestBudget: 2, ByteBudget: 5}, expiresAt: expires}

	if !m.allowRequest([]limitScope{root, child}) || !m.allowRequest([]limitScope{root, child}) {
		t.Fatal("child's initial burst was denied")
	}
	if m.allowRequest([]limitScope{root, child}) {
		t.Fatal("child request budget did not apply")
	}
	// A child's narrower limit has its own state and does not rewrite the root.
	if !m.allowRequest([]limitScope{root}) {
		t.Fatal("narrow child permanently throttled its root")
	}
	if m.allowRequest([]limitScope{root}) {
		t.Fatal("root aggregate request budget was exceeded")
	}

	otherRoot := limitScope{key: "other-root", limits: tokens.Limits{ByteBudget: 8}, expiresAt: expires}
	otherChild := limitScope{key: "other-child", limits: tokens.Limits{ByteBudget: 5}, expiresAt: expires}
	if !m.allowBytes([]limitScope{otherRoot, otherChild}, 4) {
		t.Fatal("initial byte charge was denied")
	}
	if m.allowBytes([]limitScope{otherRoot, otherChild}, 2) {
		t.Fatal("child byte budget was exceeded")
	}
	// The failed atomic child charge must not consume the root's remainder.
	if !m.allowBytes([]limitScope{otherRoot}, 4) {
		t.Fatal("failed child charge consumed root bytes")
	}
}

func TestLimitManagerRateRefillExpiryAndClaimMismatch(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newLimitManager()
	m.now = func() time.Time { return now }
	expires := now.Add(2 * time.Second)
	scope := limitScope{key: "token/grant", limits: tokens.Limits{RequestsPerSecond: 1, Burst: 1}, expiresAt: expires}

	if !m.allowRequest([]limitScope{scope}) || m.allowRequest([]limitScope{scope}) {
		t.Fatal("rate limit did not consume the initial token")
	}
	now = now.Add(time.Second)
	if !m.allowRequest([]limitScope{scope}) {
		t.Fatal("rate limit did not refill")
	}
	changed := scope
	changed.limits.Burst = 2
	if m.allowRequest([]limitScope{changed}) {
		t.Fatal("immutable claim mismatch was accepted")
	}
	now = expires
	if m.allowRequest([]limitScope{scope}) {
		t.Fatal("expired scope was accepted")
	}
	// Force a sweep and verify expired state is reclaimed.
	m.nextSweep = time.Time{}
	if m.allowBytes([]limitScope{{key: "live", expiresAt: now.Add(time.Hour)}}, 0) != true {
		t.Fatal("live scope was denied")
	}
	if _, ok := m.states[scope.key]; ok {
		t.Fatal("expired limiter state was not reclaimed")
	}
}

func TestLimitManagerRejectsDuplicateAndOverflow(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newLimitManager()
	m.now = func() time.Time { return now }
	scope := limitScope{key: "same", expiresAt: now.Add(time.Hour)}
	if m.allowRequest([]limitScope{scope, scope}) {
		t.Fatal("duplicate scope was accepted")
	}
	if !m.allowBytes([]limitScope{scope}, ^uint64(0)) || m.allowBytes([]limitScope{scope}, 1) {
		t.Fatal("byte counter overflow was not rejected")
	}
}
