package gateway

import (
	"sync"
	"time"

	"github.com/benhynes/forcefield/internal/tokens"
)

// limitScope is one independently bounded node in a token's delegation chain.
// A request is charged atomically to every scope, preventing descendants from
// multiplying an ancestor's budget without letting a narrow child permanently
// throttle its parent or siblings.
type limitScope struct {
	key       string
	limits    tokens.Limits
	expiresAt time.Time
}

type limitManager struct {
	mu        sync.Mutex
	states    map[string]*limitState
	now       func() time.Time
	nextSweep time.Time
}

type limitState struct {
	limits    tokens.Limits
	expiresAt time.Time
	tokens    float64
	last      time.Time
	requests  uint64
	bytes     uint64
}

func newLimitManager() *limitManager {
	return &limitManager{states: make(map[string]*limitState), now: time.Now}
}

func (m *limitManager) allowRequest(scopes []limitScope) bool {
	if len(scopes) == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweepLocked(now)
	states, ok := m.statesLocked(scopes, now)
	if !ok {
		return false
	}
	for _, state := range states {
		state.refill(now)
		if state.requests == ^uint64(0) || state.limits.RequestBudget != 0 && state.requests >= state.limits.RequestBudget {
			return false
		}
		if state.limits.RequestsPerSecond != 0 && state.tokens < 1 {
			return false
		}
	}
	for _, state := range states {
		if state.limits.RequestsPerSecond != 0 {
			state.tokens--
		}
		state.requests++
	}
	return true
}

// allowBytes accounts for request payload bytes. ByteBudget deliberately
// means aggregate client-to-upstream bytes in v1; response budgets need an
// adapter-specific semantic because truncating a streamed API response can be
// unsafe and misleading.
func (m *limitManager) allowBytes(scopes []limitScope, count uint64) bool {
	if len(scopes) == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweepLocked(now)
	states, ok := m.statesLocked(scopes, now)
	if !ok {
		return false
	}
	for _, state := range states {
		if count > ^uint64(0)-state.bytes {
			return false
		}
		if state.limits.ByteBudget != 0 && (state.bytes > state.limits.ByteBudget || count > state.limits.ByteBudget-state.bytes) {
			return false
		}
	}
	for _, state := range states {
		state.bytes += count
	}
	return true
}

func (m *limitManager) statesLocked(scopes []limitScope, now time.Time) ([]*limitState, bool) {
	states := make([]*limitState, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope.key == "" || scope.expiresAt.IsZero() || !now.Before(scope.expiresAt) {
			return nil, false
		}
		if _, duplicate := seen[scope.key]; duplicate {
			return nil, false
		}
		seen[scope.key] = struct{}{}

		state := m.states[scope.key]
		if state == nil {
			state = &limitState{limits: scope.limits, expiresAt: scope.expiresAt, last: now}
			state.tokens = float64(effectiveBurst(scope.limits))
			m.states[scope.key] = state
		} else if state.limits != scope.limits || !state.expiresAt.Equal(scope.expiresAt) {
			// Token claims are immutable. A reused key with different claims is
			// an invariant violation and must fail closed rather than reset use.
			return nil, false
		}
		states = append(states, state)
	}
	return states, true
}

func (m *limitManager) sweepLocked(now time.Time) {
	if !m.nextSweep.IsZero() && now.Before(m.nextSweep) {
		return
	}
	for key, state := range m.states {
		if !now.Before(state.expiresAt) {
			delete(m.states, key)
		}
	}
	m.nextSweep = now.Add(time.Minute)
}

func (s *limitState) refill(now time.Time) {
	if s.limits.RequestsPerSecond == 0 || !now.After(s.last) {
		return
	}
	s.tokens += now.Sub(s.last).Seconds() * float64(s.limits.RequestsPerSecond)
	burst := float64(effectiveBurst(s.limits))
	if s.tokens > burst {
		s.tokens = burst
	}
	s.last = now
}

func effectiveBurst(limits tokens.Limits) uint64 {
	if limits.RequestsPerSecond == 0 {
		return 0
	}
	if limits.Burst == 0 {
		return 1
	}
	return limits.Burst
}
