// Package secrets retrieves credentials while making ownership and lifetime
// explicit. A Backend returns a Lease owned by its caller. The caller must
// release the lease when it has finished injecting the credential.
package secrets

import (
	"context"
	"errors"
	"runtime"
	"sync"
)

var (
	// ErrNotFound means that a backend has no value for the requested reference.
	// It deliberately does not include the reference in its text.
	ErrNotFound = errors.New("secrets: value not found")
	// ErrInvalidReference means that a secret reference cannot be used safely.
	ErrInvalidReference = errors.New("secrets: invalid reference")
	// ErrReleased means that a lease or secret has already been destroyed.
	ErrReleased = errors.New("secrets: value released")
	// ErrClosed means that a backend or cache has been closed.
	ErrClosed = errors.New("secrets: backend closed")
)

// Backend resolves a configured reference to a caller-owned Lease.
//
// Implementations must not return a lease that aliases mutable backend or
// cache storage. That rule lets a cache evict and zero its copy without racing
// a request that is still using a credential.
type Backend interface {
	Get(context.Context, string) (*Lease, error)
}

// Secret owns a byte slice from which independent leases can be acquired.
// It is useful for long-lived backend and cache storage. Destroying a Secret
// prevents future acquisition, but does not affect leases already issued.
type Secret struct {
	mu        sync.RWMutex
	value     []byte
	destroyed bool
}

// NewSecret copies value. The caller remains responsible for its input copy.
func NewSecret(value []byte) *Secret {
	return &Secret{value: clone(value)}
}

// Acquire returns a lease containing an owned copy of the secret.
func (s *Secret) Acquire() (*Lease, error) {
	if s == nil {
		return nil, ErrReleased
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return nil, ErrReleased
	}
	return newOwnedLease(clone(s.value)), nil
}

// Destroy best-effort zeroes the Secret's storage. It is idempotent.
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.destroyed {
		zero(s.value)
		s.value = nil
		s.destroyed = true
	}
	s.mu.Unlock()
}

// Lease owns one credential copy. Bytes is valid only until Release and must
// not be mutated or retained. Release must not run concurrently with a use of
// the returned slice. Use provides a race-safe alternative when a lease may be
// released by another goroutine.
type Lease struct {
	mu       sync.RWMutex
	value    []byte
	released bool
}

// NewLease copies value into a new caller-owned lease.
func NewLease(value []byte) *Lease {
	return newOwnedLease(clone(value))
}

func newOwnedLease(value []byte) *Lease {
	return &Lease{value: value}
}

// Bytes returns the lease-owned byte slice. It does not allocate.
// See Lease's ownership rules before retaining the returned slice.
func (l *Lease) Bytes() []byte {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.released {
		return nil
	}
	return l.value
}

// Use calls fn with the lease-owned bytes while preventing a concurrent
// Release. The byte slice must not escape fn.
func (l *Lease) Use(fn func([]byte) error) error {
	if l == nil || fn == nil {
		return ErrReleased
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.released {
		return ErrReleased
	}
	return fn(l.value)
}

// Clone returns a new caller-owned copy. The caller should zero it after use.
func (l *Lease) Clone() ([]byte, error) {
	if l == nil {
		return nil, ErrReleased
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.released {
		return nil, ErrReleased
	}
	return clone(l.value), nil
}

// Release best-effort zeroes the lease. It is idempotent.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if !l.released {
		zero(l.value)
		l.value = nil
		l.released = true
	}
	l.mu.Unlock()
}

// Destroy is an alias for Release, allowing a lease to be used anywhere a
// destroyable credential is expected.
func (l *Lease) Destroy() { l.Release() }

func clone(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return append([]byte(nil), value...)
}

// zero is best effort: Go does not guarantee that every compiler/runtime copy
// can be erased, but clear plus KeepAlive prevents this explicit copy from
// becoming dead before the clearing write.
func zero(value []byte) {
	clear(value)
	runtime.KeepAlive(value)
}
