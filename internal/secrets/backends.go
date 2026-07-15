package secrets

import (
	"context"
	"os"
	"strings"
	"sync"
)

// FixedBackend returns an independent lease for one fixed value. It is useful
// for tests and deliberately ignores the reference after validating it.
type FixedBackend struct {
	mu     sync.RWMutex
	secret *Secret
	closed bool
}

// NewFixedBackend copies value into backend-owned storage.
func NewFixedBackend(value []byte) *FixedBackend {
	return &FixedBackend{secret: NewSecret(value)}
}

// Get implements Backend.
func (b *FixedBackend) Get(ctx context.Context, reference string) (*Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	if b == nil {
		return nil, ErrClosed
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return nil, ErrClosed
	}
	return b.secret.Acquire()
}

// Close zeroes the backend-owned value. Existing leases remain valid.
func (b *FixedBackend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if !b.closed {
		b.secret.Destroy()
		b.closed = true
	}
	b.mu.Unlock()
	return nil
}

// EnvBackend resolves a reference from the process environment. Its intended
// use is testing and local development; production deployments should use a
// backend backed by an OS credential store.
type EnvBackend struct {
	prefix string
	lookup func(string) (string, bool)
}

// NewEnvBackend reads variables named prefix+reference with os.LookupEnv.
func NewEnvBackend(prefix string) *EnvBackend {
	return NewEnvBackendWithLookup(prefix, os.LookupEnv)
}

// NewEnvBackendWithLookup permits a non-process lookup function in tests.
func NewEnvBackendWithLookup(prefix string, lookup func(string) (string, bool)) *EnvBackend {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}
	return &EnvBackend{prefix: prefix, lookup: lookup}
}

// Get implements Backend.
func (b *EnvBackend) Get(ctx context.Context, reference string) (*Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	if b == nil || b.lookup == nil {
		return nil, ErrClosed
	}
	name := b.prefix + reference
	if strings.IndexByte(name, '=') >= 0 || strings.IndexByte(name, 0) >= 0 {
		return nil, ErrInvalidReference
	}
	value, ok := b.lookup(name)
	if !ok {
		return nil, ErrNotFound
	}
	return NewLease([]byte(value)), nil
}

func validateReference(reference string) error {
	if reference == "" || strings.IndexByte(reference, 0) >= 0 {
		return ErrInvalidReference
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
