package secrets

import (
	"container/list"
	"context"
	"sync"
	"time"
)

const defaultCacheEntries = 128

// CacheOptions configures a bounded in-memory TTL cache. A non-positive TTL
// disables storage and makes Cache a pass-through. MaxEntries defaults to 128.
type CacheOptions struct {
	TTL        time.Duration
	MaxEntries int
	// Now is primarily for deterministic tests. time.Now is used when nil.
	Now func() time.Time
}

// Cache is a bounded LRU TTL cache. Cache entries and returned leases never
// share byte slices, so eviction can safely zero an entry during an in-flight
// request.
type Cache struct {
	backend Backend
	ttl     time.Duration
	max     int
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]*cacheEntry
	lru     list.List
	closed  bool
}

type cacheEntry struct {
	reference string
	secret    *Secret
	expires   time.Time
	element   *list.Element
}

// NewCache wraps backend. It never takes ownership of backend itself.
func NewCache(backend Backend, options CacheOptions) (*Cache, error) {
	if backend == nil {
		return nil, ErrClosed
	}
	maxEntries := options.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultCacheEntries
	}
	if maxEntries < 0 {
		return nil, ErrClosed
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{
		backend: backend,
		ttl:     options.TTL,
		max:     maxEntries,
		now:     now,
		entries: make(map[string]*cacheEntry),
	}, nil
}

// Get implements Backend.
func (c *Cache) Get(ctx context.Context, reference string) (*Lease, error) {
	if c == nil {
		return nil, ErrClosed
	}
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	now := c.now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if c.ttl <= 0 || c.max == 0 {
		c.mu.Unlock()
		return c.backend.Get(ctx, reference)
	}
	if entry, ok := c.entries[reference]; ok {
		if now.Before(entry.expires) {
			lease, err := entry.secret.Acquire()
			if err == nil {
				c.lru.MoveToFront(entry.element)
			}
			c.mu.Unlock()
			return lease, err
		}
		c.removeLocked(entry)
		c.mu.Unlock()
		entry.secret.Destroy()
	} else {
		c.mu.Unlock()
	}

	loaded, err := c.backend.Get(ctx, reference)
	if err != nil {
		return nil, err
	}
	value, err := loaded.Clone()
	loaded.Release()
	if err != nil {
		return nil, err
	}
	candidate := NewSecret(value)
	zero(value)

	var destroy []*Secret
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		candidate.Destroy()
		return nil, ErrClosed
	}
	now = c.now()
	// Another goroutine may have populated the entry while this one loaded it.
	if current, ok := c.entries[reference]; ok && now.Before(current.expires) {
		lease, acquireErr := current.secret.Acquire()
		if acquireErr == nil {
			c.lru.MoveToFront(current.element)
		}
		c.mu.Unlock()
		candidate.Destroy()
		return lease, acquireErr
	}
	if current, ok := c.entries[reference]; ok {
		c.removeLocked(current)
		destroy = append(destroy, current.secret)
	}
	entry := &cacheEntry{
		reference: reference,
		secret:    candidate,
		expires:   now.Add(c.ttl),
	}
	entry.element = c.lru.PushFront(entry)
	c.entries[reference] = entry
	for len(c.entries) > c.max {
		oldest := c.lru.Back().Value.(*cacheEntry)
		c.removeLocked(oldest)
		destroy = append(destroy, oldest.secret)
	}
	lease, acquireErr := candidate.Acquire()
	c.mu.Unlock()
	for _, secret := range destroy {
		secret.Destroy()
	}
	return lease, acquireErr
}

// Invalidate evicts and zeroes one cached value. Existing leases are
// independent and remain valid.
func (c *Cache) Invalidate(reference string) {
	if c == nil {
		return
	}
	var secret *Secret
	c.mu.Lock()
	if entry, ok := c.entries[reference]; ok {
		c.removeLocked(entry)
		secret = entry.secret
	}
	c.mu.Unlock()
	if secret != nil {
		secret.Destroy()
	}
}

// Len returns the number of currently stored entries, including entries whose
// TTL has elapsed but that have not yet been accessed or purged.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Purge evicts and zeroes all cached values without closing the cache.
func (c *Cache) Purge() {
	if c == nil {
		return
	}
	secrets := c.detachAll(false)
	for _, secret := range secrets {
		secret.Destroy()
	}
}

// Close prevents future Get calls and zeroes all cache-owned values. It does
// not close the wrapped backend.
func (c *Cache) Close() error {
	if c == nil {
		return nil
	}
	secrets := c.detachAll(true)
	for _, secret := range secrets {
		secret.Destroy()
	}
	return nil
}

func (c *Cache) removeLocked(entry *cacheEntry) {
	delete(c.entries, entry.reference)
	c.lru.Remove(entry.element)
}

func (c *Cache) detachAll(closeCache bool) []*Secret {
	c.mu.Lock()
	if closeCache {
		c.closed = true
	}
	secrets := make([]*Secret, 0, len(c.entries))
	for _, entry := range c.entries {
		secrets = append(secrets, entry.secret)
	}
	c.entries = make(map[string]*cacheEntry)
	c.lru.Init()
	c.mu.Unlock()
	return secrets
}
