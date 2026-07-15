package audit

import (
	"bytes"
	"errors"
	"runtime"
	"sort"
	"sync"
)

var ErrEmptyRedaction = errors.New("audit: empty redaction value")

var defaultReplacement = []byte("[REDACTED]")

// Redactor replaces registered exact byte values. It intentionally performs
// no prefix or entropy guessing: callers register the actual credential while
// they own it, then use Contains or Redact as a response-reflection guard.
type Redactor struct {
	mu          sync.RWMutex
	replacement []byte
	entries     []*redactionEntry // longest first
	nextID      uint64
}

type redactionEntry struct {
	id    uint64
	value []byte
	refs  int
}

// Registration keeps one exact value active until Close. It is safe and
// idempotent to close from any goroutine.
type Registration struct {
	once sync.Once
	r    *Redactor
	id   uint64
}

// NewRedactor constructs a redactor. A nil replacement uses "[REDACTED]";
// a non-nil empty replacement removes matched values.
func NewRedactor(replacement []byte) *Redactor {
	if replacement == nil {
		replacement = defaultReplacement
	}
	return &Redactor{replacement: append([]byte(nil), replacement...)}
}

// Register copies value and returns a lifetime handle. Registering the same
// value more than once reference-counts one stored copy.
func (r *Redactor) Register(value []byte) (*Registration, error) {
	if len(value) == 0 {
		return nil, ErrEmptyRedaction
	}
	if r == nil {
		return nil, ErrClosed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range r.entries {
		if bytes.Equal(entry.value, value) {
			entry.refs++
			return &Registration{r: r, id: entry.id}, nil
		}
	}
	r.nextID++
	entry := &redactionEntry{
		id:    r.nextID,
		value: append([]byte(nil), value...),
		refs:  1,
	}
	r.entries = append(r.entries, entry)
	sort.SliceStable(r.entries, func(i, j int) bool {
		return len(r.entries[i].value) > len(r.entries[j].value)
	})
	return &Registration{r: r, id: entry.id}, nil
}

// Close unregisters one reference and zeroes storage when the final
// registration is released.
func (registration *Registration) Close() error {
	if registration == nil {
		return nil
	}
	registration.once.Do(func() {
		registration.r.unregister(registration.id)
	})
	return nil
}

func (r *Redactor) unregister(id uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for index, entry := range r.entries {
		if entry.id != id {
			continue
		}
		entry.refs--
		if entry.refs == 0 {
			zeroBytes(entry.value)
			copy(r.entries[index:], r.entries[index+1:])
			r.entries[len(r.entries)-1] = nil
			r.entries = r.entries[:len(r.entries)-1]
		}
		return
	}
}

// Contains reports whether input includes any registered exact value.
func (r *Redactor) Contains(input []byte) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, entry := range r.entries {
		if bytes.Contains(input, entry.value) {
			return true
		}
	}
	return false
}

// Redact returns an owned copy of input and whether any replacement occurred.
// The input is never modified. Intermediate owned buffers are zeroed when a
// later replacement supersedes them.
func (r *Redactor) Redact(input []byte) ([]byte, bool) {
	result := append([]byte(nil), input...)
	if r == nil {
		return result, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	changed := false
	for _, entry := range r.entries {
		if !bytes.Contains(result, entry.value) {
			continue
		}
		next := bytes.ReplaceAll(result, entry.value, r.replacement)
		zeroBytes(result)
		result = next
		changed = true
	}
	return result, changed
}

// RedactString is a convenience wrapper for textual headers and bounded
// response bodies.
func (r *Redactor) RedactString(input string) (string, bool) {
	inputBytes := []byte(input)
	redacted, changed := r.Redact(inputBytes)
	zeroBytes(inputBytes)
	result := string(redacted)
	zeroBytes(redacted)
	return result, changed
}

// Clear unregisters and best-effort zeroes every value and the replacement.
// The Redactor remains usable; subsequent redactions remove matching values
// unless a new Redactor is constructed with another replacement.
func (r *Redactor) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	for _, entry := range r.entries {
		zeroBytes(entry.value)
	}
	clear(r.entries)
	r.entries = nil
	zeroBytes(r.replacement)
	r.replacement = nil
	r.mu.Unlock()
}

func zeroBytes(value []byte) {
	clear(value)
	runtime.KeepAlive(value)
}
