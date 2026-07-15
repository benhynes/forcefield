package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSecretAndLeaseOwnIndependentCopies(t *testing.T) {
	input := []byte("top-secret")
	secret := NewSecret(input)
	input[0] = 'X'

	first, err := secret.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	second, err := secret.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	first.Bytes()[0] = 'T'
	if got := string(second.Bytes()); got != "top-secret" {
		t.Fatalf("leases alias each other: %q", got)
	}

	secret.Destroy()
	if got := string(first.Bytes()); got != "Top-secret" {
		t.Fatalf("destroying owner changed lease: %q", got)
	}
	if _, err := secret.Acquire(); !errors.Is(err, ErrReleased) {
		t.Fatalf("Acquire after Destroy error = %v", err)
	}
	first.Release()
	if first.Bytes() != nil {
		t.Fatal("released lease still exposes bytes")
	}
	first.Release() // idempotent
	second.Release()
}

func TestLeaseUseSerializesRelease(t *testing.T) {
	lease := NewLease([]byte("value"))
	started := make(chan struct{})
	unblock := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := lease.Use(func(value []byte) error {
			close(started)
			<-unblock
			if string(value) != "value" {
				t.Errorf("value changed during Use: %q", value)
			}
			return nil
		}); err != nil {
			t.Errorf("Use: %v", err)
		}
	}()
	<-started
	released := make(chan struct{})
	go func() {
		lease.Release()
		close(released)
	}()
	select {
	case <-released:
		t.Fatal("Release did not wait for Use")
	case <-time.After(10 * time.Millisecond):
	}
	close(unblock)
	<-done
	<-released
}

func TestFixedBackendCopiesAndCloses(t *testing.T) {
	value := []byte("fixed")
	backend := NewFixedBackend(value)
	value[0] = 'X'
	lease, err := backend.Get(context.Background(), "any")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got := string(lease.Bytes()); got != "fixed" {
		t.Fatalf("value = %q", got)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if got := string(lease.Bytes()); got != "fixed" {
		t.Fatalf("Close changed issued lease: %q", got)
	}
	if _, err := backend.Get(context.Background(), "any"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after Close error = %v", err)
	}
}

func TestEnvBackend(t *testing.T) {
	backend := NewEnvBackendWithLookup("FF_", func(name string) (string, bool) {
		if name == "FF_API_KEY" {
			return "environment-secret", true
		}
		return "", false
	})
	lease, err := backend.Get(context.Background(), "API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got := string(lease.Bytes()); got != "environment-secret" {
		t.Fatalf("value = %q", got)
	}
	if _, err := backend.Get(context.Background(), "MISSING"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing error = %v", err)
	}
	if _, err := backend.Get(context.Background(), "bad=name"); !errors.Is(err, ErrInvalidReference) {
		t.Fatalf("invalid name error = %v", err)
	}
}

type countingBackend struct {
	mu     sync.Mutex
	calls  map[string]int
	values map[string]string
}

func (b *countingBackend) Get(ctx context.Context, reference string) (*Lease, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls[reference]++
	value, ok := b.values[reference]
	if !ok {
		return nil, ErrNotFound
	}
	return NewLease([]byte(value)), nil
}

func (b *countingBackend) count(reference string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls[reference]
}

func TestCacheTTLBoundAndLeaseSurvivesEviction(t *testing.T) {
	now := time.Unix(100, 0)
	backend := &countingBackend{
		calls:  make(map[string]int),
		values: map[string]string{"a": "alpha", "b": "bravo", "c": "charlie"},
	}
	cache, err := NewCache(backend, CacheOptions{
		TTL:        time.Minute,
		MaxEntries: 2,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	leaseA, err := cache.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	defer leaseA.Release()
	leaseB, _ := cache.Get(context.Background(), "b")
	leaseB.Release()
	leaseC, _ := cache.Get(context.Background(), "c") // evicts a
	leaseC.Release()
	if cache.Len() != 2 {
		t.Fatalf("cache length = %d, want 2", cache.Len())
	}
	if got := string(leaseA.Bytes()); got != "alpha" {
		t.Fatalf("eviction mutated in-flight lease: %q", got)
	}
	loadedA, err := cache.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	loadedA.Release()
	if got := backend.count("a"); got != 2 {
		t.Fatalf("backend calls for evicted value = %d, want 2", got)
	}

	now = now.Add(2 * time.Minute)
	loadedA, err = cache.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	loadedA.Release()
	if got := backend.count("a"); got != 3 {
		t.Fatalf("backend calls after TTL = %d, want 3", got)
	}
}

func TestCacheConcurrentEvictionAndReads(t *testing.T) {
	backend := &countingBackend{
		calls:  make(map[string]int),
		values: map[string]string{"stable": "credential", "other": "different"},
	}
	cache, err := NewCache(backend, CacheOptions{TTL: time.Minute, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	const iterations = 250
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				lease, err := cache.Get(context.Background(), "stable")
				if err != nil {
					failures.Add(1)
					continue
				}
				if string(lease.Bytes()) != "credential" {
					failures.Add(1)
				}
				lease.Release()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < iterations; j++ {
			lease, err := cache.Get(context.Background(), "other")
			if err == nil {
				lease.Release()
			}
			cache.Invalidate("stable")
		}
	}()
	wg.Wait()
	if got := failures.Load(); got != 0 {
		t.Fatalf("observed %d corrupt/error leases", got)
	}
}

func TestCacheDisabledPassesThroughAndCloseIsFinal(t *testing.T) {
	backend := &countingBackend{calls: make(map[string]int), values: map[string]string{"x": "y"}}
	cache, err := NewCache(backend, CacheOptions{TTL: 0})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		lease, err := cache.Get(context.Background(), "x")
		if err != nil {
			t.Fatal(err)
		}
		lease.Release()
	}
	if got := backend.count("x"); got != 2 {
		t.Fatalf("backend calls = %d", got)
	}
	_ = cache.Close()
	if _, err := cache.Get(context.Background(), "x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after close error = %v", err)
	}
}

func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("FF_EXEC_HELPER") != "1" {
		return
	}
	reference := os.Args[len(os.Args)-1]
	switch reference {
	case "success":
		fmt.Print("exec-secret\n")
	case "two-newlines":
		fmt.Print("exec-secret\n\n")
	case "crlf":
		fmt.Print("exec-secret\r\n")
	case "overflow":
		fmt.Print("123456789")
	case "fail-secret":
		fmt.Print("do-not-leak-secret")
		fmt.Fprint(os.Stderr, "do-not-leak-stderr")
		os.Exit(17)
	case "environment":
		if os.Getenv("FF_PARENT_SENTINEL") != "" {
			fmt.Print("inherited-environment")
			os.Exit(18)
		}
		fmt.Print("minimal")
	case "timeout":
		time.Sleep(10 * time.Second)
	default:
		os.Exit(19)
	}
	os.Exit(0)
}

func newHelperBackend(t *testing.T, timeout time.Duration, maxOutput int) *ExecBackend {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewExecBackend(path, ExecOptions{
		Args:      []string{"-test.run=^TestExecHelperProcess$", "--"},
		ExtraEnv:  []string{"FF_EXEC_HELPER=1", "GORACE=atexit_sleep_ms=0"},
		Timeout:   timeout,
		MaxOutput: maxOutput,
	})
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func TestExecBackendSuccessMinimalEnvAndNewline(t *testing.T) {
	backend := newHelperBackend(t, time.Second, 64)
	for reference, want := range map[string]string{
		"success":      "exec-secret",
		"two-newlines": "exec-secret\n",
		"crlf":         "exec-secret",
	} {
		t.Run(reference, func(t *testing.T) {
			lease, err := backend.Get(context.Background(), reference)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			if got := string(lease.Bytes()); got != want {
				t.Fatalf("value = %q, want %q", got, want)
			}
		})
	}
	t.Setenv("FF_PARENT_SENTINEL", "must-not-be-inherited")
	lease, err := backend.Get(context.Background(), "environment")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if got := string(lease.Bytes()); got != "minimal" {
		t.Fatalf("helper inherited parent environment: %q", got)
	}
}

func TestExecBackendOpaqueErrorsAndLimits(t *testing.T) {
	backend := newHelperBackend(t, time.Second, 4)
	if _, err := backend.Get(context.Background(), "overflow"); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("overflow error = %v", err)
	}
	backend = newHelperBackend(t, time.Second, 64)
	_, err := backend.Get(context.Background(), "fail-secret")
	if !errors.Is(err, ErrExecFailed) {
		t.Fatalf("failure error = %v", err)
	}
	for _, forbidden := range []string{"do-not-leak-secret", "do-not-leak-stderr", "fail-secret"} {
		if bytes.Contains([]byte(err.Error()), []byte(forbidden)) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
}

func TestExecBackendTimeoutAndAbsolutePath(t *testing.T) {
	if _, err := NewExecBackend("agent-secret", ExecOptions{}); !errors.Is(err, ErrExecFailed) {
		t.Fatalf("relative executable error = %v", err)
	}
	backend := newHelperBackend(t, 20*time.Millisecond, 64)
	started := time.Now()
	if _, err := backend.Get(context.Background(), "timeout"); !errors.Is(err, ErrExecTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}
