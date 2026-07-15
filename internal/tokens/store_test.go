package tokens

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, time.July, 15, 12, 0, 0, 123456789, time.FixedZone("test", 3600))

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func testGrant() Grant {
	return Grant{
		Service:         "github-api",
		CredentialRef:   "vault://github/agent-token",
		PolicyRevision:  "sha256:policy-v1",
		BindingRevision: "sha256:binding-v1",
		Limits: Limits{
			RequestsPerSecond: 10,
			Burst:             20,
			RequestBudget:     100,
			ByteBudget:        1_000_000,
			MaxRequestBytes:   64_000,
		},
	}
}

func openTestStore(t *testing.T, opts Options) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	store, err := Open(path, opts)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return store, path
}

func mintRoot(t *testing.T, store *Store, now time.Time, mutate func(*MintRequest)) IssuedToken {
	t.Helper()
	req := MintRequest{
		Workload:        "vm://runner/root",
		Audience:        "forcefield-data-plane",
		ExpiresAt:       now.Add(time.Hour),
		Grants:          []Grant{testGrant()},
		AllowDelegation: true,
	}
	if mutate != nil {
		mutate(&req)
	}
	issued, err := store.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	return issued
}

func delegate(t *testing.T, store *Store, parent IssuedToken, caller, child string, expiresAt time.Time, mutate func(*DelegateRequest)) IssuedToken {
	t.Helper()
	req := DelegateRequest{
		CallerWorkload:  caller,
		Audience:        parent.Claims.Audience,
		Workload:        child,
		ExpiresAt:       expiresAt,
		Grants:          cloneGrants(parent.Claims.Grants),
		AllowDelegation: true,
	}
	if mutate != nil {
		mutate(&req)
	}
	issued, err := store.Delegate(context.Background(), parent.Bearer, req)
	if err != nil {
		t.Fatalf("Delegate() error = %v", err)
	}
	return issued
}

func TestContainsBearerOnlyMatchesCanonicalEmbeddedToken(t *testing.T) {
	bearer := BearerPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, tokenBytes))
	if len(bearer) != BearerLength || !ContainsBearer("prefix "+bearer+" suffix") {
		t.Fatal("embedded canonical bearer was not detected")
	}
	for _, value := range []string{"ff_", "documentation mentions ff_tokens", bearer[:len(bearer)-1] + "!", strings.Repeat("x", 100)} {
		if ContainsBearer(value) {
			t.Fatalf("non-bearer %q was detected", value)
		}
	}
}

func TestMintValidateAndPersistHashedOnly(t *testing.T) {
	clk := &clock{now: testNow}
	store, path := openTestStore(t, Options{Now: clk.Now})

	initialInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := initialInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("new store mode = %04o, want 0600", got)
	}

	issued := mintRoot(t, store, clk.Now(), nil)
	if !strings.HasPrefix(issued.Bearer, BearerPrefix) {
		t.Fatalf("bearer %q does not have prefix %q", issued.Bearer, BearerPrefix)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(issued.Bearer, BearerPrefix))
	if err != nil || len(decoded) != tokenBytes {
		t.Fatalf("bearer suffix decoded to %d bytes, error %v", len(decoded), err)
	}
	if issued.Claims.TokenID != issued.Claims.RootTokenID || issued.Claims.ParentTokenID != "" || issued.Claims.Depth != 0 {
		t.Fatalf("root lineage = %#v", issued.Claims)
	}
	if issued.Claims.IssuedAt.Location() != time.UTC || issued.Claims.ExpiresAt.Location() != time.UTC {
		t.Fatalf("claims times were not canonicalized to UTC: %#v", issued.Claims)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte(issued.Bearer)) {
		t.Fatal("persisted state contains raw bearer material")
	}
	digest := sha256.Sum256([]byte(issued.Bearer))
	if !bytes.Contains(contents, []byte(hex.EncodeToString(digest[:]))) {
		t.Fatal("persisted state does not contain token digest")
	}

	wantBinding := ValidationRequest{Workload: "vm://runner/root", Audience: "forcefield-data-plane"}
	claims, err := store.Validate(context.Background(), issued.Bearer, wantBinding)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if claims.TokenID != issued.Claims.TokenID || len(claims.Grants) != 1 {
		t.Fatalf("Validate() claims = %#v", claims)
	}
	if len(claims.LimitChain) != 1 || claims.LimitChain[0].TokenID != claims.TokenID || claims.LimitChain[0].Grants[0] != testGrant() {
		t.Fatalf("root limit chain = %#v", claims.LimitChain)
	}

	// Returned slices are detached from both the store and each other.
	issued.Claims.Grants[0].Service = "mutated-issued-claims"
	claims.Grants[0].CredentialRef = "mutated-validation-claims"
	claims.LimitChain[0].Grants[0].PolicyRevision = "mutated-limit-chain"
	again, err := store.Validate(context.Background(), issued.Bearer, wantBinding)
	if err != nil {
		t.Fatal(err)
	}
	if again.Grants[0] != testGrant() {
		t.Fatalf("mutating returned claims changed store grant: %#v", again.Grants[0])
	}
	if again.LimitChain[0].Grants[0] != testGrant() {
		t.Fatalf("mutating returned limit chain changed store grant: %#v", again.LimitChain)
	}

	invalidCases := []struct {
		name    string
		bearer  string
		binding ValidationRequest
	}{
		{"wrong workload", issued.Bearer, ValidationRequest{Workload: "vm://runner/other", Audience: wantBinding.Audience}},
		{"wrong audience", issued.Bearer, ValidationRequest{Workload: wantBinding.Workload, Audience: "admin"}},
		{"missing binding", issued.Bearer, ValidationRequest{}},
		{"unknown token", BearerPrefix + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, tokenBytes)), wantBinding},
		{"malformed token", "ff_not-a-token", wantBinding},
		{"hash is not bearer", issued.Claims.TokenID, wantBinding},
	}
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			claims, err := store.Validate(context.Background(), test.bearer, test.binding)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Validate() error = %v, want ErrInvalidToken", err)
			}
			if claims.TokenID != "" || claims.Workload != "" || len(claims.Grants) != 0 {
				t.Fatalf("invalid token returned claims %#v", claims)
			}
		})
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := Open(path, Options{Now: clk.Now})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Validate(context.Background(), issued.Bearer, wantBinding); err != nil {
		t.Fatalf("reopened Validate() error = %v", err)
	}
	temps, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".tokens.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("atomic writes left temporary files: %v", temps)
	}
}

func TestMandatoryExpiryAndContext(t *testing.T) {
	clk := &clock{now: testNow}
	store, _ := openTestStore(t, Options{Now: clk.Now})
	request := MintRequest{
		Workload:  "vm://runner/root",
		Audience:  "data-plane",
		ExpiresAt: clk.Now(),
		Grants:    []Grant{testGrant()},
	}
	if _, err := store.Mint(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Mint(expiry=now) error = %v, want ErrInvalidRequest", err)
	}
	request.ExpiresAt = time.Time{}
	if _, err := store.Mint(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Mint(zero expiry) error = %v, want ErrInvalidRequest", err)
	}

	request.ExpiresAt = clk.Now().Add(time.Minute)
	issued, err := store.Mint(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if _, err := store.Validate(context.Background(), issued.Bearer, ValidationRequest{Workload: request.Workload, Audience: request.Audience}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Validate(at exact expiry) error = %v, want ErrInvalidToken", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Validate(canceled, issued.Bearer, ValidationRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Validate(canceled) error = %v", err)
	}
	if _, err := store.Mint(nil, request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Mint(nil context) error = %v", err)
	}
}

func TestDelegationNarrowsAuthority(t *testing.T) {
	clk := &clock{now: testNow}
	store, _ := openTestStore(t, Options{Now: clk.Now})
	unlimited := Grant{
		Service:         "metrics",
		CredentialRef:   "vault://metrics/key",
		PolicyRevision:  "policy-v3",
		BindingRevision: "sha256:metrics-binding-v1",
	}
	root := mintRoot(t, store, clk.Now(), func(req *MintRequest) {
		req.Grants = append(req.Grants, unlimited)
	})

	childGrant := testGrant()
	childGrant.Limits = Limits{
		RequestsPerSecond: 5,
		Burst:             10,
		RequestBudget:     50,
		ByteBudget:        500_000,
		MaxRequestBytes:   32_000,
	}
	child := delegate(t, store, root, root.Claims.Workload, "vm://runner/child", clk.Now().Add(30*time.Minute), func(req *DelegateRequest) {
		req.Grants = []Grant{childGrant}
		req.AllowDelegation = false
	})
	if child.Claims.ParentTokenID != root.Claims.TokenID || child.Claims.RootTokenID != root.Claims.TokenID || child.Claims.Depth != 1 {
		t.Fatalf("child lineage = %#v", child.Claims)
	}
	if len(child.Claims.LimitChain) != 2 || child.Claims.LimitChain[0].TokenID != root.Claims.TokenID || child.Claims.LimitChain[1].TokenID != child.Claims.TokenID {
		t.Fatalf("child limit chain = %#v", child.Claims.LimitChain)
	}
	if child.Claims.AllowDelegation {
		t.Fatal("child unexpectedly permits delegation")
	}
	if _, err := store.Validate(context.Background(), child.Bearer, ValidationRequest{Workload: child.Claims.Workload, Audience: child.Claims.Audience}); err != nil {
		t.Fatalf("child Validate() error = %v", err)
	}

	// An unlimited parent may be narrowed to a finite value.
	_ = delegate(t, store, root, root.Claims.Workload, "vm://runner/metrics", clk.Now().Add(20*time.Minute), func(req *DelegateRequest) {
		finite := unlimited
		finite.Limits.RequestBudget = 10
		req.Grants = []Grant{finite}
		req.AllowDelegation = false
	})

	base := DelegateRequest{
		CallerWorkload: root.Claims.Workload,
		Audience:       root.Claims.Audience,
		Workload:       "vm://runner/rejected",
		ExpiresAt:      clk.Now().Add(10 * time.Minute),
		Grants:         []Grant{childGrant},
	}
	tests := []struct {
		name string
		edit func(*DelegateRequest)
		want error
	}{
		{"wrong caller binding", func(req *DelegateRequest) { req.CallerWorkload = "vm://runner/thief" }, ErrInvalidToken},
		{"wrong parent audience", func(req *DelegateRequest) { req.Audience = "other-plane" }, ErrInvalidToken},
		{"expiry after parent", func(req *DelegateRequest) { req.ExpiresAt = root.Claims.ExpiresAt.Add(time.Nanosecond) }, ErrExpiryBroadening},
		{"changed service", func(req *DelegateRequest) { req.Grants[0].Service = "gitlab-api" }, ErrGrantBroadening},
		{"changed credential", func(req *DelegateRequest) { req.Grants[0].CredentialRef = "vault://other" }, ErrGrantBroadening},
		{"changed policy", func(req *DelegateRequest) { req.Grants[0].PolicyRevision = "policy-v2" }, ErrGrantBroadening},
		{"changed binding", func(req *DelegateRequest) { req.Grants[0].BindingRevision = "sha256:binding-v2" }, ErrGrantBroadening},
		{"higher rate", func(req *DelegateRequest) { req.Grants[0].Limits.RequestsPerSecond = 11 }, ErrGrantBroadening},
		{"finite rate to unlimited", func(req *DelegateRequest) { req.Grants[0].Limits.RequestsPerSecond = 0; req.Grants[0].Limits.Burst = 0 }, ErrGrantBroadening},
		{"higher burst", func(req *DelegateRequest) { req.Grants[0].Limits.Burst = 21 }, ErrGrantBroadening},
		{"higher request budget", func(req *DelegateRequest) { req.Grants[0].Limits.RequestBudget = 101 }, ErrGrantBroadening},
		{"higher byte budget", func(req *DelegateRequest) { req.Grants[0].Limits.ByteBudget = 1_000_001 }, ErrGrantBroadening},
		{"higher body ceiling", func(req *DelegateRequest) { req.Grants[0].Limits.MaxRequestBytes = 64_001 }, ErrGrantBroadening},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := base
			req.Grants = cloneGrants(base.Grants)
			test.edit(&req)
			if _, err := store.Delegate(context.Background(), root.Bearer, req); !errors.Is(err, test.want) {
				t.Fatalf("Delegate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDelegationCannotBroadenImplicitBurst(t *testing.T) {
	clk := &clock{now: testNow}
	store, _ := openTestStore(t, Options{Now: clk.Now})
	root := mintRoot(t, store, clk.Now(), func(req *MintRequest) {
		req.Grants[0].Limits.RequestsPerSecond = 10
		req.Grants[0].Limits.Burst = 0 // Runtime semantics: an implicit burst of one.
	})
	childGrant := root.Claims.Grants[0]
	childGrant.Limits.RequestsPerSecond = 5
	childGrant.Limits.Burst = 2
	_, err := store.Delegate(context.Background(), root.Bearer, DelegateRequest{
		CallerWorkload: root.Claims.Workload, Audience: root.Claims.Audience,
		Workload: "vm://runner/child", ExpiresAt: clk.Now().Add(time.Minute),
		Grants: []Grant{childGrant},
	})
	if !errors.Is(err, ErrGrantBroadening) {
		t.Fatalf("Delegate() error = %v, want ErrGrantBroadening", err)
	}
}

func TestDelegationRequiresPermission(t *testing.T) {
	clk := &clock{now: testNow}
	store, _ := openTestStore(t, Options{Now: clk.Now})
	root := mintRoot(t, store, clk.Now(), func(req *MintRequest) { req.AllowDelegation = false })
	_, err := store.Delegate(context.Background(), root.Bearer, DelegateRequest{
		CallerWorkload: root.Claims.Workload,
		Audience:       root.Claims.Audience,
		Workload:       "vm://runner/child",
		ExpiresAt:      clk.Now().Add(time.Minute),
		Grants:         cloneGrants(root.Claims.Grants),
	})
	if !errors.Is(err, ErrDelegationNotAllowed) {
		t.Fatalf("Delegate() error = %v, want ErrDelegationNotAllowed", err)
	}
}

func TestDelegationBounds(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, _ := openTestStore(t, Options{Now: clk.Now, MaxDelegationDepth: 2, MaxChildrenPerToken: 10, MaxTokensPerRoot: 10})
		root := mintRoot(t, store, clk.Now(), nil)
		child := delegate(t, store, root, root.Claims.Workload, "vm://child", clk.Now().Add(40*time.Minute), nil)
		grandchild := delegate(t, store, child, child.Claims.Workload, "vm://grandchild", clk.Now().Add(30*time.Minute), nil)
		_, err := store.Delegate(context.Background(), grandchild.Bearer, DelegateRequest{
			CallerWorkload: grandchild.Claims.Workload,
			Audience:       grandchild.Claims.Audience,
			Workload:       "vm://great-grandchild",
			ExpiresAt:      clk.Now().Add(20 * time.Minute),
			Grants:         cloneGrants(grandchild.Claims.Grants),
		})
		if !errors.Is(err, ErrDelegationDepth) {
			t.Fatalf("Delegate() error = %v, want ErrDelegationDepth", err)
		}
	})

	t.Run("direct children", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, _ := openTestStore(t, Options{Now: clk.Now, MaxDelegationDepth: 3, MaxChildrenPerToken: 2, MaxTokensPerRoot: 10})
		root := mintRoot(t, store, clk.Now(), nil)
		for i := range 2 {
			delegate(t, store, root, root.Claims.Workload, fmt.Sprintf("vm://child/%d", i), clk.Now().Add(30*time.Minute), nil)
		}
		_, err := store.Delegate(context.Background(), root.Bearer, DelegateRequest{
			CallerWorkload: root.Claims.Workload,
			Audience:       root.Claims.Audience,
			Workload:       "vm://child/overflow",
			ExpiresAt:      clk.Now().Add(30 * time.Minute),
			Grants:         cloneGrants(root.Claims.Grants),
		})
		if !errors.Is(err, ErrChildLimit) {
			t.Fatalf("Delegate() error = %v, want ErrChildLimit", err)
		}
	})

	t.Run("root count", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, _ := openTestStore(t, Options{Now: clk.Now, MaxDelegationDepth: 3, MaxChildrenPerToken: 10, MaxTokensPerRoot: 3})
		root := mintRoot(t, store, clk.Now(), nil)
		child := delegate(t, store, root, root.Claims.Workload, "vm://child", clk.Now().Add(30*time.Minute), nil)
		_ = delegate(t, store, child, child.Claims.Workload, "vm://grandchild", clk.Now().Add(20*time.Minute), nil)
		_, err := store.Delegate(context.Background(), root.Bearer, DelegateRequest{
			CallerWorkload: root.Claims.Workload,
			Audience:       root.Claims.Audience,
			Workload:       "vm://overflow",
			ExpiresAt:      clk.Now().Add(10 * time.Minute),
			Grants:         cloneGrants(root.Claims.Grants),
		})
		if !errors.Is(err, ErrRootTokenLimit) {
			t.Fatalf("Delegate() error = %v, want ErrRootTokenLimit", err)
		}
	})
}

func TestCascadeRevocation(t *testing.T) {
	clk := &clock{now: testNow}
	store, path := openTestStore(t, Options{Now: clk.Now})
	root := mintRoot(t, store, clk.Now(), nil)
	child := delegate(t, store, root, root.Claims.Workload, "vm://child", clk.Now().Add(40*time.Minute), nil)
	grandchild := delegate(t, store, child, child.Claims.Workload, "vm://grandchild", clk.Now().Add(30*time.Minute), nil)
	sibling := delegate(t, store, root, root.Claims.Workload, "vm://sibling", clk.Now().Add(40*time.Minute), nil)

	if err := store.Revoke(context.Background(), child.Bearer); err != nil {
		t.Fatalf("Revoke(child) error = %v", err)
	}
	for _, token := range []IssuedToken{child, grandchild} {
		if _, err := store.Validate(context.Background(), token.Bearer, ValidationRequest{Workload: token.Claims.Workload, Audience: token.Claims.Audience}); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("revoked token %s validation error = %v", token.Claims.TokenID, err)
		}
	}
	for _, token := range []IssuedToken{root, sibling} {
		if _, err := store.Validate(context.Background(), token.Bearer, ValidationRequest{Workload: token.Claims.Workload, Audience: token.Claims.Audience}); err != nil {
			t.Fatalf("unrelated token %s validation error = %v", token.Claims.TokenID, err)
		}
	}
	if err := store.Revoke(context.Background(), child.Bearer); err != nil {
		t.Fatalf("idempotent Revoke() error = %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := Open(path, Options{Now: clk.Now})
	if err != nil {
		t.Fatalf("reopen error = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Validate(context.Background(), grandchild.Bearer, ValidationRequest{Workload: grandchild.Claims.Workload, Audience: grandchild.Claims.Audience}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reopened revoked grandchild error = %v", err)
	}
	if err := reopened.RevokeTokenID(context.Background(), root.Claims.TokenID); err != nil {
		t.Fatalf("RevokeTokenID(root) error = %v", err)
	}
	for _, token := range []IssuedToken{root, sibling} {
		if _, err := reopened.Validate(context.Background(), token.Bearer, ValidationRequest{Workload: token.Claims.Workload, Audience: token.Claims.Audience}); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("root cascade token %s error = %v", token.Claims.TokenID, err)
		}
	}
	if err := reopened.RevokeTokenID(context.Background(), strings.Repeat("0", sha256.Size*2)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("RevokeTokenID(unknown) error = %v", err)
	}
}

func TestTokenGenerationCollisionIsBounded(t *testing.T) {
	clk := &clock{now: testNow}
	constantEntropy := bytes.NewReader(bytes.Repeat([]byte{0}, tokenBytes*9))
	store, _ := openTestStore(t, Options{Now: clk.Now, Rand: constantEntropy})
	_ = mintRoot(t, store, clk.Now(), nil)
	_, err := store.Mint(context.Background(), MintRequest{
		Workload:  "vm://second",
		Audience:  "data-plane",
		ExpiresAt: clk.Now().Add(time.Hour),
		Grants:    []Grant{testGrant()},
	})
	if !errors.Is(err, ErrEntropy) {
		t.Fatalf("Mint(colliding entropy) error = %v, want ErrEntropy", err)
	}
}

func TestConcurrentDelegationAndValidation(t *testing.T) {
	clk := &clock{now: testNow}
	store, _ := openTestStore(t, Options{
		Now:                 clk.Now,
		MaxDelegationDepth:  2,
		MaxChildrenPerToken: 64,
		MaxTokensPerRoot:    65,
		MaxGrantsPerToken:   4,
	})
	root := mintRoot(t, store, clk.Now(), nil)

	const children = 24
	issued := make(chan IssuedToken, children)
	errorsChannel := make(chan error, children)
	var group sync.WaitGroup
	for i := range children {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			child, err := store.Delegate(context.Background(), root.Bearer, DelegateRequest{
				CallerWorkload: root.Claims.Workload,
				Audience:       root.Claims.Audience,
				Workload:       fmt.Sprintf("vm://concurrent/%d", i),
				ExpiresAt:      clk.Now().Add(30 * time.Minute),
				Grants:         cloneGrants(root.Claims.Grants),
			})
			if err != nil {
				errorsChannel <- err
				return
			}
			issued <- child
		}(i)
	}
	group.Wait()
	close(issued)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent Delegate() error = %v", err)
	}

	var validators sync.WaitGroup
	for child := range issued {
		child := child
		validators.Add(1)
		go func() {
			defer validators.Done()
			if _, err := store.Validate(context.Background(), child.Bearer, ValidationRequest{Workload: child.Claims.Workload, Audience: child.Claims.Audience}); err != nil {
				t.Errorf("concurrent Validate() error = %v", err)
			}
		}()
	}
	validators.Wait()
}
