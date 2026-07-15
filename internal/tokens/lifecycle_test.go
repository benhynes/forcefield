package tokens

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreLockHeldUntilIdempotentClose(t *testing.T) {
	store, path := openTestStore(t, Options{})
	lockInfo, err := os.Lstat(path + ".lock")
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v, want 0600 regular file", lockInfo.Mode())
	}

	second, err := Open(path, Options{})
	if second != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second Open() = (%v, %v), want nil ErrStoreLocked", second, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := store.Validate(context.Background(), "", ValidationRequest{}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Validate(after Close) error = %v, want ErrStoreClosed", err)
	}

	reopened, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("Open(after Close) error = %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("reopened Close() error = %v", err)
	}
}

func TestOpenRejectsInsecureLockPath(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.lock")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "tokens.json")
		if err := os.Symlink(target, path+".lock"); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{}); !errors.Is(err, ErrSymlink) {
			t.Fatalf("Open() error = %v, want ErrSymlink", err)
		}
	})

	t.Run("permissions", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "tokens.json")
		if err := os.WriteFile(path+".lock", nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{}); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("Open() error = %v, want ErrInsecurePermissions", err)
		}
	})
}

func TestStoreLockIsCrossProcess(t *testing.T) {
	if os.Getenv("FF_TOKEN_LOCK_HELPER") == "1" {
		store, err := Open(os.Getenv("FF_TOKEN_LOCK_PATH"), Options{})
		if store != nil {
			_ = store.Close()
		}
		if !errors.Is(err, ErrStoreLocked) {
			t.Fatalf("helper Open() error = %v, want ErrStoreLocked", err)
		}
		return
	}

	store, path := openTestStore(t, Options{})
	command := exec.Command(os.Args[0], "-test.run=^TestStoreLockIsCrossProcess$")
	command.Env = append(os.Environ(), "FF_TOKEN_LOCK_HELPER=1", "FF_TOKEN_LOCK_PATH="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("lock helper failed: %v\n%s", err, output)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFailureReleasesStoreLock(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "tokens.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{}); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("Open(corrupt) error = %v, want ErrCorruptStore", err)
	}
	if err := os.WriteFile(path, []byte("{\"version\":1,\"records\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("Open(after failed Open) error = %v", err)
	}
	defer store.Close()
}

func TestExpiredAndRevokedChildrenReleaseActiveBounds(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, _ := openTestStore(t, Options{
			Now: clk.Now, MaxChildrenPerToken: 1, MaxTokensPerRoot: 2,
		})
		root := mintRoot(t, store, clk.Now(), nil)
		expired := delegate(t, store, root, root.Claims.Workload, "vm://expired", clk.Now().Add(time.Minute), nil)
		clk.Advance(time.Minute)
		replacement := delegate(t, store, root, root.Claims.Workload, "vm://replacement", clk.Now().Add(30*time.Minute), nil)

		if _, exists := sRecordByID(store, expired.Claims.TokenID); exists {
			t.Fatal("expired child was not pruned before delegation")
		}
		if _, err := store.Validate(context.Background(), replacement.Bearer, ValidationRequest{
			Workload: replacement.Claims.Workload, Audience: replacement.Claims.Audience,
		}); err != nil {
			t.Fatalf("replacement Validate() error = %v", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, _ := openTestStore(t, Options{
			Now: clk.Now, MaxChildrenPerToken: 1, MaxTokensPerRoot: 2,
		})
		root := mintRoot(t, store, clk.Now(), nil)
		revoked := delegate(t, store, root, root.Claims.Workload, "vm://revoked", clk.Now().Add(30*time.Minute), nil)
		if err := store.Revoke(context.Background(), revoked.Bearer); err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		_ = delegate(t, store, root, root.Claims.Workload, "vm://replacement", clk.Now().Add(30*time.Minute), nil)
		if _, exists := sRecordByID(store, revoked.Claims.TokenID); exists {
			t.Fatal("revoked child was not pruned before delegation")
		}
	})
}

func TestOpenDurablyPrunesInactiveSubtrees(t *testing.T) {
	clk := &clock{now: testNow}
	store, path := openTestStore(t, Options{Now: clk.Now})
	root := mintRoot(t, store, clk.Now(), nil)
	expiring := delegate(t, store, root, root.Claims.Workload, "vm://expiring", clk.Now().Add(time.Minute), nil)
	revoked := delegate(t, store, root, root.Claims.Workload, "vm://revoked", clk.Now().Add(30*time.Minute), nil)
	revokedDescendant := delegate(t, store, revoked, revoked.Claims.Workload, "vm://revoked/descendant", clk.Now().Add(20*time.Minute), nil)
	active := delegate(t, store, root, root.Claims.Workload, "vm://active", clk.Now().Add(30*time.Minute), nil)
	if err := store.Revoke(context.Background(), revoked.Bearer); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, Options{Now: clk.Now})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer reopened.Close()
	if got := len(reopened.records); got != 2 {
		t.Fatalf("records after pruning = %d, want root and active child", got)
	}
	for _, removed := range []IssuedToken{expiring, revoked, revokedDescendant} {
		if _, exists := sRecordByID(reopened, removed.Claims.TokenID); exists {
			t.Fatalf("inactive record %s survived Open pruning", removed.Claims.TokenID)
		}
	}
	if _, err := reopened.Validate(context.Background(), active.Bearer, ValidationRequest{
		Workload: active.Claims.Workload, Audience: active.Claims.Audience,
	}); err != nil {
		t.Fatalf("active token Validate() error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range []IssuedToken{expiring, revoked, revokedDescendant} {
		if strings.Contains(string(contents), removed.Claims.TokenID) {
			t.Fatalf("inactive record %s remains on disk", removed.Claims.TokenID)
		}
	}
}

func TestGlobalRecordLimitPrunesBeforeRejecting(t *testing.T) {
	clk := &clock{now: testNow}
	store, _ := openTestStore(t, Options{Now: clk.Now, MaxRecords: 2})
	first := mintRoot(t, store, clk.Now(), func(req *MintRequest) {
		req.ExpiresAt = clk.Now().Add(time.Minute)
	})
	_ = mintRoot(t, store, clk.Now(), func(req *MintRequest) { req.Workload = "vm://second" })
	_, err := store.Mint(context.Background(), MintRequest{
		Workload: "vm://overflow", Audience: first.Claims.Audience,
		ExpiresAt: clk.Now().Add(time.Hour), Grants: []Grant{testGrant()},
	})
	if !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("Mint(at global bound) error = %v, want ErrRecordLimit", err)
	}
	clk.Advance(time.Minute)
	if _, err := store.Mint(context.Background(), MintRequest{
		Workload: "vm://after-prune", Audience: first.Claims.Audience,
		ExpiresAt: clk.Now().Add(time.Hour), Grants: []Grant{testGrant()},
	}); err != nil {
		t.Fatalf("Mint(after expired-record pruning) error = %v", err)
	}
}

func TestOpenPrunesBeforeApplyingConfiguredRecordBound(t *testing.T) {
	clk := &clock{now: testNow}
	store, path := openTestStore(t, Options{Now: clk.Now, MaxRecords: 2})
	expired := mintRoot(t, store, clk.Now(), func(req *MintRequest) {
		req.ExpiresAt = clk.Now().Add(time.Minute)
	})
	active := mintRoot(t, store, clk.Now(), func(req *MintRequest) {
		req.Workload = "vm://active"
	})
	clk.Advance(time.Minute)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, Options{Now: clk.Now, MaxRecords: 1})
	if err != nil {
		t.Fatalf("Open(after expiry with lower bound) error = %v", err)
	}
	defer reopened.Close()
	if _, exists := sRecordByID(reopened, expired.Claims.TokenID); exists {
		t.Fatal("expired root survived lower-bound Open")
	}
	if _, err := reopened.Validate(context.Background(), active.Bearer, ValidationRequest{
		Workload: active.Claims.Workload, Audience: active.Claims.Audience,
	}); err != nil {
		t.Fatalf("active token Validate() error = %v", err)
	}
}

func TestIssuanceReservesRevocationHeadroom(t *testing.T) {
	clk := &clock{now: testNow}
	store, path := openTestStore(t, Options{
		Now: clk.Now, MaxRecords: 100, storeFileSizeLimit: 32 << 10,
	})
	var issued []IssuedToken
	for index := 0; index < 100; index++ {
		token, err := store.Mint(context.Background(), MintRequest{
			Workload: fmt.Sprintf("vm://capacity/%03d", index), Audience: "data-plane",
			ExpiresAt: clk.Now().Add(time.Hour), Grants: []Grant{testGrant()},
		})
		if errors.Is(err, ErrRecordLimit) {
			break
		}
		if err != nil {
			t.Fatalf("Mint(%d) error = %v", index, err)
		}
		issued = append(issued, token)
	}
	if len(issued) < 2 || len(issued) == 100 {
		t.Fatalf("capacity guard admitted %d records; expected a nontrivial file-bound limit", len(issued))
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(context.Background(), issued[0].Bearer); err != nil {
		t.Fatalf("Revoke(near capacity) error = %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() > 32<<10 || after.Size() <= before.Size() {
		t.Fatalf("revoked store sizes before=%d after=%d, want bounded metadata growth", before.Size(), after.Size())
	}
}

func TestOpenRejectsStateWithoutRevocationHeadroom(t *testing.T) {
	clk := &clock{now: testNow}
	directory := t.TempDir()
	path := filepath.Join(directory, "tokens.json")
	largeOptions := Options{Now: clk.Now, MaxGrantsPerToken: 16, storeFileSizeLimit: 64 << 10}
	store, err := Open(path, largeOptions)
	if err != nil {
		t.Fatal(err)
	}
	grants := make([]Grant, 0, 8)
	for index := range 8 {
		grant := testGrant()
		grant.Service = fmt.Sprintf("service-%d", index)
		grant.CredentialRef = fmt.Sprintf("vault://%d/%s", index, strings.Repeat("x", 800))
		grants = append(grants, grant)
	}
	if _, err := store.Mint(context.Background(), MintRequest{
		Workload: "vm://large", Audience: "data-plane", ExpiresAt: clk.Now().Add(time.Hour), Grants: grants,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	limit := int(info.Size()) + fixedRevocationHeadroom/2
	if limit < minimumStoreFileSize {
		limit = minimumStoreFileSize
	}
	_, err = Open(path, Options{Now: clk.Now, MaxGrantsPerToken: 16, storeFileSizeLimit: limit})
	if !errors.Is(err, ErrCorruptStore) || !errors.Is(err, ErrRecordLimit) {
		t.Fatalf("Open(without headroom) error = %v, want ErrCorruptStore and ErrRecordLimit", err)
	}
}

func sRecordByID(store *Store, id string) (record, bool) {
	hash, err := parseTokenID(id)
	if err != nil {
		return record{}, false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	rec, ok := store.records[hash]
	return rec, ok
}
