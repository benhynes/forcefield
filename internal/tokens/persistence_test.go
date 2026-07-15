package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenRejectsInsecurePaths(t *testing.T) {
	t.Run("creates missing private directories", func(t *testing.T) {
		base := t.TempDir()
		directory := filepath.Join(base, "state", "forcefield")
		path := filepath.Join(directory, "tokens.json")
		store, err := Open(path, Options{})
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		defer store.Close()
		for current := directory; current != base; current = filepath.Dir(current) {
			info, err := os.Stat(current)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0o700 {
				t.Fatalf("created directory %s mode = %04o, want 0700", current, got)
			}
		}
	})

	t.Run("insecure file permissions", func(t *testing.T) {
		store, path := openTestStore(t, Options{})
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{}); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("Open() error = %v, want ErrInsecurePermissions", err)
		}
	})

	t.Run("store symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte("{\"version\":1,\"records\":[]}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "tokens.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link, Options{}); !errors.Is(err, ErrSymlink) {
			t.Fatalf("Open() error = %v, want ErrSymlink", err)
		}
	})

	t.Run("parent symlink", func(t *testing.T) {
		dir := t.TempDir()
		realDirectory := filepath.Join(dir, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDirectory := filepath.Join(dir, "link")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(filepath.Join(linkDirectory, "tokens.json"), Options{}); !errors.Is(err, ErrSymlink) {
			t.Fatalf("Open() error = %v, want ErrSymlink", err)
		}
	})

	t.Run("writable parent directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o700)
		if _, err := Open(filepath.Join(dir, "tokens.json"), Options{}); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("Open() error = %v, want ErrInsecurePermissions", err)
		}
	})

	t.Run("destination is directory", func(t *testing.T) {
		dir := t.TempDir()
		destination := filepath.Join(dir, "tokens.json")
		if err := os.Mkdir(destination, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(destination, Options{}); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("Open() error = %v, want ErrInsecurePermissions", err)
		}
	})
}

func TestOpenRejectsCorruptState(t *testing.T) {
	t.Run("unknown JSON field", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tokens.json")
		contents := []byte("{\"version\":1,\"records\":[],\"raw_token\":\"ff_forbidden\"}\n")
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{}); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Open() error = %v, want ErrCorruptStore", err)
		}
	})

	t.Run("trailing JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "tokens.json")
		if err := os.WriteFile(path, []byte("{\"version\":1,\"records\":[]} {}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{}); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Open() error = %v, want ErrCorruptStore", err)
		}
	})

	t.Run("delegated grant broadening", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, path := openTestStore(t, Options{Now: clk.Now})
		root := mintRoot(t, store, clk.Now(), nil)
		_ = delegate(t, store, root, root.Claims.Workload, "vm://child", clk.Now().Add(30*time.Minute), nil)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var state diskState
		if err := json.Unmarshal(contents, &state); err != nil {
			t.Fatal(err)
		}
		foundChild := false
		for index := range state.Records {
			if state.Records[index].Depth == 1 {
				state.Records[index].Grants[0].Limits.RequestBudget++
				foundChild = true
			}
		}
		if !foundChild {
			t.Fatal("persisted state did not contain child")
		}
		tampered, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{Now: clk.Now}); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Open(tampered) error = %v, want ErrCorruptStore", err)
		}
	})

	t.Run("configured bounds reduced", func(t *testing.T) {
		clk := &clock{now: testNow}
		store, path := openTestStore(t, Options{Now: clk.Now, MaxChildrenPerToken: 3})
		root := mintRoot(t, store, clk.Now(), nil)
		for index := range 2 {
			delegate(t, store, root, root.Claims.Workload, "vm://child/"+string(rune('a'+index)), clk.Now().Add(30*time.Minute), nil)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path, Options{Now: clk.Now, MaxChildrenPerToken: 1}); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("Open(with lower bound) error = %v, want ErrCorruptStore", err)
		}
	})
}

func TestFailedPersistenceDoesNotCommitInMemoryOrOnDisk(t *testing.T) {
	clk := &clock{now: testNow}
	store, path := openTestStore(t, Options{Now: clk.Now})
	root := mintRoot(t, store, clk.Now(), nil)
	directory := filepath.Dir(path)
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	_, mintErr := store.Mint(context.Background(), MintRequest{
		Workload:  "vm://uncommitted",
		Audience:  root.Claims.Audience,
		ExpiresAt: clk.Now().Add(time.Hour),
		Grants:    []Grant{testGrant()},
	})
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if mintErr == nil {
		t.Fatal("Mint() unexpectedly succeeded without directory write permission")
	}

	binding := ValidationRequest{Workload: root.Claims.Workload, Audience: root.Claims.Audience}
	if _, err := store.Validate(context.Background(), root.Bearer, binding); err != nil {
		t.Fatalf("existing in-memory token after failed commit: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := Open(path, Options{Now: clk.Now})
	if err != nil {
		t.Fatalf("Open() after failed commit = %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.Validate(context.Background(), root.Bearer, binding); err != nil {
		t.Fatalf("existing persisted token after failed commit: %v", err)
	}
	temps, err := filepath.Glob(filepath.Join(directory, ".tokens.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("failed commit left temporary files: %v", temps)
	}
}
