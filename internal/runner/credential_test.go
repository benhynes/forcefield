package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRunnerFileRequiresTrustedAncestryAndModes(t *testing.T) {
	base := realTempDir(t)
	private := mkdirPrivate(t, filepath.Join(base, "credentials"))
	path := filepath.Join(private, "client.key")
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, err := readRunnerFile(path, 1024, true); err != nil || string(contents) != "key" {
		t.Fatalf("trusted private file = %q, %v", contents, err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := readRunnerFile(path, 1024, true); err == nil {
		t.Fatal("group-readable private key was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := readRunnerFile(path, 1024, true); err == nil {
		t.Fatal("credential below group-writable directory was accepted")
	}
}

func TestReadRunnerFileRejectsSymlinkAncestry(t *testing.T) {
	base := realTempDir(t)
	realDirectory := mkdirPrivate(t, filepath.Join(base, "real"))
	path := filepath.Join(realDirectory, "ca.pem")
	if err := os.WriteFile(path, []byte("certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRunnerFile(filepath.Join(link, "ca.pem"), 1024, false); err == nil {
		t.Fatal("credential path with symlink ancestry was accepted")
	}
}
