package gitadapter

import "testing"

func TestNormalizeRepositoryMakesCaseSemanticsExplicit(t *testing.T) {
	t.Parallel()
	value, err := NormalizeRepository("Acme/INFRASTRUCTURE.git", RepositoryCaseASCIIInsensitive)
	if err != nil || value != "acme/infrastructure.git" {
		t.Fatalf("ASCII-insensitive identity = %q, %v", value, err)
	}
	value, err = NormalizeRepository("Acme/Infrastructure.git", RepositoryCaseSensitive)
	if err != nil || value != "Acme/Infrastructure.git" {
		t.Fatalf("case-sensitive identity = %q, %v", value, err)
	}
	if _, err := NormalizeRepository("acme/répo.git", RepositoryCaseASCIIInsensitive); err == nil {
		t.Fatal("ASCII-insensitive mode guessed at Unicode repository folding")
	}
}
