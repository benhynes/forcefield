package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGitCredentialGet(t *testing.T) {
	t.Parallel()
	token := "ff_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := "protocol=https\nhost=forcefield.test:7902\npath=forgejo-git/org/repo.git\nwwwauth[]=Basic realm=forcefield-git\n\n"
	var output bytes.Buffer
	if err := runGitCredential([]string{
		"--url", "https://forcefield.test:7902/forgejo-git",
		"--token-file", tokenFile,
		"get",
	}, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	want := "username=forcefield\npassword=" + token + "\n\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}

func TestRunGitCredentialDoesNotServeOutsideScope(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"scheme":       "protocol=http\nhost=forcefield.test\npath=forgejo-git/org/repo.git\n\n",
		"host":         "protocol=https\nhost=other.test\npath=forgejo-git/org/repo.git\n\n",
		"port":         "protocol=https\nhost=forcefield.test:443\npath=forgejo-git/org/repo.git\n\n",
		"path sibling": "protocol=https\nhost=forcefield.test\npath=forgejo-git-evil/org/repo.git\n\n",
		"parent path":  "protocol=https\nhost=forcefield.test\npath=org/repo.git\n\n",
		"dot segment":  "protocol=https\nhost=forcefield.test\npath=forgejo-git/../repo.git\n\n",
	}
	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			err := runGitCredential([]string{
				"--url", "https://forcefield.test/forgejo-git",
				"--token-file", filepath.Join(t.TempDir(), "must-not-be-read"),
				"get",
			}, strings.NewReader(input), &output)
			if err != nil {
				t.Fatalf("non-matching context returned error: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("non-matching context output = %q", output.String())
			}
		})
	}
}

func TestRunGitCredentialStoreAndEraseAreNoops(t *testing.T) {
	t.Parallel()
	input := "protocol=https\nhost=forcefield.test\npath=forgejo-git/org/repo.git\nusername=forcefield\npassword=must-not-be-written\n\n"
	for _, operation := range []string{"store", "erase"} {
		operation := operation
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			missing := filepath.Join(t.TempDir(), "token")
			if err := runGitCredential([]string{
				"--url", "https://forcefield.test/forgejo-git", "--token-file", missing, operation,
			}, strings.NewReader(input), &output); err != nil {
				t.Fatal(err)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q", output.String())
			}
			if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("helper persisted a credential: %v", err)
			}
		})
	}
}

func TestRunGitCredentialRejectsMalformedOrOversizedInput(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"empty":              "",
		"unterminated":       "protocol=https\nhost=forcefield.test\n",
		"duplicate protocol": "protocol=https\nprotocol=https\nhost=forcefield.test\npath=forgejo-git/repo.git\n\n",
		"compound url":       "url=https://forcefield.test/forgejo-git/repo.git\n\n",
		"embedded record":    "protocol=https\n\nhost=forcefield.test\n\n",
		"carriage return":    "protocol=https\r\nhost=forcefield.test\r\n\r\n",
		"oversized":          "protocol=https\nhost=forcefield.test\nunknown=" + strings.Repeat("x", maxGitCredentialInputBytes) + "\n\n",
	}
	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			err := runGitCredential([]string{
				"--url", "https://forcefield.test/forgejo-git",
				"--token-file", filepath.Join(t.TempDir(), "token"),
				"get",
			}, strings.NewReader(input), &output)
			if err == nil {
				t.Fatal("malformed input succeeded")
			}
			if output.Len() != 0 {
				t.Fatalf("malformed input output = %q", output.String())
			}
		})
	}
}

func TestRunGitCredentialRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	input := "protocol=https\nhost=forcefield.test\npath=forgejo-git/repo.git\n\n"
	for _, configuredURL := range []string{
		"", "forcefield.test/forgejo-git", "ftp://forcefield.test/forgejo-git",
		"https://user@forcefield.test/forgejo-git", "https://forcefield.test/forgejo-git?x=1",
		"https://forcefield.test/forgejo-git#fragment", "https://forcefield.test/a/../forgejo-git",
		"https://FORCEFIELD.test/forgejo-git", "https://forcefield.test/forgejo-git/",
	} {
		configuredURL := configuredURL
		t.Run(configuredURL, func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			err := runGitCredential([]string{
				"--url", configuredURL, "--token-file", filepath.Join(t.TempDir(), "token"), "get",
			}, strings.NewReader(input), &output)
			if err == nil {
				t.Fatal("unsafe configuration succeeded")
			}
			if output.Len() != 0 {
				t.Fatalf("unsafe configuration output = %q", output.String())
			}
		})
	}
}

func TestRunGitCredentialRejectsBadInvocation(t *testing.T) {
	t.Parallel()
	input := strings.NewReader("protocol=https\nhost=forcefield.test\npath=repo.git\n\n")
	for _, args := range [][]string{
		{"--url", "https://forcefield.test", "--token-file", "/unused"},
		{"--url", "https://forcefield.test", "--token-file", "/unused", "wat"},
		{"--url", "https://forcefield.test", "get"},
	} {
		if err := runGitCredential(args, input, io.Discard); err == nil {
			t.Fatalf("invocation %q succeeded", args)
		}
	}
}

func TestRunGitCredentialPropagatesOutputFailureWithoutCredentialInError(t *testing.T) {
	t.Parallel()
	token := "ff_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := "protocol=https\nhost=forcefield.test\npath=repo.git\n\n"
	err := runGitCredential([]string{
		"--url", "https://forcefield.test", "--token-file", tokenFile, "get",
	}, strings.NewReader(input), errorWriter{})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error = %v", err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), tokenFile) {
		t.Fatal("output error exposed credential material")
	}
}
