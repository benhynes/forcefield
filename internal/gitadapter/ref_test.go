package gitadapter

import (
	"errors"
	"testing"
)

func TestValidateRefName(t *testing.T) {
	t.Parallel()

	valid := []string{
		"refs/x",
		"refs/heads/topic",
		"refs/tags/v1.2.3",
		"refs/namespaces/tenant/refs/heads/topic",
		"refs/heads/foo.locked",
		"refs/heads/foo./bar",
		"refs/heads/naïve",
	}
	for _, ref := range valid {
		if err := ValidateRefName(ref); err != nil {
			t.Errorf("ValidateRefName(%q) error = %v", ref, err)
		}
	}

	invalid := []string{
		"",
		"HEAD",
		"@",
		"refs/",
		"refs//heads/topic",
		"refs/heads/topic/",
		"refs/.hidden/topic",
		"refs/heads/.hidden",
		"refs/heads/topic.lock",
		"refs/heads/foo..bar",
		"refs/heads/foo@{bar",
		"refs/heads/topic.",
		"refs/heads/has space",
		"refs/heads/has~tilde",
		"refs/heads/has^caret",
		"refs/heads/has:colon",
		"refs/heads/has?question",
		"refs/heads/has*star",
		"refs/heads/has[bracket",
		"refs/heads/has\\backslash",
		"refs/heads/has\x00nul",
		"refs/heads/has\x1fcontrol",
		"refs/heads/has\x7fdelete",
	}
	for _, ref := range invalid {
		if err := ValidateRefName(ref); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("ValidateRefName(%q) error = %v, want ErrInvalidRef", ref, err)
		}
	}
}

func TestValidateRefNameBounded(t *testing.T) {
	t.Parallel()
	if err := validateRefNameBounded("refs/heads/topic", len("refs/heads/topic")-1); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("error = %v, want ErrInvalidRef", err)
	}
}
