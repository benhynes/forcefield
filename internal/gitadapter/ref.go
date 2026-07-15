package gitadapter

import (
	"fmt"
	"strings"
)

// ValidateRefName implements the safety-relevant git-check-ref-format rules
// for a full ref. Receive-pack updates must additionally begin with refs/.
func ValidateRefName(name string) error {
	if !strings.HasPrefix(name, "refs/") || len(name) == len("refs/") || name == "@" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") || strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.HasSuffix(name, ".") {
		return ErrInvalidRef
	}
	components := strings.Split(name, "/")
	if len(components) < 2 {
		return ErrInvalidRef
	}
	for _, component := range components {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return ErrInvalidRef
		}
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b < 0x20 || b == 0x7f || b == ' ' || strings.ContainsRune("~^:?*[\\", rune(b)) {
			return ErrInvalidRef
		}
	}
	return nil
}

func validateRefNameBounded(name string, maxBytes int) error {
	if len(name) == 0 || len(name) > maxBytes {
		return fmt.Errorf("%w: ref length", ErrInvalidRef)
	}
	return ValidateRefName(name)
}
