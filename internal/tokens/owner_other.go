//go:build !linux && !darwin

package tokens

import "os"

func ensureCurrentOwner(os.FileInfo, string) error {
	return nil
}
