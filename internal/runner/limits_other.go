//go:build !linux

package runner

import "errors"

func ApplySupervisorLimits() error {
	return errors.New("runner supervisor limits require Linux")
}
