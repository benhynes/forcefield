//go:build linux && amd64

package runner

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAMD64SandboxSeccompRejectsX32AndRawIO(t *testing.T) {
	spec, err := sandboxSeccompArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := buildSandboxSeccompFilter(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)

	if got := evaluateSandboxBPF(t, filter, sandboxSeccompData{arch: spec.auditArch, number: uint32(unix.SYS_GETPID) | 0x40000000}); got != want {
		t.Fatalf("x32 syscall returned %#x, want %#x", got, want)
	}
	for _, number := range []uint32{unix.SYS_IOPL, unix.SYS_IOPERM} {
		if got := evaluateSandboxBPF(t, filter, sandboxSeccompData{arch: spec.auditArch, number: number}); got != want {
			t.Errorf("raw I/O syscall %d returned %#x, want %#x", number, got, want)
		}
	}
}
