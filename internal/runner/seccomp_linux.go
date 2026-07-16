//go:build linux

package runner

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompDataNumberOffset    = 0
	seccompDataArchOffset      = 4
	seccompDataArgument0Offset = 16
	seccompDataArgument1Offset = 24
	seccompMaxInstructions     = 4096
)

// ErrSandboxSeccompUnsupported reports that Forcefield has no audited
// seccomp policy for the current operating system or CPU architecture.
var ErrSandboxSeccompUnsupported = errors.New("sandbox seccomp is unsupported")

type sandboxSeccompSpec struct {
	auditArch             uint32
	rejectedNumberMask    uint32
	deniedSyscalls        []uint32
	ioctlNumber           uint32
	deniedIoctls          []uint32
	socketNumber          uint32
	allowedSocketFamilies []uint32
}

// InstallSandboxSeccomp irreversibly enables no-new-privileges and installs
// the Forcefield sandbox syscall policy on every thread in the process.
//
// Callers must treat any returned error as fatal and must not execute an
// untrusted workload afterward. Only linux/amd64 and linux/arm64 have audited
// policies; other platforms return ErrSandboxSeccompUnsupported.
func InstallSandboxSeccomp() error {
	spec, err := sandboxSeccompArchitecture()
	if err != nil {
		return err
	}
	filter, err := buildSandboxSeccompFilter(spec)
	if err != nil {
		return fmt.Errorf("construct sandbox seccomp filter: %w", err)
	}

	// A goroutine may otherwise move to another kernel thread between prctl
	// and seccomp. TSYNC applies the filter to all threads, but the thread that
	// invokes seccomp must be the one on which no-new-privileges was enabled.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("enable no-new-privileges: %w", err)
	}
	program := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&program)),
		0,
		0,
		0,
	)
	// Keep both the program and its instruction backing array live until the
	// kernel has copied them.
	runtime.KeepAlive(program)
	runtime.KeepAlive(filter)
	if errno != 0 {
		return fmt.Errorf("install sandbox seccomp filter with thread sync: %w", errno)
	}
	return nil
}

func buildSandboxSeccompFilter(spec sandboxSeccompSpec) ([]unix.SockFilter, error) {
	if spec.auditArch == 0 {
		return nil, errors.New("audit architecture is missing")
	}
	if len(spec.deniedSyscalls) == 0 {
		return nil, errors.New("syscall denylist is empty")
	}

	seen := make(map[uint32]struct{}, len(spec.deniedSyscalls))
	for _, number := range spec.deniedSyscalls {
		if _, duplicate := seen[number]; duplicate {
			return nil, fmt.Errorf("duplicate denied syscall number %d", number)
		}
		seen[number] = struct{}{}
	}
	if (spec.ioctlNumber == 0) != (len(spec.deniedIoctls) == 0) {
		return nil, errors.New("ioctl number and request denylist must be configured together")
	}
	if len(spec.deniedIoctls) > 127 {
		return nil, errors.New("ioctl denylist exceeds classic-BPF jump range")
	}
	seenIoctls := make(map[uint32]struct{}, len(spec.deniedIoctls))
	for _, request := range spec.deniedIoctls {
		if _, duplicate := seenIoctls[request]; duplicate {
			return nil, fmt.Errorf("duplicate denied ioctl request %d", request)
		}
		seenIoctls[request] = struct{}{}
	}
	if (spec.socketNumber == 0) != (len(spec.allowedSocketFamilies) == 0) {
		return nil, errors.New("socket number and family allowlist must be configured together")
	}
	if len(spec.allowedSocketFamilies) > 253 {
		return nil, errors.New("socket family allowlist exceeds classic-BPF jump range")
	}
	seenFamilies := make(map[uint32]struct{}, len(spec.allowedSocketFamilies))
	for _, family := range spec.allowedSocketFamilies {
		if _, duplicate := seenFamilies[family]; duplicate {
			return nil, fmt.Errorf("duplicate allowed socket family %d", family)
		}
		seenFamilies[family] = struct{}{}
	}

	// Load arch, compare arch, kill mismatch, load syscall number, then use
	// two instructions per denied syscall plus the final ALLOW. amd64 adds a
	// two-instruction guard that rejects the x32 ABI.
	length := 5 + 2*len(spec.deniedSyscalls)
	if spec.rejectedNumberMask != 0 {
		length += 2
	}
	if len(spec.deniedIoctls) != 0 {
		length += 3 + 2*len(spec.deniedIoctls)
	}
	if len(spec.allowedSocketFamilies) != 0 {
		length += 4 + len(spec.allowedSocketFamilies)
	}
	if length > seccompMaxInstructions || length > math.MaxUint16 {
		return nil, fmt.Errorf("seccomp filter has %d instructions", length)
	}

	deny := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	filter := make([]unix.SockFilter, 0, length)
	filter = append(filter,
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArchOffset),
		// Matching the expected audit architecture skips the KILL instruction.
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, spec.auditArch, 1, 0),
		seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNumberOffset),
	)
	if spec.rejectedNumberMask != 0 {
		// A set bit falls through to EPERM; native syscall numbers skip it.
		filter = append(filter,
			seccompJump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, spec.rejectedNumberMask, 0, 1),
			seccompStatement(unix.BPF_RET|unix.BPF_K, deny),
		)
	}
	if len(spec.deniedIoctls) != 0 {
		// Non-ioctl syscalls skip the argument checks and reload nr. ioctl
		// requests are compared against the lower 32 bits of arg1.
		filter = append(filter,
			seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, spec.ioctlNumber, 0, uint8(1+2*len(spec.deniedIoctls))),
			seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArgument1Offset),
		)
		for _, request := range spec.deniedIoctls {
			filter = append(filter,
				seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, request, 0, 1),
				seccompStatement(unix.BPF_RET|unix.BPF_K, deny),
			)
		}
		filter = append(filter, seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNumberOffset))
	}
	if len(spec.allowedSocketFamilies) != 0 {
		filter = append(filter,
			seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, spec.socketNumber, 0, uint8(2+len(spec.allowedSocketFamilies))),
			seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArgument0Offset),
		)
		for index, family := range spec.allowedSocketFamilies {
			filter = append(filter, seccompJump(
				unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, family,
				uint8(len(spec.allowedSocketFamilies)-index), 0,
			))
		}
		filter = append(filter,
			seccompStatement(unix.BPF_RET|unix.BPF_K, deny),
			seccompStatement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNumberOffset),
		)
	}
	for _, number := range spec.deniedSyscalls {
		// Equality falls through to EPERM; inequality skips the return.
		filter = append(filter,
			seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, number, 0, 1),
			seccompStatement(unix.BPF_RET|unix.BPF_K, deny),
		)
	}
	filter = append(filter, seccompStatement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW))
	return filter, nil
}

func seccompStatement(code uint16, value uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: value}
}

func seccompJump(code uint16, value uint32, jumpTrue, jumpFalse uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jumpTrue, Jf: jumpFalse, K: value}
}
