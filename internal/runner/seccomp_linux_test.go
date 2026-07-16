//go:build linux

package runner

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxSeccompFilterEvaluatesPolicy(t *testing.T) {
	spec, err := sandboxSeccompArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := buildSandboxSeccompFilter(spec)
	if err != nil {
		t.Fatal(err)
	}

	if len(filter) < 4 {
		t.Fatalf("filter has only %d instructions", len(filter))
	}
	if want := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS); filter[0].Code != want || filter[0].K != seccompDataArchOffset {
		t.Fatalf("first instruction = %#v, want audit-arch load", filter[0])
	}
	if want := uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K); filter[1].Code != want || filter[1].K != spec.auditArch {
		t.Fatalf("second instruction = %#v, want audit-arch comparison", filter[1])
	}

	wrongArch := spec.auditArch ^ 1
	if got := evaluateSandboxBPF(t, filter, sandboxSeccompData{arch: wrongArch, number: unix.SYS_GETPID}); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatalf("architecture mismatch returned %#x, want KILL_PROCESS", got)
	}

	wantDenied := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	for _, number := range spec.deniedSyscalls {
		if got := evaluateSandboxBPF(t, filter, sandboxSeccompData{arch: spec.auditArch, number: number}); got != wantDenied {
			t.Errorf("denied syscall %d returned %#x, want %#x", number, got, wantDenied)
		}
	}
	ioctlData := sandboxSeccompData{arch: spec.auditArch, number: spec.ioctlNumber}
	ioctlData.arguments[1] = uint64(unix.TIOCSTI)
	if got := evaluateSandboxBPF(t, filter, ioctlData); got != wantDenied {
		t.Errorf("TIOCSTI returned %#x, want %#x", got, wantDenied)
	}
	ioctlData.arguments[1] = uint64(unix.TIOCGWINSZ)
	if got := evaluateSandboxBPF(t, filter, ioctlData); got != unix.SECCOMP_RET_ALLOW {
		t.Errorf("ordinary terminal ioctl returned %#x, want ALLOW", got)
	}
	for _, family := range spec.allowedSocketFamilies {
		socketData := sandboxSeccompData{arch: spec.auditArch, number: spec.socketNumber}
		socketData.arguments[0] = uint64(family)
		if got := evaluateSandboxBPF(t, filter, socketData); got != unix.SECCOMP_RET_ALLOW {
			t.Errorf("socket family %d returned %#x, want ALLOW", family, got)
		}
	}
	vsockData := sandboxSeccompData{arch: spec.auditArch, number: spec.socketNumber}
	vsockData.arguments[0] = uint64(unix.AF_VSOCK)
	if got := evaluateSandboxBPF(t, filter, vsockData); got != wantDenied {
		t.Errorf("AF_VSOCK returned %#x, want %#x", got, wantDenied)
	}

	ordinary := []uint32{
		unix.SYS_READ,
		unix.SYS_WRITE,
		unix.SYS_OPENAT,
		unix.SYS_CLOSE,
		unix.SYS_GETPID,
		unix.SYS_CONNECT,
		unix.SYS_ACCEPT4,
		unix.SYS_CLONE,
		unix.SYS_EXECVE,
	}
	for _, number := range ordinary {
		if got := evaluateSandboxBPF(t, filter, sandboxSeccompData{arch: spec.auditArch, number: number}); got != unix.SECCOMP_RET_ALLOW {
			t.Errorf("ordinary syscall %d returned %#x, want ALLOW", number, got)
		}
	}
}

func TestSandboxSeccompFilterContainsRequiredDenylist(t *testing.T) {
	spec, err := sandboxSeccompArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	denied := make(map[uint32]bool, len(spec.deniedSyscalls))
	for _, number := range spec.deniedSyscalls {
		if denied[number] {
			t.Fatalf("duplicate syscall number %d", number)
		}
		denied[number] = true
	}

	required := []uint32{
		unix.SYS_MOUNT,
		unix.SYS_UMOUNT2,
		unix.SYS_PIVOT_ROOT,
		unix.SYS_CHROOT,
		unix.SYS_SETNS,
		unix.SYS_UNSHARE,
		unix.SYS_BPF,
		unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV,
		unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_INIT_MODULE,
		unix.SYS_FINIT_MODULE,
		unix.SYS_DELETE_MODULE,
		unix.SYS_KEXEC_LOAD,
		unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_REBOOT,
		unix.SYS_SWAPON,
		unix.SYS_SWAPOFF,
		unix.SYS_ADD_KEY,
		unix.SYS_REQUEST_KEY,
		unix.SYS_KEYCTL,
		unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_NAME_TO_HANDLE_AT,
		unix.SYS_USERFAULTFD,
		unix.SYS_IO_URING_SETUP,
		unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER,
		unix.SYS_FANOTIFY_INIT,
		unix.SYS_FANOTIFY_MARK,
		unix.SYS_ACCT,
		unix.SYS_QUOTACTL,
		unix.SYS_SYSLOG,
	}
	for _, number := range required {
		if !denied[number] {
			t.Errorf("required syscall %d is not denied", number)
		}
	}
}

func TestBuildSandboxSeccompFilterRejectsInvalidSpecs(t *testing.T) {
	tests := []struct {
		name string
		spec sandboxSeccompSpec
	}{
		{name: "missing architecture", spec: sandboxSeccompSpec{deniedSyscalls: []uint32{1}}},
		{name: "empty denylist", spec: sandboxSeccompSpec{auditArch: 1}},
		{name: "duplicate syscall", spec: sandboxSeccompSpec{auditArch: 1, deniedSyscalls: []uint32{2, 2}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildSandboxSeccompFilter(test.spec); err == nil {
				t.Fatal("invalid seccomp specification was accepted")
			}
		})
	}
}

type sandboxSeccompData struct {
	number    uint32
	arch      uint32
	arguments [6]uint64
}

// evaluateSandboxBPF interprets the deliberately small classic-BPF subset
// emitted by buildSandboxSeccompFilter. It verifies jump behavior without
// irreversibly installing a filter in the test process.
func evaluateSandboxBPF(t *testing.T, filter []unix.SockFilter, data sandboxSeccompData) uint32 {
	t.Helper()
	var accumulator uint32
	for pc := 0; pc < len(filter); {
		instruction := filter[pc]
		switch instruction.Code {
		case uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS):
			switch instruction.K {
			case seccompDataNumberOffset:
				accumulator = data.number
			case seccompDataArchOffset:
				accumulator = data.arch
			case seccompDataArgument0Offset:
				accumulator = uint32(data.arguments[0])
			case seccompDataArgument1Offset:
				accumulator = uint32(data.arguments[1])
			default:
				t.Fatalf("unsupported seccomp-data offset %d at instruction %d", instruction.K, pc)
			}
			pc++
		case uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K):
			jump := instruction.Jf
			if accumulator == instruction.K {
				jump = instruction.Jt
			}
			pc += int(jump) + 1
		case uint16(unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K):
			jump := instruction.Jf
			if accumulator&instruction.K != 0 {
				jump = instruction.Jt
			}
			pc += int(jump) + 1
		case uint16(unix.BPF_RET | unix.BPF_K):
			return instruction.K
		default:
			t.Fatal(fmt.Sprintf("unsupported BPF instruction %#x at index %d", instruction.Code, pc))
		}
	}
	t.Fatal("BPF program terminated without RET")
	return 0
}
