package secrets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultExecTimeout   = 5 * time.Second
	defaultExecMaxOutput = 64 << 10
	maxExecOutputLimit   = 64 << 20
)

var (
	// ErrExecFailed is intentionally opaque: child output and secret values
	// must never be incorporated into a returned error.
	ErrExecFailed  = errors.New("secrets: credential command failed")
	ErrExecTimeout = errors.New("secrets: credential command timed out")
	ErrOutputLimit = errors.New("secrets: credential command output exceeded limit")
)

// ExecOptions controls a hardened credential command invocation. Args are
// placed before the reference. For agent-secret, leave Args nil to use "get".
// ExtraEnv is added to a small, cleared environment; inherited environment is
// never passed wholesale to the child.
type ExecOptions struct {
	Args      []string
	ExtraEnv  []string
	Timeout   time.Duration
	MaxOutput int
}

// ExecBackend invokes an absolute credential helper without a shell.
type ExecBackend struct {
	path      string
	args      []string
	env       []string
	timeout   time.Duration
	maxOutput int
}

// NewExecBackend validates and resolves executablePath immediately. The
// executable must be an absolute path to an executable regular file.
func NewExecBackend(executablePath string, options ExecOptions) (*ExecBackend, error) {
	if !filepath.IsAbs(executablePath) {
		return nil, ErrExecFailed
	}
	resolved, err := filepath.EvalSymlinks(executablePath)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, ErrExecFailed
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, ErrExecFailed
	}

	timeout := options.Timeout
	if timeout == 0 {
		timeout = defaultExecTimeout
	}
	if timeout < 0 {
		return nil, ErrExecFailed
	}
	maxOutput := options.MaxOutput
	if maxOutput == 0 {
		maxOutput = defaultExecMaxOutput
	}
	if maxOutput < 1 || maxOutput > maxExecOutputLimit {
		return nil, ErrExecFailed
	}
	args := append([]string(nil), options.Args...)
	if options.Args == nil {
		args = []string{"get"}
	}
	env, err := minimalEnv(options.ExtraEnv)
	if err != nil {
		return nil, ErrExecFailed
	}
	return &ExecBackend{
		path:      resolved,
		args:      args,
		env:       env,
		timeout:   timeout,
		maxOutput: maxOutput,
	}, nil
}

// Get invokes the configured helper as: executable Args... reference.
func (b *ExecBackend) Get(ctx context.Context, reference string) (*Lease, error) {
	if b == nil {
		return nil, ErrClosed
	}
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	args := make([]string, 0, len(b.args)+1)
	args = append(args, b.args...)
	args = append(args, reference)
	cmd := exec.CommandContext(runCtx, b.path, args...)
	cmd.Env = append([]string(nil), b.env...)
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	configureCommand(cmd)

	// Store at most MaxOutput plus a CRLF and keep draining thereafter. This
	// bounds memory even if a compromised helper emits unbounded output.
	output := &cappedBuffer{limit: b.maxOutput + 2}
	defer func() { zero(output.buf) }()
	cmd.Stdout = output
	err := cmd.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, ErrExecTimeout
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, ErrExecFailed
	}
	if output.overflow {
		return nil, ErrOutputLimit
	}
	value := trimOneNewline(output.buf)
	if len(value) > b.maxOutput {
		return nil, ErrOutputLimit
	}
	lease := NewLease(value)
	return lease, nil
}

func minimalEnv(extra []string) ([]string, error) {
	values := map[string]string{
		"PATH":   "/usr/bin:/bin",
		"LANG":   "C",
		"LC_ALL": "C",
	}
	for _, name := range []string{"HOME", "USER", "LOGNAME"} {
		if value, ok := os.LookupEnv(name); ok {
			values[name] = value
		}
	}
	for _, item := range extra {
		name, value, ok := strings.Cut(item, "=")
		if !ok || name == "" || strings.IndexByte(name, 0) >= 0 || strings.IndexByte(value, 0) >= 0 {
			return nil, ErrExecFailed
		}
		values[name] = value
	}
	// Stable ordering makes the environment deterministic and easier to audit.
	order := []string{"HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL"}
	env := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, name := range order {
		if value, ok := values[name]; ok {
			env = append(env, name+"="+value)
			seen[name] = struct{}{}
		}
	}
	for _, item := range extra {
		name, _, _ := strings.Cut(item, "=")
		if _, ok := seen[name]; ok {
			continue
		}
		env = append(env, name+"="+values[name])
		seen[name] = struct{}{}
	}
	return env, nil
}

type cappedBuffer struct {
	buf      []byte
	limit    int
	overflow bool
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	remaining := w.limit - len(w.buf)
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		w.buf = append(w.buf, p[:remaining]...)
	}
	if remaining < len(p) {
		w.overflow = true
	}
	return len(p), nil
}

func trimOneNewline(value []byte) []byte {
	if bytes.HasSuffix(value, []byte("\r\n")) {
		return value[:len(value)-2]
	}
	if bytes.HasSuffix(value, []byte("\n")) {
		return value[:len(value)-1]
	}
	return value
}
