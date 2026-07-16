package runner

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	bubblewrapBackend = "bubblewrap"
	sandboxHome       = "/home/agent"
	brokerRoot        = "/run/forcefield"
)

// Host launch helpers are resolved only from operator-controlled system
// directories. In particular, never use the invoking agent's PATH here: the
// selected executable runs outside the sandbox and inherits host authority.
// Tests replace this package-private slice with a private fixture directory.
var trustedExecutableDirectories = []string{"/usr/bin", "/bin"}

// LaunchSpec describes one command inside a profile-defined sandbox.
// Executable is an absolute path in the sandbox, not a host executable path.
type LaunchSpec struct {
	Profile          Profile
	Workspace        string
	BrokerHostSocket string
	HiveAgent        string
	Executable       string
	RootFSExecutable bool
	Arguments        []string
	Environment      []string
}

// CommandSpec is ready to pass to exec.Command. Args does not include Path.
// Env is deliberately non-nil and empty so the bwrap process itself does not
// inherit runner secrets. The supervisor is responsible for applying the
// profile's cgroup limits before starting this command; doing that here via
// systemd-run would make the command builder host- and session-dependent.
type CommandSpec struct {
	Path string
	Args []string
	Env  []string
}

// BuildBubblewrap validates all host inputs before constructing a fail-closed
// bubblewrap invocation. Bubblewrap is a mount/namespace primitive: this
// function, rather than a caller-provided argument list, defines its security
// model.
func BuildBubblewrap(spec LaunchSpec) (CommandSpec, error) {
	if spec.Profile.Backend != "" && spec.Profile.Backend != bubblewrapBackend {
		return CommandSpec{}, invalidLaunch("profile backend is not bubblewrap")
	}

	bwrap, err := findExecutable("bwrap")
	if err != nil {
		return CommandSpec{}, invalidLaunch("bubblewrap executable is unavailable")
	}
	rootfs, err := canonicalDirectory(spec.Profile.RootFS, true)
	if err != nil {
		return CommandSpec{}, invalidLaunch("root filesystem is unsafe")
	}
	rootfsInfo, err := os.Stat(rootfs)
	if err != nil || rootfsInfo.Mode().Perm()&0o022 != 0 {
		return CommandSpec{}, invalidLaunch("root filesystem is writable by group or other")
	}
	workspace, err := canonicalDirectory(spec.Workspace, true)
	if err != nil {
		return CommandSpec{}, invalidLaunch("workspace is unsafe")
	}
	if hostPathsOverlap(rootfs, workspace) {
		return CommandSpec{}, invalidLaunch("workspace and root filesystem overlap")
	}

	workspaceTarget, err := cleanSandboxPath(spec.Profile.WorkspaceTarget)
	if err != nil || workspaceTarget == "/" || isAtOrBelow(workspaceTarget, "/proc") ||
		isAtOrBelow(workspaceTarget, "/dev") || isAtOrBelow(workspaceTarget, "/run") {
		return CommandSpec{}, invalidLaunch("workspace target is unsafe")
	}
	brokerSocket, err := cleanSandboxPath(spec.Profile.BrokerSocket)
	if err != nil || brokerSocket == brokerRoot || !isAtOrBelow(brokerSocket, brokerRoot) {
		return CommandSpec{}, invalidLaunch("sandbox broker socket is unsafe")
	}
	brokerHostSocket, err := canonicalSocket(spec.BrokerHostSocket)
	if err != nil {
		return CommandSpec{}, invalidLaunch("host broker socket is unsafe")
	}
	if hostPathWithin(brokerHostSocket, workspace) || hostPathWithin(brokerHostSocket, rootfs) {
		return CommandSpec{}, invalidLaunch("host broker socket overlaps sandbox inputs")
	}

	mounts, err := canonicalMounts(spec.Profile.ReadOnlyMounts, workspaceTarget, brokerSocket)
	if err != nil {
		return CommandSpec{}, err
	}
	for _, mount := range mounts {
		if hostPathWithin(brokerHostSocket, mount.source) {
			return CommandSpec{}, invalidLaunch("host broker socket is exposed by a read-only mount")
		}
	}
	executable, err := cleanSandboxPath(spec.Executable)
	if err != nil || executable == "/" || isAtOrBelow(executable, "/proc") ||
		isAtOrBelow(executable, "/dev") || isAtOrBelow(executable, "/run") {
		return CommandSpec{}, invalidLaunch("sandbox executable path is unsafe")
	}
	if err := validateSandboxExecutable(executable, rootfs, workspace, workspaceTarget, mounts); err != nil {
		return CommandSpec{}, invalidLaunch("sandbox executable is unavailable or unsafe")
	}
	if spec.RootFSExecutable {
		if isAtOrBelow(executable, workspaceTarget) {
			return CommandSpec{}, invalidLaunch("trusted sandbox executable is shadowed by the workspace")
		}
		for _, mount := range mounts {
			if isAtOrBelow(executable, mount.target) {
				return CommandSpec{}, invalidLaunch("trusted sandbox executable is shadowed by a read-only mount")
			}
		}
		hostExecutable := filepath.Join(rootfs, filepath.FromSlash(strings.TrimPrefix(executable, "/")))
		if validateTrustedPath(hostExecutable, true) != nil {
			return CommandSpec{}, invalidLaunch("trusted sandbox executable has unsafe ancestry or permissions")
		}
	}
	for _, argument := range spec.Arguments {
		if strings.IndexByte(argument, 0) >= 0 {
			return CommandSpec{}, invalidLaunch("command argument contains NUL")
		}
	}
	if spec.Profile.Hive.Enabled() {
		if !validHiveAddress(spec.HiveAgent) || !strings.Contains(spec.HiveAgent, "@") {
			return CommandSpec{}, invalidLaunch("Hive-enabled sandbox requires a full agent identity")
		}
	} else if spec.HiveAgent != "" {
		return CommandSpec{}, invalidLaunch("Hive agent identity was supplied to a profile without Hive access")
	}
	environment, err := sandboxEnvironment(spec.Profile, spec.Environment, spec.HiveAgent)
	if err != nil {
		return CommandSpec{}, err
	}

	args := []string{
		"--die-with-parent",
		"--unshare-all",
		// systemd-run --pty provides a subordinate, mediated terminal. Preserve
		// that controlling-terminal relationship for agent TUIs and shell job
		// control; the inherited seccomp policy rejects TIOCSTI before the
		// untrusted child is started.
		"--disable-userns",
		"--cap-drop", "ALL",
		"--clearenv",
		"--ro-bind", rootfs, "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--perms", "0700", "--tmpfs", "/tmp",
		"--perms", "0700", "--tmpfs", "/run",
		"--perms", "0700", "--tmpfs", "/home",
		"--perms", "0700", "--dir", sandboxHome,
	}
	workspaceBind := "--bind"
	if spec.Profile.WorkspaceReadOnly {
		workspaceBind = "--ro-bind"
	}
	args = append(args, workspaceBind, workspace, workspaceTarget)

	brokerParent := path.Dir(brokerSocket)
	args = append(args,
		"--perms", "0700", "--dir", brokerParent,
		"--ro-bind", brokerHostSocket, brokerSocket,
	)
	for _, mount := range mounts {
		args = append(args, "--ro-bind", mount.source, mount.target)
	}
	args = append(args, "--chdir", workspaceTarget)
	for _, item := range environment {
		name, value, _ := strings.Cut(item, "=")
		args = append(args, "--setenv", name, value)
	}
	args = append(args, "--", executable)
	args = append(args, spec.Arguments...)

	return CommandSpec{
		Path: bwrap,
		Args: args,
		// An empty, non-nil environment prevents exec.Cmd from inheriting the
		// runner's credentials. Child environment is built with --clearenv above.
		Env: []string{},
	}, nil
}

type resolvedMount struct {
	source string
	target string
	info   os.FileInfo
}

func canonicalMounts(configured []Mount, workspaceTarget, brokerSocket string) ([]resolvedMount, error) {
	mounts := make([]resolvedMount, 0, len(configured))
	for _, configuredMount := range configured {
		target, err := cleanSandboxPath(configuredMount.Target)
		if err != nil || target == "/" || target == "/proc" || target == "/dev" || target == "/run" ||
			target == "/tmp" || target == "/home" || isAtOrBelow(target, "/proc") ||
			isAtOrBelow(target, "/dev") || isAtOrBelow(target, "/run") || sandboxPathsOverlap(target, workspaceTarget) ||
			sandboxPathsOverlap(target, brokerSocket) {
			return nil, invalidLaunch("read-only mount target is unsafe")
		}
		source, info, err := canonicalMountSource(configuredMount.Source)
		if err != nil {
			return nil, invalidLaunch("read-only mount source is unsafe")
		}
		if isAtOrBelow(target, "/home") && (!isAtOrBelow(target, sandboxHome) || !info.Mode().IsRegular()) {
			return nil, invalidLaunch("home mounts must be individual files beneath the sandbox home")
		}
		mounts = append(mounts, resolvedMount{source: source, target: target, info: info})
	}
	for left := range mounts {
		for right := left + 1; right < len(mounts); right++ {
			if sandboxPathsOverlap(mounts[left].target, mounts[right].target) {
				return nil, invalidLaunch("read-only mount targets overlap")
			}
		}
	}
	return mounts, nil
}

func canonicalDirectory(raw string, rejectRoot bool) (string, error) {
	if raw == "" || !filepath.IsAbs(raw) || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("absolute directory required")
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil || !filepath.IsAbs(resolved) || rejectRoot && filepath.Clean(resolved) == string(filepath.Separator) {
		return "", errors.New("resolve directory")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("directory required")
	}
	return filepath.Clean(resolved), nil
}

func canonicalMountSource(raw string) (string, os.FileInfo, error) {
	if raw == "" || !filepath.IsAbs(raw) || strings.IndexByte(raw, 0) >= 0 {
		return "", nil, errors.New("absolute mount source required")
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) == string(filepath.Separator) {
		return "", nil, errors.New("resolve mount source")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() && !info.Mode().IsRegular() {
		return "", nil, errors.New("mount source must be a regular file or directory")
	}
	return filepath.Clean(resolved), info, nil
}

func canonicalSocket(raw string) (string, error) {
	if raw == "" || !filepath.IsAbs(raw) || filepath.Clean(raw) != raw || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("absolute clean socket path required")
	}
	original, err := os.Lstat(raw)
	if err != nil || original.Mode()&os.ModeSymlink != 0 || original.Mode()&os.ModeSocket == 0 {
		return "", errors.New("Unix socket required")
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("resolve socket")
	}
	info, err := os.Stat(resolved)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return "", errors.New("Unix socket required")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("runner-owned Unix socket required")
	}
	parentInfo, err := os.Lstat(filepath.Dir(resolved))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("private socket parent required")
	}
	if stat, ok := parentInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("runner-owned socket parent required")
	}
	return filepath.Clean(resolved), nil
}

func findExecutable(name string) (string, error) {
	if name == "" || filepath.Base(name) != name || strings.IndexByte(name, 0) >= 0 {
		return "", errors.New("executable unavailable")
	}
	for _, directory := range trustedExecutableDirectories {
		if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
			continue
		}
		candidate := filepath.Join(directory, name)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || !filepath.IsAbs(resolved) {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		return filepath.Clean(resolved), nil
	}
	return "", errors.New("executable unavailable")
}

func validateSandboxExecutable(executable, rootfs, workspace, workspaceTarget string, mounts []resolvedMount) error {
	for _, mount := range mounts {
		if !isAtOrBelow(executable, mount.target) {
			continue
		}
		return statMappedExecutable(executable, mount.target, mount.source, mount.info)
	}
	if isAtOrBelow(executable, workspaceTarget) {
		workspaceInfo, err := os.Stat(workspace)
		if err != nil {
			return err
		}
		return statMappedExecutable(executable, workspaceTarget, workspace, workspaceInfo)
	}
	// These rootfs locations are hidden by private tmpfs mounts. An executable
	// there is valid only when an explicit mount or the workspace above provides
	// it in the final sandbox view.
	if isAtOrBelow(executable, "/tmp") || isAtOrBelow(executable, "/home") {
		return errors.New("executable is hidden by a private filesystem")
	}
	rootInfo, err := os.Stat(rootfs)
	if err != nil {
		return err
	}
	return statMappedExecutable(executable, "/", rootfs, rootInfo)
}

func statMappedExecutable(executable, target, source string, sourceInfo os.FileInfo) error {
	relative := strings.TrimPrefix(executable, target)
	relative = strings.TrimPrefix(relative, "/")
	if !sourceInfo.IsDir() {
		if relative != "" || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode().Perm()&0o111 == 0 {
			return errors.New("not an executable regular file")
		}
		return nil
	}
	if relative == "" {
		return errors.New("executable names a directory")
	}
	root, err := os.OpenRoot(source)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Stat(filepath.FromSlash(relative))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("not an executable regular file")
	}
	return nil
}

func sandboxEnvironment(profile Profile, supplied []string, hiveAgent string) ([]string, error) {
	canonicalListen, err := canonicalLoopbackListen(profile.BrokerListen)
	if err != nil || canonicalListen != profile.BrokerListen {
		return nil, invalidLaunch("sandbox broker listener is unsafe")
	}
	values := make(map[string]string, len(supplied))
	for _, item := range supplied {
		name, value, ok := strings.Cut(item, "=")
		if !ok || !validEnvironmentName(name) || strings.IndexByte(value, 0) >= 0 {
			return nil, invalidLaunch("supplied environment is malformed")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, invalidLaunch("supplied environment contains duplicate names")
		}
		values[name] = value
	}

	result := map[string]string{
		"HOME":           sandboxHome,
		"FORCEFIELD_URL": "http://" + profile.BrokerListen,
	}
	if profile.Hive.Enabled() {
		result["HIVE_ADDR"] = "http://" + profile.BrokerListen + HiveBrokerPrefix
		result["HIVE_NET"] = profile.Hive.Network
		result["HIVE_AGENT"] = hiveAgent
		// Hive's existing client insists on a bearer variable. This value is a
		// non-secret loopback marker; the host proxy discards it and injects the
		// real personal MSG token only on an approved Hive request.
		result["HIVE_TOKEN"] = sandboxCredentialPlaceholder
	}
	configured := make(map[string]struct{}, len(profile.Environment.Inherit)+len(profile.Environment.Set))
	for _, name := range profile.Environment.Inherit {
		if !validEnvironmentName(name) || reservedEnvironmentName(name) || secretBearingEnvironmentName(name) {
			return nil, invalidLaunch("inherited environment name is unsafe")
		}
		if _, duplicate := configured[name]; duplicate {
			return nil, invalidLaunch("configured environment contains duplicate names")
		}
		configured[name] = struct{}{}
		if value, ok := values[name]; ok {
			result[name] = value
		}
	}
	for name, value := range profile.Environment.Set {
		if !safeStaticEnvironment(name, value) {
			return nil, invalidLaunch("static environment is unsafe")
		}
		if _, duplicate := configured[name]; duplicate {
			return nil, invalidLaunch("configured environment contains duplicate names")
		}
		configured[name] = struct{}{}
		result[name] = value
	}

	names := make([]string, 0, len(result))
	for name := range result {
		names = append(names, name)
	}
	sort.Strings(names)
	environment := make([]string, 0, len(names))
	for _, name := range names {
		environment = append(environment, name+"="+result[name])
	}
	return environment, nil
}

func reservedEnvironmentName(name string) bool {
	if strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
		return true
	}
	switch name {
	case "HOME", "FORCEFIELD_URL", "HIVE_ADDR", "HIVE_NET", "HIVE_AGENT", "HIVE_TOKEN", "HIVE_CONTROL_TOKEN", "HIVE_CONTROL_HOST", "GLIBC_TUNABLES":
		return true
	default:
		return false
	}
}

func cleanSandboxPath(raw string) (string, error) {
	if raw == "" || raw[0] != '/' || path.Clean(raw) != raw || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("absolute clean sandbox path required")
	}
	return raw, nil
}

func sandboxPathsOverlap(left, right string) bool {
	return isAtOrBelow(left, right) || isAtOrBelow(right, left)
}

func isAtOrBelow(candidate, base string) bool {
	return candidate == base || base != "/" && strings.HasPrefix(candidate, base+"/") || base == "/" && strings.HasPrefix(candidate, "/")
}

func hostPathsOverlap(left, right string) bool {
	return hostPathWithin(left, right) || hostPathWithin(right, left)
}

func hostPathWithin(candidate, base string) bool {
	relative, err := filepath.Rel(base, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func invalidLaunch(reason string) error {
	return fmt.Errorf("runner: invalid bubblewrap launch: %s", reason)
}
