package runner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// HostIsolationSpec describes host paths that must remain outside every
// filesystem exposed to an untrusted sandbox. OperatorFiles are policy inputs;
// SensitivePaths contain sockets, keys, stores, and helpers with host
// authority. StateDirectory contains the per-run broker socket.
type HostIsolationSpec struct {
	Profile                   Profile
	Workspace                 string
	StateDirectory            string
	RootFSDirectory           string
	WorkspaceDirectory        string
	ReadOnlySourceDirectories []string
	OperatorFiles             []string
	SensitivePaths            []string
}

// ValidateOperatorFile checks a configuration file before parsing it. The
// complete path must be symlink-free, owner-controlled, and outside the
// writable workspace. This prevents a worker from rewriting policy for its
// next Hive launch.
func ValidateOperatorFile(path, workspace string) error {
	if !cleanAbsolutePath(path) || !cleanAbsolutePath(workspace) || hostPathWithin(path, workspace) {
		return errors.New("runner operator file must be an absolute trusted path outside the workspace")
	}
	if err := validateTrustedPath(path, true); err != nil {
		return errors.New("runner operator file path is unsafe")
	}
	return nil
}

// ValidateHostIsolation rejects any mount layout that would expose runner or
// Forcefield host authority. All inputs must already exist so symlinks can be
// resolved before the token is minted.
func ValidateHostIsolation(spec HostIsolationSpec) error {
	rootfsDirectory, err := canonicalTrustedDirectory(spec.RootFSDirectory)
	if err != nil {
		return errors.New("runner rootfs directory is unsafe")
	}
	workspaceDirectory, err := canonicalTrustedDirectory(spec.WorkspaceDirectory)
	if err != nil {
		return errors.New("runner workspace directory is unsafe")
	}
	readOnlyDirectories := make([]string, 0, len(spec.ReadOnlySourceDirectories))
	for _, directory := range spec.ReadOnlySourceDirectories {
		resolved, err := canonicalTrustedDirectory(directory)
		if err != nil {
			return errors.New("runner read-only source directory is unsafe")
		}
		readOnlyDirectories = append(readOnlyDirectories, resolved)
	}
	workspace, err := canonicalTrustedDirectory(spec.Workspace)
	if err != nil || workspace != spec.Workspace || !strictlyWithin(workspace, workspaceDirectory) {
		return errors.New("runner workspace is unsafe")
	}
	rootfs, err := canonicalTrustedDirectory(spec.Profile.RootFS)
	if err != nil || !strictlyWithin(rootfs, rootfsDirectory) {
		return errors.New("runner root filesystem is unsafe")
	}
	exposed := []string{workspace, rootfs}
	for _, mount := range spec.Profile.ReadOnlyMounts {
		source, info, err := canonicalMountSource(mount.Source)
		if err != nil {
			return errors.New("runner read-only mount source is unsafe")
		}
		if validateTrustedPath(source, info.Mode().IsRegular()) != nil {
			return errors.New("runner read-only mount source has unsafe ancestry or permissions")
		}
		if !withinAny(source, readOnlyDirectories) {
			return errors.New("runner read-only mount source is outside the trusted directories")
		}
		exposed = append(exposed, source)
	}

	stateDirectory, err := canonicalTrustedDirectory(spec.StateDirectory)
	if err != nil {
		return errors.New("runner state directory is unsafe")
	}
	protected := []string{stateDirectory}
	for _, path := range spec.OperatorFiles {
		resolved, err := canonicalExistingPath(path)
		if err != nil {
			return errors.New("runner operator file is unavailable")
		}
		protected = append(protected, resolved)
	}
	for _, path := range spec.SensitivePaths {
		if path == "" {
			continue
		}
		resolved, err := canonicalExistingPath(path)
		if err != nil {
			return errors.New("runner sensitive host path is unavailable")
		}
		protected = append(protected, resolved)
	}
	for _, authority := range protected {
		for _, source := range exposed {
			if hostPathsOverlap(authority, source) {
				return errors.New("runner sandbox mount exposes a protected host path")
			}
		}
	}
	return nil
}

func canonicalTrustedDirectory(path string) (string, error) {
	resolved, err := canonicalDirectory(path, true)
	if err != nil || resolved != path || validateTrustedPath(path, false) != nil {
		return "", errors.New("trusted directory required")
	}
	return resolved, nil
}

func canonicalExistingPath(path string) (string, error) {
	if !cleanAbsolutePath(path) {
		return "", errors.New("absolute clean path required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("resolve path")
	}
	return filepath.Clean(resolved), nil
}

func validateTrustedPath(path string, finalRegular bool) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
	if !strings.HasPrefix(remainder, string(filepath.Separator)) {
		return errors.New("absolute path required")
	}
	current := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(remainder, string(filepath.Separator)), string(filepath.Separator))
	if info, err := os.Lstat(current); err != nil || !trustedPathComponent(info, false) {
		return errors.New("unsafe filesystem root")
	}
	for index, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		last := index == len(parts)-1
		if err != nil || !trustedPathComponent(info, finalRegular && last) {
			return errors.New("unsafe path component")
		}
	}
	return nil
}

func trustedPathComponent(info os.FileInfo, regular bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if regular {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
	} else if !info.IsDir() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	if !regular && info.Mode().Perm()&0o022 != 0 {
		// A root-owned sticky directory (normally /tmp) cannot have another
		// user's private child renamed out from underneath it.
		return stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
	}
	return true
}
