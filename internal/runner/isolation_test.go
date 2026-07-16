package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOperatorFileRejectsWorkspaceAndSymlinkAncestry(t *testing.T) {
	base := realTempDir(t)
	workspace := filepath.Join(base, "workspace")
	configDirectory := filepath.Join(base, "config")
	for _, directory := range []string{workspace, configDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	trusted := filepath.Join(configDirectory, "runner.yaml")
	if err := os.WriteFile(trusted, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOperatorFile(trusted, workspace); err != nil {
		t.Fatalf("trusted operator file: %v", err)
	}
	inside := filepath.Join(workspace, "runner.yaml")
	if err := os.WriteFile(inside, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOperatorFile(inside, workspace); err == nil {
		t.Fatal("workspace-owned operator file was accepted")
	}
	link := filepath.Join(base, "config-link")
	if err := os.Symlink(configDirectory, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOperatorFile(filepath.Join(link, "runner.yaml"), workspace); err == nil {
		t.Fatal("symlink ancestry was accepted")
	}
}

func TestValidateHostIsolationRejectsProtectedMountExposure(t *testing.T) {
	base := realTempDir(t)
	workspaceDirectory := mkdirPrivate(t, filepath.Join(base, "workspaces"))
	rootfsDirectory := mkdirPrivate(t, filepath.Join(base, "rootfiles"))
	mountDirectory := mkdirPrivate(t, filepath.Join(base, "mounts"))
	workspace := mkdirPrivate(t, filepath.Join(workspaceDirectory, "worker"))
	rootfs := mkdirPrivate(t, filepath.Join(rootfsDirectory, "debian"))
	state := mkdirPrivate(t, filepath.Join(base, "state"))
	configDirectory := mkdirPrivate(t, filepath.Join(base, "config"))
	configPath := filepath.Join(configDirectory, "forcefield.yaml")
	adminSocket := filepath.Join(configDirectory, "admin.sock")
	if err := os.WriteFile(configPath, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminSocket, []byte("socket fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseSpec := HostIsolationSpec{
		Profile: Profile{RootFS: rootfs}, Workspace: workspace, StateDirectory: state,
		RootFSDirectory: rootfsDirectory, WorkspaceDirectory: workspaceDirectory,
		ReadOnlySourceDirectories: []string{mountDirectory, state, configDirectory},
		OperatorFiles:             []string{configPath}, SensitivePaths: []string{adminSocket},
	}
	if err := ValidateHostIsolation(baseSpec); err != nil {
		t.Fatalf("isolated layout: %v", err)
	}
	for name, source := range map[string]string{
		"admin socket parent": configDirectory,
		"runner state":        state,
	} {
		t.Run(name, func(t *testing.T) {
			spec := baseSpec
			spec.Profile.ReadOnlyMounts = []Mount{{Source: source, Target: "/opt/exposed"}}
			if err := ValidateHostIsolation(spec); err == nil {
				t.Fatal("protected host path was accepted")
			}
		})
	}
}

func TestValidateHostIsolationRejectsRootsOutsideTrustedLayout(t *testing.T) {
	base := realTempDir(t)
	workspaceDirectory := mkdirPrivate(t, filepath.Join(base, "workspaces"))
	rootfsDirectory := mkdirPrivate(t, filepath.Join(base, "rootfiles"))
	mountDirectory := mkdirPrivate(t, filepath.Join(base, "mounts"))
	workspace := mkdirPrivate(t, filepath.Join(workspaceDirectory, "worker"))
	rootfs := mkdirPrivate(t, filepath.Join(rootfsDirectory, "debian"))
	state := mkdirPrivate(t, filepath.Join(base, "state"))
	operatorDirectory := mkdirPrivate(t, filepath.Join(base, "operator"))
	operatorFile := filepath.Join(operatorDirectory, "runner.yaml")
	if err := os.WriteFile(operatorFile, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseSpec := HostIsolationSpec{
		Profile: Profile{RootFS: rootfs}, Workspace: workspace, StateDirectory: state,
		RootFSDirectory: rootfsDirectory, WorkspaceDirectory: workspaceDirectory,
		ReadOnlySourceDirectories: []string{mountDirectory}, OperatorFiles: []string{operatorFile},
	}
	outsideWorkspace := mkdirPrivate(t, filepath.Join(base, "outside-workspace"))
	outsideMount := mkdirPrivate(t, filepath.Join(base, "outside-mount"))
	rootfsLink := filepath.Join(base, "rootfiles-link")
	if err := os.Symlink(rootfsDirectory, rootfsLink); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*HostIsolationSpec)
	}{
		{"workspace outside base", func(spec *HostIsolationSpec) { spec.Workspace = outsideWorkspace }},
		{"rootfs equals base", func(spec *HostIsolationSpec) { spec.Profile.RootFS = rootfsDirectory }},
		{"symlinked rootfs base", func(spec *HostIsolationSpec) { spec.RootFSDirectory = rootfsLink }},
		{"mount outside source roots", func(spec *HostIsolationSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: outsideMount, Target: "/opt/tools"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := baseSpec
			test.mutate(&spec)
			if err := ValidateHostIsolation(spec); err == nil {
				t.Fatal("untrusted host layout was accepted")
			}
		})
	}
}

func realTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func mkdirPrivate(t *testing.T, path string) string {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
