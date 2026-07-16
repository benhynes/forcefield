package runner

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestBuildBubblewrapConstructsFailClosedCommand(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	toolchain := filepath.Join(fixture.base, "toolchain")
	if err := os.Mkdir(toolchain, 0o755); err != nil {
		t.Fatal(err)
	}

	profile := fixture.profile()
	profile.ReadOnlyMounts = []Mount{{Source: toolchain, Target: "/opt/toolchain"}}
	profile.Environment = Environment{
		Inherit: []string{"PATH"},
		Set: map[string]string{
			"LANG": "C.UTF-8", "OPENAI_API_KEY": sandboxCredentialPlaceholder,
		},
	}
	spec, err := BuildBubblewrap(LaunchSpec{
		Profile: profile, Workspace: fixture.workspace,
		BrokerHostSocket: fixture.socket,
		Executable:       "/usr/bin/agent",
		Arguments:        []string{"--mode", "--", "literal"},
		Environment: []string{
			"PATH=/usr/local/bin:/usr/bin:/bin",
			"AWS_SECRET_ACCESS_KEY=must-not-survive",
			"UNLISTED=value",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	wantArgs := []string{
		"--die-with-parent",
		"--unshare-all",
		"--unshare-user",
		"--disable-userns",
		"--cap-drop", "ALL",
		"--clearenv",
		"--ro-bind", fixture.rootfs, "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--perms", "0700", "--tmpfs", "/tmp",
		"--perms", "0700", "--tmpfs", "/run",
		"--perms", "0700", "--tmpfs", "/home",
		"--perms", "0700", "--dir", "/home/agent",
		"--bind", fixture.workspace, "/workspace",
		"--perms", "0700", "--dir", "/run/forcefield",
		"--ro-bind", fixture.socket, "/run/forcefield/broker.sock",
		"--ro-bind", toolchain, "/opt/toolchain",
		"--chdir", "/workspace",
		"--setenv", "FORCEFIELD_URL", "http://127.0.0.1:7902",
		"--setenv", "HOME", "/home/agent",
		"--setenv", "LANG", "C.UTF-8",
		"--setenv", "OPENAI_API_KEY", sandboxCredentialPlaceholder,
		"--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--", "/usr/bin/agent", "--mode", "--", "literal",
	}
	if spec.Path != fixture.bwrap {
		t.Fatalf("Path = %q, want %q", spec.Path, fixture.bwrap)
	}
	if !reflect.DeepEqual(spec.Args, wantArgs) {
		t.Fatalf("Args mismatch\n got: %#v\nwant: %#v", spec.Args, wantArgs)
	}
	if spec.Env == nil || len(spec.Env) != 0 {
		t.Fatalf("Env = %#v, want non-nil empty environment", spec.Env)
	}
	joined := strings.Join(spec.Args, "\x00")
	for _, forbidden := range []string{"must-not-survive", "AWS_SECRET_ACCESS_KEY", "UNLISTED=value"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sandbox command leaked %q", forbidden)
		}
	}
}

func TestBuildBubblewrapReadOnlyWorkspaceAndCanonicalPaths(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	rootLink := filepath.Join(fixture.base, "root-link")
	workspaceLink := filepath.Join(fixture.base, "workspace-link")
	if err := os.Symlink(fixture.rootfs, rootLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.workspace, workspaceLink); err != nil {
		t.Fatal(err)
	}
	profile := fixture.profile()
	profile.RootFS = rootLink
	profile.WorkspaceReadOnly = true

	spec, err := BuildBubblewrap(LaunchSpec{
		Profile: profile, Workspace: workspaceLink,
		BrokerHostSocket: fixture.socket,
		Executable:       "/usr/bin/agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !containsArgTriple(spec.Args, "--ro-bind", fixture.rootfs, "/") {
		t.Fatalf("canonical rootfs bind is missing: %#v", spec.Args)
	}
	if !containsArgTriple(spec.Args, "--ro-bind", fixture.workspace, "/workspace") {
		t.Fatalf("canonical read-only workspace bind is missing: %#v", spec.Args)
	}
	if containsArgTriple(spec.Args, "--bind", fixture.workspace, "/workspace") {
		t.Fatalf("writable workspace bind survived read-only profile: %#v", spec.Args)
	}
}

func TestBuildBubblewrapCanRetainTrustedHostNetwork(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	profile := fixture.profile()
	profile.ShareNetwork = true
	spec, err := BuildBubblewrap(LaunchSpec{
		Profile: profile, Workspace: fixture.workspace,
		BrokerHostSocket: fixture.socket,
		Executable:       "/usr/bin/agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Args) < 4 || !reflect.DeepEqual(spec.Args[:4], []string{
		"--die-with-parent", "--unshare-all", "--share-net", "--unshare-user",
	}) {
		t.Fatalf("network namespace args = %#v", spec.Args[:min(4, len(spec.Args))])
	}
}

func TestBuildBubblewrapExposesHiveBrokerWithoutHiveBearer(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	profile := fixture.profile()
	profile.Hive = HiveConfig{
		URL: "http://127.0.0.1:7777", Network: "dev",
		AllowTo: []string{"lead@vm1"}, AllowKinds: []string{"msg"},
	}
	spec, err := BuildBubblewrap(LaunchSpec{
		Profile: profile, Workspace: fixture.workspace, BrokerHostSocket: fixture.socket,
		HiveAgent: "worker@vm1", Executable: "/usr/bin/agent",
		Environment: []string{"HIVE_TOKEN=host-secret", "HIVE_CONTROL_TOKEN=control-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spec.Args, "\x00")
	for _, required := range []string{
		"HIVE_ADDR\x00http://127.0.0.1:7902" + HiveBrokerPrefix,
		"HIVE_NET\x00dev", "HIVE_AGENT\x00worker@vm1", "HIVE_TOKEN\x00forcefield-runner-broker",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("sandbox environment lacks %q: %#v", required, spec.Args)
		}
	}
	for _, forbidden := range []string{"host-secret", "control-secret", "HIVE_CONTROL_TOKEN"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sandbox environment leaked %q", forbidden)
		}
	}
}

func TestBuildBubblewrapValidatesExecutableAgainstMountedView(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	workspaceAgent := filepath.Join(fixture.workspace, "bin", "workspace-agent")
	if err := os.MkdirAll(filepath.Dir(workspaceAgent), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, workspaceAgent)

	_, err := BuildBubblewrap(LaunchSpec{
		Profile: fixture.profile(), Workspace: fixture.workspace,
		BrokerHostSocket: fixture.socket,
		Executable:       "/workspace/bin/workspace-agent",
	})
	if err != nil {
		t.Fatalf("workspace executable was rejected: %v", err)
	}

	if err := os.Chmod(workspaceAgent, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = BuildBubblewrap(LaunchSpec{
		Profile: fixture.profile(), Workspace: fixture.workspace,
		BrokerHostSocket: fixture.socket,
		Executable:       "/workspace/bin/workspace-agent",
	})
	if err == nil {
		t.Fatal("non-executable workspace file was accepted")
	}
}

func TestBuildBubblewrapCanRequireTrustedExecutableFromRootFS(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	workspaceAgent := filepath.Join(fixture.workspace, "bin", "workspace-agent")
	if err := os.MkdirAll(filepath.Dir(workspaceAgent), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, workspaceAgent)
	_, err := BuildBubblewrap(LaunchSpec{
		Profile: fixture.profile(), Workspace: fixture.workspace, BrokerHostSocket: fixture.socket,
		Executable: "/workspace/bin/workspace-agent", RootFSExecutable: true,
	})
	if err == nil {
		t.Fatal("workspace shadowed a trusted rootfs executable")
	}
}

func TestBuildBubblewrapRejectsUnsafeInputs(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	regularSocket := filepath.Join(fixture.base, "not-a-socket")
	if err := os.WriteFile(regularSocket, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	nonExecutable := filepath.Join(fixture.rootfs, "usr", "bin", "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	overlapWorkspace := filepath.Join(fixture.rootfs, "workspace")
	if err := os.Mkdir(overlapWorkspace, 0o755); err != nil {
		t.Fatal(err)
	}

	base := LaunchSpec{
		Profile: fixture.profile(), Workspace: fixture.workspace,
		BrokerHostSocket: fixture.socket,
		Executable:       "/usr/bin/agent",
		Environment:      []string{"PATH=/usr/bin:/bin", "SECRET=value"},
	}
	tests := []struct {
		name   string
		mutate func(*LaunchSpec)
	}{
		{"root filesystem is host root", func(spec *LaunchSpec) { spec.Profile.RootFS = "/" }},
		{"relative workspace", func(spec *LaunchSpec) { spec.Workspace = "workspace" }},
		{"workspace overlaps rootfs", func(spec *LaunchSpec) { spec.Workspace = overlapWorkspace }},
		{"workspace target escapes", func(spec *LaunchSpec) { spec.Profile.WorkspaceTarget = "/workspace/../etc" }},
		{"workspace target shadows run", func(spec *LaunchSpec) { spec.Profile.WorkspaceTarget = "/run/work" }},
		{"broker target outside private run", func(spec *LaunchSpec) { spec.Profile.BrokerSocket = "/tmp/broker.sock" }},
		{"broker target is directory", func(spec *LaunchSpec) { spec.Profile.BrokerSocket = "/run/forcefield" }},
		{"host broker is regular file", func(spec *LaunchSpec) { spec.BrokerHostSocket = regularSocket }},
		{"relative executable", func(spec *LaunchSpec) { spec.Executable = "usr/bin/agent" }},
		{"executable traversal", func(spec *LaunchSpec) { spec.Executable = "/usr/bin/../bin/agent" }},
		{"non-executable file", func(spec *LaunchSpec) { spec.Executable = "/usr/bin/not-executable" }},
		{"proc executable", func(spec *LaunchSpec) { spec.Executable = "/proc/self/exe" }},
		{"mount source is host root", func(spec *LaunchSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: "/", Target: "/opt/host"}}
		}},
		{"mount source exposes broker socket", func(spec *LaunchSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: fixture.base, Target: "/opt/host"}}
		}},
		{"mount shadows proc", func(spec *LaunchSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: fixture.workspace, Target: "/proc/host"}}
		}},
		{"mount shadows workspace", func(spec *LaunchSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: fixture.workspace, Target: "/workspace/tools"}}
		}},
		{"mount shadows private run", func(spec *LaunchSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: fixture.workspace, Target: "/run/user"}}
		}},
		{"directory mounted into home", func(spec *LaunchSpec) {
			spec.Profile.ReadOnlyMounts = []Mount{{Source: fixture.workspace, Target: "/home/agent/config"}}
		}},
		{"secret inherited environment", func(spec *LaunchSpec) {
			spec.Profile.Environment.Inherit = []string{"SECRET"}
		}},
		{"reserved static environment", func(spec *LaunchSpec) {
			spec.Profile.Environment.Set = map[string]string{"HOME": "/host/home"}
		}},
		{"non-loopback broker listener", func(spec *LaunchSpec) { spec.Profile.BrokerListen = "0.0.0.0:7902" }},
		{"NUL argument", func(spec *LaunchSpec) { spec.Arguments = []string{"bad\x00argument"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := cloneLaunchSpec(base)
			test.mutate(&spec)
			if _, err := BuildBubblewrap(spec); err == nil {
				t.Fatal("unsafe launch was accepted")
			}
		})
	}
}

func TestBuildBubblewrapRequiresBwrap(t *testing.T) {
	fixture := newBubblewrapFixture(t)
	useTrustedToolDirectories(t, t.TempDir())
	_, err := BuildBubblewrap(LaunchSpec{
		Profile: fixture.profile(), Workspace: fixture.workspace,
		BrokerHostSocket: fixture.socket,
		Executable:       "/usr/bin/agent",
	})
	if err == nil {
		t.Fatal("launch succeeded without bwrap")
	}
}

type bubblewrapFixture struct {
	base      string
	rootfs    string
	workspace string
	socket    string
	bwrap     string
	listener  net.Listener
}

func newBubblewrapFixture(t *testing.T) bubblewrapFixture {
	t.Helper()
	// Darwin's default TMPDIR is long enough to exceed sockaddr_un once the
	// testing package appends the test name. /tmp is short on both supported
	// development platforms and resolves normally during builder validation.
	base, err := os.MkdirTemp("/tmp", "ff-bwrap-")
	if err != nil {
		t.Fatal(err)
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	rootfs := filepath.Join(base, "rootfs")
	workspace := filepath.Join(base, "workspace")
	for _, directory := range []string{
		filepath.Join(rootfs, "usr", "bin"), workspace, filepath.Join(base, "broker"), filepath.Join(base, "bin"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	agent := filepath.Join(rootfs, "usr", "bin", "agent")
	writeExecutable(t, agent)
	bwrap := filepath.Join(base, "bin", "bwrap")
	writeExecutable(t, bwrap)
	useTrustedToolDirectories(t, filepath.Dir(bwrap))

	socket := filepath.Join(base, "broker", "broker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("test sandbox does not permit AF_UNIX listeners")
		}
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return bubblewrapFixture{
		base: base, rootfs: rootfs, workspace: workspace,
		socket: socket, bwrap: bwrap, listener: listener,
	}
}

func useTrustedToolDirectories(t *testing.T, directories ...string) {
	t.Helper()
	previous := append([]string(nil), trustedExecutableDirectories...)
	trustedExecutableDirectories = append([]string(nil), directories...)
	t.Cleanup(func() { trustedExecutableDirectories = previous })
}

func (fixture bubblewrapFixture) profile() Profile {
	return Profile{
		Backend:         "bubblewrap",
		RootFS:          fixture.rootfs,
		WorkspaceTarget: "/workspace",
		BrokerSocket:    "/run/forcefield/broker.sock",
		BrokerListen:    "127.0.0.1:7902",
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func containsArgTriple(arguments []string, first, second, third string) bool {
	for index := 0; index+2 < len(arguments); index++ {
		if arguments[index] == first && arguments[index+1] == second && arguments[index+2] == third {
			return true
		}
	}
	return false
}

func cloneLaunchSpec(source LaunchSpec) LaunchSpec {
	clone := source
	clone.Arguments = append([]string(nil), source.Arguments...)
	clone.Environment = append([]string(nil), source.Environment...)
	clone.Profile.ReadOnlyMounts = append([]Mount(nil), source.Profile.ReadOnlyMounts...)
	clone.Profile.Environment.Inherit = append([]string(nil), source.Profile.Environment.Inherit...)
	if source.Profile.Environment.Set != nil {
		clone.Profile.Environment.Set = make(map[string]string, len(source.Profile.Environment.Set))
		for name, value := range source.Profile.Environment.Set {
			clone.Profile.Environment.Set[name] = value
		}
	}
	return clone
}
