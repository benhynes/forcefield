package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validRunnerConfig = `
version: 1
state_directory: /var/lib/forcefield-runner
rootfs_directory: /var/lib/forcefield-runner-rootfs
workspace_directory: /srv/forcefield-runner-workspaces
profiles:
  execution_worker:
    role: execution_worker
    workload: ip:127.0.0.1
    forcefield_url: https://forcefield.example
    rootfs: /var/lib/forcefield-runner-rootfs/debian
`

const fullRunnerConfig = `
version: 1
state_directory: /var/lib/forcefield-runner
rootfs_directory: /var/lib/forcefield-runner-rootfs
workspace_directory: /srv/forcefield-runner-workspaces
read_only_source_directories: [/opt/forcefield]
profiles:
  execution_worker:
    backend: bubblewrap
    role: execution_worker
    workload: mtls-spki:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    token_ttl: 30m
    forcefield_url: http://127.0.0.1:7902/
    ca_cert: /etc/forcefield/ca.pem
    client_cert: /etc/forcefield/client.pem
    client_key: /etc/forcefield/client-key.pem
    rootfs: /var/lib/forcefield-runner-rootfs/debian
    workspace_target: /workspace
    workspace_read_only: true
    broker_socket: /run/forcefield/worker.sock
    broker_listen: "[::1]:7902"
    read_only_mounts:
      - source: /opt/forcefield/tools
        target: /opt/tools
    environment:
      inherit: [PATH, LANG]
      set:
        TERM: xterm-256color
        OPENAI_BASE_URL: http://127.0.0.1:7902/openai
        OPENAI_API_KEY: forcefield-runner-broker
    hive:
      url: http://127.0.0.1:7777/
      network: dev
      allow_to: [linear-lead@debian-dev, reviewer]
      allow_kinds: [msg, answer]
      allow_discovery: true
    resources:
      memory_max_bytes: 4294967296
      tasks_max: 256
      cpu_quota_percent: 200
      wall_time: 90m
`

func TestDecodeAppliesConservativeDefaults(t *testing.T) {
	t.Parallel()
	config, err := Decode(strings.NewReader(validRunnerConfig))
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != 1 || config.StateDirectory != "/var/lib/forcefield-runner" || config.RootFSDirectory != "/var/lib/forcefield-runner-rootfs" || config.WorkspaceDirectory != "/srv/forcefield-runner-workspaces" {
		t.Fatalf("config = %#v", config)
	}
	profile, err := config.Profile("execution_worker")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Backend != "bubblewrap" || profile.TokenTTL.Value() != time.Hour {
		t.Fatalf("identity defaults = %#v", profile)
	}
	if !profile.WorkspaceReadOnly {
		t.Fatal("workspace is writable without an explicit opt-in")
	}
	if profile.WorkspaceTarget != defaultWorkspaceTarget || profile.BrokerSocket != defaultBrokerSocket || profile.BrokerListen != defaultBrokerListen {
		t.Fatalf("sandbox defaults = %#v", profile)
	}
	if profile.Resources.MemoryMaxBytes != 8<<30 || profile.Resources.TasksMax != 512 || profile.Resources.CPUQuotaPercent != 400 || profile.Resources.WallTime.Value() != 2*time.Hour {
		t.Fatalf("resource defaults = %#v", profile.Resources)
	}
	if _, err := config.Profile("missing"); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("missing profile error = %v", err)
	}
}

func TestDecodeAcceptsAndCanonicalizesCompleteProfile(t *testing.T) {
	t.Parallel()
	config, err := Decode(strings.NewReader(fullRunnerConfig))
	if err != nil {
		t.Fatal(err)
	}
	profile := config.Profiles["execution_worker"]
	if profile.ForcefieldURL != "http://127.0.0.1:7902" {
		t.Fatalf("forcefield URL = %q", profile.ForcefieldURL)
	}
	if profile.BrokerListen != "[::1]:7902" || !profile.WorkspaceReadOnly {
		t.Fatalf("sandbox fields = %#v", profile)
	}
	if profile.TokenTTL.Value() != 30*time.Minute || profile.Resources.WallTime.Value() != 90*time.Minute {
		t.Fatalf("durations = %v, %v", profile.TokenTTL.Value(), profile.Resources.WallTime.Value())
	}
	if len(profile.ReadOnlyMounts) != 1 || profile.ReadOnlyMounts[0].Target != "/opt/tools" || profile.Environment.Set["TERM"] != "xterm-256color" || profile.Environment.Set["OPENAI_API_KEY"] != sandboxCredentialPlaceholder {
		t.Fatalf("mount/environment = %#v / %#v", profile.ReadOnlyMounts, profile.Environment)
	}
	if profile.Hive.URL != "http://127.0.0.1:7777" || profile.Hive.Network != "dev" || len(profile.Hive.AllowTo) != 2 || !profile.Hive.AllowDiscovery {
		t.Fatalf("hive policy = %#v", profile.Hive)
	}
}

func TestProfileReturnsDeepCopy(t *testing.T) {
	t.Parallel()
	config, err := Decode(strings.NewReader(fullRunnerConfig))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := config.Profile("execution_worker")
	if err != nil {
		t.Fatal(err)
	}
	profile.Environment.Inherit[0] = "SHELL"
	profile.Environment.Set["TERM"] = "changed"
	profile.ReadOnlyMounts[0].Target = "/changed"
	profile.Hive.AllowTo[0] = "changed"
	profile.Hive.AllowKinds[0] = "changed"
	original := config.Profiles["execution_worker"]
	if original.Environment.Inherit[0] != "PATH" || original.Environment.Set["TERM"] != "xterm-256color" || original.ReadOnlyMounts[0].Target != "/opt/tools" {
		t.Fatal("resolved profile aliases configuration storage")
	}
	if original.Hive.AllowTo[0] != "linear-lead@debian-dev" || original.Hive.AllowKinds[0] != "msg" {
		t.Fatal("resolved Hive policy aliases configuration storage")
	}
}

func TestProfileDigestIsDeterministicAndSemantic(t *testing.T) {
	t.Parallel()
	config, err := Decode(strings.NewReader(fullRunnerConfig))
	if err != nil {
		t.Fatal(err)
	}
	profile := config.Profiles["execution_worker"]
	first, err := ProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("digest = %q", first)
	}
	reordered := cloneProfile(profile)
	reordered.Environment.Inherit[0], reordered.Environment.Inherit[1] = reordered.Environment.Inherit[1], reordered.Environment.Inherit[0]
	reordered.Environment.Set = map[string]string{
		"TERM": "xterm-256color", "OPENAI_BASE_URL": "http://127.0.0.1:7902/openai", "OPENAI_API_KEY": sandboxCredentialPlaceholder,
	}
	reordered.Hive.AllowTo[0], reordered.Hive.AllowTo[1] = reordered.Hive.AllowTo[1], reordered.Hive.AllowTo[0]
	reordered.Hive.AllowKinds[0], reordered.Hive.AllowKinds[1] = reordered.Hive.AllowKinds[1], reordered.Hive.AllowKinds[0]
	second, err := ProfileDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("equivalent profile digest changed: %q != %q", second, first)
	}
	if reordered.Environment.Inherit[0] != "LANG" {
		t.Fatal("digest mutated its input")
	}
	changed := cloneProfile(profile)
	changed.Resources.TasksMax++
	third, err := ProfileDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("authority-affecting change did not change digest")
	}
	changed.RootFS = "/"
	if _, err := ProfileDigest(changed); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid profile digest error = %v", err)
	}
}

func TestDecodeHiveDefaultsAndRejectsUnsafePolicy(t *testing.T) {
	t.Parallel()
	withHive := replaceOne(validRunnerConfig, "    rootfs:", `    hive:
      url: http://127.0.0.1:7777
      network: dev
      allow_to: [lead@vm1]
    rootfs:`)
	config, err := Decode(strings.NewReader(withHive))
	if err != nil {
		t.Fatal(err)
	}
	profile := config.Profiles["execution_worker"]
	if got := strings.Join(profile.Hive.AllowKinds, ","); got != "msg,ask,answer" {
		t.Fatalf("default Hive kinds = %q", got)
	}
	tests := map[string]string{
		"plaintext remote Hive": replaceOne(withHive, "http://127.0.0.1:7777", "http://hive.example:7777"),
		"Hive URL path":         replaceOne(withHive, "http://127.0.0.1:7777", "http://127.0.0.1:7777/api"),
		"missing Hive network":  replaceOne(withHive, "      network: dev\n", ""),
		"broadcast in allow_to": replaceOne(withHive, "lead@vm1", "@all"),
		"invalid recipient":     replaceOne(withHive, "lead@vm1", "Lead@vm1"),
		"duplicate recipient":   replaceOne(withHive, "[lead@vm1]", "[lead@vm1, lead@vm1]"),
		"invalid kind":          replaceOne(withHive, "      allow_to: [lead@vm1]", "      allow_to: [lead@vm1]\n      allow_kinds: [control]"),
		"Hive fields sans URL":  replaceOne(withHive, "      url: http://127.0.0.1:7777\n", ""),
	}
	assertInvalidConfigs(t, tests)
}

func TestDecodeIsStrictAndBounded(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"unknown top-level field": strings.Replace(validRunnerConfig, "version: 1", "version: 1\ntypo: true", 1),
		"unknown profile field":   strings.Replace(validRunnerConfig, "    role:", "    typo: true\n    role:", 1),
		"multiple documents":      validRunnerConfig + "\n---\nversion: 1\n",
		"empty second document":   validRunnerConfig + "\n---\n",
		"duplicate field":         strings.Replace(validRunnerConfig, "    role: execution_worker", "    role: execution_worker\n    role: other", 1),
		"wrong version":           strings.Replace(validRunnerConfig, "version: 1", "version: 2", 1),
		"relative state":          strings.Replace(validRunnerConfig, "state_directory: /var/lib/forcefield-runner", "state_directory: var/lib/forcefield-runner", 1),
		"missing rootfs base":     strings.Replace(validRunnerConfig, "rootfs_directory: /var/lib/forcefield-runner-rootfs\n", "", 1),
		"unsafe workspace base":   strings.Replace(validRunnerConfig, "/srv/forcefield-runner-workspaces", "/home/agent/workspaces", 1),
		"overlapping directories": strings.Replace(validRunnerConfig, "/srv/forcefield-runner-workspaces", "/var/lib/forcefield-runner/subdir", 1),
		"no profiles":             "version: 1\nstate_directory: /var/lib/forcefield-runner\nrootfs_directory: /var/lib/forcefield-runner-rootfs\nworkspace_directory: /srv/forcefield-runner-workspaces\nprofiles: {}\n",
	}
	for name, input := range tests {
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Decode(strings.NewReader(input)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := Decode(strings.NewReader(strings.Repeat(" ", maxConfigBytes+1))); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversize error = %v", err)
	}
	if _, err := Decode(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil reader error = %v", err)
	}
}

func TestDecodeRejectsUnsafeIdentityAndAuthority(t *testing.T) {
	t.Parallel()
	mtlsConfig := replaceOne(validRunnerConfig, "ip:127.0.0.1", "mtls-spki:"+strings.Repeat("a", 64))
	mtlsConfig = addProfileField(mtlsConfig, "client_cert: /etc/client.pem\n    client_key: /etc/client-key.pem")
	tests := map[string]string{
		"unsafe profile name": replaceOne(validRunnerConfig, "execution_worker:", "ExecutionWorker:"),
		"unsafe role":         replaceOne(validRunnerConfig, "role: execution_worker", "role: ExecutionWorker"),
		"unsupported backend": replaceOne(validRunnerConfig, "    role:", "    backend: docker\n    role:"),
		"noncanonical ipv4":   replaceOne(validRunnerConfig, "ip:127.0.0.1", "ip:127.000.000.001"),
		"noncanonical ipv6":   replaceOne(validRunnerConfig, "ip:127.0.0.1", "ip:2001:0db8::1"),
		"uppercase spki":      replaceOne(mtlsConfig, strings.Repeat("a", 64), strings.Repeat("A", 64)),
		"zero token TTL":      replaceOne(validRunnerConfig, "    forcefield_url:", "    token_ttl: 0s\n    forcefield_url:"),
		"excessive token TTL": replaceOne(validRunnerConfig, "    forcefield_url:", "    token_ttl: 169h\n    forcefield_url:"),
		"rootfs outside base": replaceOne(validRunnerConfig, "/var/lib/forcefield-runner-rootfs/debian", "/opt/rootfs/debian"),
	}
	assertInvalidConfigs(t, tests)
}

func TestDecodeRejectsUnsafeForcefieldEndpointAndCredentials(t *testing.T) {
	t.Parallel()
	mtlsWithoutCert := replaceOne(validRunnerConfig, "ip:127.0.0.1", "mtls-spki:"+strings.Repeat("a", 64))
	tests := map[string]string{
		"plaintext remote":        replaceOne(validRunnerConfig, "https://forcefield.example", "http://forcefield.example"),
		"URL path":                replaceOne(validRunnerConfig, "https://forcefield.example", "https://forcefield.example/api"),
		"URL query":               replaceOne(validRunnerConfig, "https://forcefield.example", "https://forcefield.example?debug=1"),
		"URL credentials":         replaceOne(validRunnerConfig, "https://forcefield.example", "https://agent:secret@forcefield.example"),
		"invalid URL port":        replaceOne(validRunnerConfig, "https://forcefield.example", "https://forcefield.example:00080"),
		"client cert without key": replaceOne(validRunnerConfig, "    rootfs:", "    client_cert: /etc/client.pem\n    rootfs:"),
		"mTLS without identity":   mtlsWithoutCert,
		"IP with client identity": addProfileField(validRunnerConfig, "client_cert: /etc/client.pem\n    client_key: /etc/client-key.pem"),
		"relative credential":     replaceOne(validRunnerConfig, "    rootfs:", "    ca_cert: etc/ca.pem\n    rootfs:"),
	}
	assertInvalidConfigs(t, tests)
}

func TestDecodeRejectsUnsafeSandboxPathsAndListen(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"host root rootfs":       replaceOne(validRunnerConfig, "/var/lib/forcefield-runner-rootfs/debian", "/"),
		"relative rootfs":        replaceOne(validRunnerConfig, "/var/lib/forcefield-runner-rootfs/debian", "rootfs/debian"),
		"unclean rootfs":         replaceOne(validRunnerConfig, "/var/lib/forcefield-runner-rootfs/debian", "/var/lib/../rootfs/debian"),
		"rootfs equals base":     replaceOne(validRunnerConfig, "/var/lib/forcefield-runner-rootfs/debian", "/var/lib/forcefield-runner-rootfs"),
		"root workspace":         addProfileField(validRunnerConfig, "workspace_target: /"),
		"proc workspace":         addProfileField(validRunnerConfig, "workspace_target: /proc/agent"),
		"run workspace":          addProfileField(validRunnerConfig, "workspace_target: /run/agent"),
		"external broker socket": addProfileField(validRunnerConfig, "broker_socket: /tmp/broker.sock"),
		"broker directory":       addProfileField(validRunnerConfig, "broker_socket: /run/forcefield"),
		"remote broker listen":   addProfileField(validRunnerConfig, "broker_listen: 0.0.0.0:7902"),
		"missing listen port":    addProfileField(validRunnerConfig, "broker_listen: 127.0.0.1"),
	}
	assertInvalidConfigs(t, tests)
}

func TestDecodeRejectsUnsafeMounts(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"relative source":      mountConfig("opt/tools", "/opt/tools", ""),
		"relative target":      mountConfig("/opt/tools", "opt/tools", ""),
		"workspace target":     mountConfig("/opt/tools", "/workspace/tools", ""),
		"workspace ancestor":   mountConfig("/opt/tools", "/", ""),
		"proc target":          mountConfig("/opt/tools", "/proc/tool", ""),
		"dev ancestor":         mountConfig("/opt/tools", "/dev", ""),
		"broker ancestor":      mountConfig("/opt/tools", "/run/forcefield", ""),
		"run target":           mountConfig("/opt/tools", "/run/tool", ""),
		"duplicate target":     mountConfig("/opt/tools", "/opt/tools", "      - source: /opt/other\n        target: /opt/tools\n"),
		"source outside roots": replaceOne(fullRunnerConfig, "/opt/forcefield/tools", "/srv/unapproved/tools"),
	}
	assertInvalidConfigs(t, tests)
}

func TestDecodeRejectsUnsafeEnvironment(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"invalid name":             environmentConfig("inherit: [BAD-NAME]"),
		"duplicate inherited name": environmentConfig("inherit: [PATH, PATH]"),
		"duplicate set target":     environmentConfig("inherit: [PATH]\n      set: {PATH: /bin}"),
		"inherited token":          environmentConfig("inherit: [GITHUB_TOKEN]"),
		"set secret":               environmentConfig("set: {CLIENT_SECRET: literal}"),
		"set password":             environmentConfig("set: {db_password: literal}"),
		"set credentials":          environmentConfig("set: {CREDENTIALS_FILE: /tmp/file}"),
		"set auth":                 environmentConfig("set: {AUTHORS: literal}"),
		"set API key":              environmentConfig("set: {SERVICE_API_KEY: literal}"),
		"set Forcefield":           environmentConfig("set: {FORCEFIELD_URL: literal}"),
		"set reserved home":        environmentConfig("set: {HOME: /host/home}"),
		"inherited loader":         environmentConfig("inherit: [LD_PRELOAD]"),
		"set loader":               environmentConfig("set: {LD_LIBRARY_PATH: /workspace/lib}"),
		"glibc tunables":           environmentConfig("set: {GLIBC_TUNABLES: glibc.malloc.check=0}"),
		"inherited tmux":           environmentConfig("inherit: [TMUX]"),
	}
	assertInvalidConfigs(t, tests)
}

func TestDecodeAllowsOnlyFixedCredentialPlaceholder(t *testing.T) {
	t.Parallel()
	input := environmentConfig("set: {OPENAI_BASE_URL: 'http://127.0.0.1:7902/openai', OPENAI_API_KEY: forcefield-runner-broker}")
	config, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Profiles["execution_worker"].Environment.Set["OPENAI_API_KEY"]; got != sandboxCredentialPlaceholder {
		t.Fatalf("credential placeholder = %q", got)
	}
	reserved := environmentConfig("set: {HIVE_TOKEN: forcefield-runner-broker}")
	if _, err := Decode(strings.NewReader(reserved)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("reserved placeholder error = %v", err)
	}
}

func TestDecodeRejectsUnsafeResourceBounds(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"zero memory":         resourceConfig("memory_max_bytes: 0"),
		"small memory":        resourceConfig("memory_max_bytes: 67108863"),
		"huge memory":         resourceConfig("memory_max_bytes: 1099511627777"),
		"zero tasks":          resourceConfig("tasks_max: 0"),
		"too many tasks":      resourceConfig("tasks_max: 65537"),
		"zero CPU":            resourceConfig("cpu_quota_percent: 0"),
		"too much CPU":        resourceConfig("cpu_quota_percent: 10001"),
		"zero wall time":      resourceConfig("wall_time: 0s"),
		"excessive wall time": resourceConfig("wall_time: 169h"),
	}
	assertInvalidConfigs(t, tests)
}

func TestLoadEnforcesFileSafety(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "runner.yaml")
	if err := os.WriteFile(path, []byte(validRunnerConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("safe load: %v", err)
	}

	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("group-writable error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(directory, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("symlink error = %v", err)
	}

	oversize := filepath.Join(directory, "oversize.yaml")
	if err := os.WriteFile(oversize, []byte(strings.Repeat(" ", maxConfigBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(oversize); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversize file error = %v", err)
	}
}

func assertInvalidConfigs(t *testing.T, tests map[string]string) {
	t.Helper()
	for name, input := range tests {
		input := input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Decode(strings.NewReader(input)); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v\nconfig:\n%s", err, input)
			}
		})
	}
}

func replaceOne(input, old, replacement string) string {
	if strings.Count(input, old) != 1 {
		panic(fmt.Sprintf("replacement source %q occurs %d times", old, strings.Count(input, old)))
	}
	return strings.Replace(input, old, replacement, 1)
}

func addProfileField(input, field string) string {
	return replaceOne(input, "    rootfs:", "    "+field+"\n    rootfs:")
}

func mountConfig(source, target, additional string) string {
	return replaceOne(validRunnerConfig, "    rootfs:", fmt.Sprintf("    read_only_mounts:\n      - source: %s\n        target: %s\n%s    rootfs:", source, target, additional))
}

func environmentConfig(body string) string {
	return replaceOne(validRunnerConfig, "    rootfs:", "    environment:\n      "+body+"\n    rootfs:")
}

func resourceConfig(body string) string {
	return replaceOne(validRunnerConfig, "    rootfs:", "    resources:\n      "+body+"\n    rootfs:")
}
