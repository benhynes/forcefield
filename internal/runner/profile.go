// Package runner defines the trusted configuration boundary for sandboxed
// agent processes. Profiles describe authority selected by an operator; they
// are never supplied or widened by the sandboxed process itself.
package runner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	maxConfigBytes = 1 << 20

	defaultTokenTTL       = time.Hour
	maximumTokenTTL       = 7 * 24 * time.Hour
	defaultMemoryMaxBytes = uint64(8 << 30)
	minimumMemoryMaxBytes = uint64(64 << 20)
	maximumMemoryMaxBytes = uint64(1 << 40)
	defaultTasksMax       = uint64(512)
	maximumTasksMax       = uint64(65_536)
	defaultCPUQuota       = uint64(400)
	maximumCPUQuota       = uint64(10_000)
	defaultWallTime       = 2 * time.Hour
	maximumWallTime       = 7 * 24 * time.Hour

	defaultWorkspaceTarget       = "/workspace"
	defaultBrokerSocket          = "/run/forcefield/broker.sock"
	defaultBrokerListen          = "127.0.0.1:7902"
	brokerDirectory              = "/run/forcefield"
	profileDigestRevision        = "forcefield-runner-profile/v1"
	sandboxCredentialPlaceholder = "forcefield-runner-broker"
)

var (
	// ErrInvalidConfig is returned for malformed, unsafe, or unsupported runner
	// configuration. Error details deliberately do not reproduce configured
	// environment values or credential paths.
	ErrInvalidConfig = errors.New("invalid runner configuration")
	// ErrProfileNotFound is returned when an operator requests a profile that
	// is not present in an otherwise valid configuration.
	ErrProfileNotFound = errors.New("runner profile not found")
)

// Duration is a YAML duration such as "30s" or "2h".
type Duration time.Duration

// UnmarshalText parses a Go duration. Range and non-zero requirements are
// enforced by the field that contains the duration.
func (d *Duration) UnmarshalText(value []byte) error {
	parsed, err := time.ParseDuration(string(value))
	if err != nil || parsed < 0 {
		return errors.New("invalid duration")
	}
	*d = Duration(parsed)
	return nil
}

// MarshalText renders a duration using Go's canonical duration syntax.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// Value returns the duration as a time.Duration.
func (d Duration) Value() time.Duration { return time.Duration(d) }

// Config is the complete runner configuration selected by the trusted host
// operator.
type Config struct {
	Version                   int                `json:"version" yaml:"version"`
	StateDirectory            string             `json:"state_directory" yaml:"state_directory"`
	RootFSDirectory           string             `json:"rootfs_directory" yaml:"rootfs_directory"`
	WorkspaceDirectory        string             `json:"workspace_directory" yaml:"workspace_directory"`
	ReadOnlySourceDirectories []string           `json:"read_only_source_directories,omitempty" yaml:"read_only_source_directories,omitempty"`
	Profiles                  map[string]Profile `json:"profiles" yaml:"profiles"`
}

// Profile describes one bubblewrap sandbox and its narrow Forcefield broker
// identity. Paths ending in Target or Socket are paths inside the sandbox;
// RootFS and credential paths are host paths.
type Profile struct {
	Backend           string      `json:"backend" yaml:"backend"`
	Role              string      `json:"role" yaml:"role"`
	Workload          string      `json:"workload" yaml:"workload"`
	TokenTTL          Duration    `json:"token_ttl" yaml:"token_ttl"`
	TokenFile         string      `json:"token_file,omitempty" yaml:"token_file,omitempty"`
	ForcefieldURL     string      `json:"forcefield_url" yaml:"forcefield_url"`
	CACert            string      `json:"ca_cert,omitempty" yaml:"ca_cert,omitempty"`
	ClientCert        string      `json:"client_cert,omitempty" yaml:"client_cert,omitempty"`
	ClientKey         string      `json:"client_key,omitempty" yaml:"client_key,omitempty"`
	RootFS            string      `json:"rootfs" yaml:"rootfs"`
	WorkspaceTarget   string      `json:"workspace_target" yaml:"workspace_target"`
	BrokerSocket      string      `json:"broker_socket" yaml:"broker_socket"`
	BrokerListen      string      `json:"broker_listen" yaml:"broker_listen"`
	WorkspaceReadOnly bool        `json:"workspace_read_only" yaml:"workspace_read_only"`
	ShareNetwork      bool        `json:"share_network,omitempty" yaml:"share_network,omitempty"`
	ReadOnlyMounts    []Mount     `json:"read_only_mounts,omitempty" yaml:"read_only_mounts,omitempty"`
	Environment       Environment `json:"environment,omitempty" yaml:"environment,omitempty"`
	Hive              HiveConfig  `json:"hive,omitempty" yaml:"hive,omitempty"`
	Resources         Resources   `json:"resources" yaml:"resources"`
}

// Mount maps a host source to a read-only target inside the sandbox.
type Mount struct {
	Source string `json:"source" yaml:"source"`
	Target string `json:"target" yaml:"target"`
}

// Environment is an explicit, secret-free environment allowlist. Inherit
// names are copied from the runner's environment; Set values are literal.
// Credential-shaped Set names may contain only the fixed, non-secret runner
// placeholder required by clients that reject an empty API key.
type Environment struct {
	Inherit []string          `json:"inherit,omitempty" yaml:"inherit,omitempty"`
	Set     map[string]string `json:"set,omitempty" yaml:"set,omitempty"`
}

// HiveConfig is a least-privilege view of Hive messaging. The real personal
// MSG token stays in the host broker; the sandbox receives a loopback endpoint
// and a non-secret placeholder. An empty URL disables in-sandbox Hive access.
type HiveConfig struct {
	URL            string   `json:"url,omitempty" yaml:"url,omitempty"`
	Network        string   `json:"network,omitempty" yaml:"network,omitempty"`
	AllowTo        []string `json:"allow_to,omitempty" yaml:"allow_to,omitempty"`
	AllowKinds     []string `json:"allow_kinds,omitempty" yaml:"allow_kinds,omitempty"`
	AllowBroadcast bool     `json:"allow_broadcast,omitempty" yaml:"allow_broadcast,omitempty"`
	AllowDiscovery bool     `json:"allow_discovery,omitempty" yaml:"allow_discovery,omitempty"`
}

func (h HiveConfig) Enabled() bool { return h.URL != "" }

// Resources contains hard sandbox resource ceilings.
type Resources struct {
	MemoryMaxBytes  uint64   `json:"memory_max_bytes" yaml:"memory_max_bytes"`
	TasksMax        uint64   `json:"tasks_max" yaml:"tasks_max"`
	CPUQuotaPercent uint64   `json:"cpu_quota_percent" yaml:"cpu_quota_percent"`
	WallTime        Duration `json:"wall_time" yaml:"wall_time"`
}

// rawProfile and rawResources retain scalar presence while decoding. This
// prevents an explicitly configured zero from being mistaken for an omitted
// field that should receive a default.
type rawConfig struct {
	Version                   int                   `yaml:"version"`
	StateDirectory            string                `yaml:"state_directory"`
	RootFSDirectory           string                `yaml:"rootfs_directory"`
	WorkspaceDirectory        string                `yaml:"workspace_directory"`
	ReadOnlySourceDirectories []string              `yaml:"read_only_source_directories,omitempty"`
	Profiles                  map[string]rawProfile `yaml:"profiles"`
}

type rawProfile struct {
	Backend           string       `yaml:"backend"`
	Role              string       `yaml:"role"`
	Workload          string       `yaml:"workload"`
	TokenTTL          *Duration    `yaml:"token_ttl"`
	TokenFile         string       `yaml:"token_file,omitempty"`
	ForcefieldURL     string       `yaml:"forcefield_url"`
	CACert            string       `yaml:"ca_cert,omitempty"`
	ClientCert        string       `yaml:"client_cert,omitempty"`
	ClientKey         string       `yaml:"client_key,omitempty"`
	RootFS            string       `yaml:"rootfs"`
	WorkspaceTarget   string       `yaml:"workspace_target"`
	BrokerSocket      string       `yaml:"broker_socket"`
	BrokerListen      string       `yaml:"broker_listen"`
	WorkspaceReadOnly *bool        `yaml:"workspace_read_only,omitempty"`
	ShareNetwork      bool         `yaml:"share_network,omitempty"`
	ReadOnlyMounts    []Mount      `yaml:"read_only_mounts,omitempty"`
	Environment       Environment  `yaml:"environment,omitempty"`
	Hive              HiveConfig   `yaml:"hive,omitempty"`
	Resources         rawResources `yaml:"resources"`
}

type rawResources struct {
	MemoryMaxBytes  *uint64   `yaml:"memory_max_bytes"`
	TasksMax        *uint64   `yaml:"tasks_max"`
	CPUQuotaPercent *uint64   `yaml:"cpu_quota_percent"`
	WallTime        *Duration `yaml:"wall_time"`
}

// Load securely opens and decodes a runner configuration. The final path must
// be a regular, non-symlink file owned by root or the effective user and must
// not be group- or world-writable.
func Load(path string) (*Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || validateTrustedPath(path, true) != nil {
		return nil, invalid("unsafe configuration path")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !safeConfigFile(pathInfo) {
		return nil, invalid("unsafe configuration file")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, invalid("cannot open configuration file")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !safeConfigFile(info) || !os.SameFile(pathInfo, info) || info.Size() < 0 || info.Size() > maxConfigBytes {
		return nil, invalid("unsafe configuration file")
	}
	return Decode(io.LimitReader(file, maxConfigBytes+1))
}

// Decode parses exactly one strict YAML document and applies conservative
// defaults before validating every profile.
func Decode(reader io.Reader) (*Config, error) {
	if reader == nil {
		return nil, invalid("empty input")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxConfigBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxConfigBytes {
		return nil, invalid("configuration exceeds the read limit or is empty")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var source rawConfig
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidConfig, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, invalid("multiple YAML documents are not allowed")
	}

	if source.Version != 1 {
		return nil, invalid("version must be 1")
	}
	if !cleanAbsolutePath(source.StateDirectory) {
		return nil, invalid("state_directory must be a clean absolute path")
	}
	if err := validateRunnerDirectories(source); err != nil {
		return nil, invalid(err.Error())
	}
	if len(source.Profiles) == 0 {
		return nil, invalid("at least one profile is required")
	}

	config := &Config{
		Version: source.Version, StateDirectory: source.StateDirectory,
		RootFSDirectory: source.RootFSDirectory, WorkspaceDirectory: source.WorkspaceDirectory,
		ReadOnlySourceDirectories: append([]string(nil), source.ReadOnlySourceDirectories...),
		Profiles:                  make(map[string]Profile, len(source.Profiles)),
	}
	names := make([]string, 0, len(source.Profiles))
	for name := range source.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !validIdentifier(name) {
			return nil, invalid("profile name is invalid")
		}
		profile, err := compileRawProfile(source.Profiles[name])
		if err != nil {
			return nil, fmt.Errorf("%w: profile %q: %v", ErrInvalidConfig, name, err)
		}
		if !strictlyWithin(profile.RootFS, source.RootFSDirectory) {
			return nil, fmt.Errorf("%w: profile %q: rootfs is outside rootfs_directory", ErrInvalidConfig, name)
		}
		for _, mount := range profile.ReadOnlyMounts {
			if !withinAny(mount.Source, source.ReadOnlySourceDirectories) {
				return nil, fmt.Errorf("%w: profile %q: read-only mount source is outside the configured source directories", ErrInvalidConfig, name)
			}
		}
		config.Profiles[name] = profile
	}
	return config, nil
}

func validateRunnerDirectories(source rawConfig) error {
	directories := []string{source.StateDirectory, source.RootFSDirectory, source.WorkspaceDirectory}
	if len(source.ReadOnlySourceDirectories) > 32 {
		return errors.New("read_only_source_directories exceeds 32 entries")
	}
	directories = append(directories, source.ReadOnlySourceDirectories...)
	seen := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if !validRunnerBase(directory) {
			return errors.New("runner directories must be clean, non-system absolute paths")
		}
		if _, duplicate := seen[directory]; duplicate {
			return errors.New("runner directories must be unique")
		}
		seen[directory] = struct{}{}
	}
	for left := range directories {
		for right := left + 1; right < len(directories); right++ {
			if pathsOverlap(directories[left], directories[right]) {
				return errors.New("runner directories must not overlap")
			}
		}
	}
	return nil
}

func validRunnerBase(directory string) bool {
	if !cleanAbsolutePath(directory) || directory == string(filepath.Separator) {
		return false
	}
	for _, reserved := range []string{
		"/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
	} {
		if pathsOverlap(directory, reserved) {
			return false
		}
	}
	return true
}

func strictlyWithin(candidate, directory string) bool {
	return candidate != directory && pathWithin(candidate, directory)
}

func withinAny(candidate string, directories []string) bool {
	for _, directory := range directories {
		if pathWithin(candidate, directory) {
			return true
		}
	}
	return false
}

// Profile resolves a profile by its exact operator-owned name. The returned
// profile is a deep copy, so callers cannot mutate the configuration map via
// nested slices or maps.
func (c Config) Profile(name string) (Profile, error) {
	if !validIdentifier(name) {
		return Profile{}, ErrProfileNotFound
	}
	profile, ok := c.Profiles[name]
	if !ok {
		return Profile{}, ErrProfileNotFound
	}
	profile = cloneProfile(profile)
	if err := applyDefaultsAndValidate(&profile); err != nil {
		return Profile{}, fmt.Errorf("%w: profile is not valid: %v", ErrInvalidConfig, err)
	}
	return profile, nil
}

// ProfileDigest returns a stable digest over the effective, validated profile.
// It is suitable for correlating runner state and audit events, but carries no
// authority itself.
func ProfileDigest(profile Profile) (string, error) {
	profile = cloneProfile(profile)
	if err := applyDefaultsAndValidate(&profile); err != nil {
		return "", fmt.Errorf("%w: profile is not valid: %v", ErrInvalidConfig, err)
	}
	if len(profile.Environment.Inherit) == 0 {
		profile.Environment.Inherit = nil
	} else {
		sort.Strings(profile.Environment.Inherit)
	}
	if len(profile.Environment.Set) == 0 {
		profile.Environment.Set = nil
	}
	if len(profile.ReadOnlyMounts) == 0 {
		profile.ReadOnlyMounts = nil
	}
	if len(profile.Hive.AllowTo) == 0 {
		profile.Hive.AllowTo = nil
	} else {
		sort.Strings(profile.Hive.AllowTo)
	}
	if len(profile.Hive.AllowKinds) == 0 {
		profile.Hive.AllowKinds = nil
	} else {
		sort.Strings(profile.Hive.AllowKinds)
	}
	material := struct {
		Revision string  `json:"revision"`
		Profile  Profile `json:"profile"`
	}{Revision: profileDigestRevision, Profile: profile}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("profile digest: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func compileRawProfile(source rawProfile) (Profile, error) {
	profile := Profile{
		Backend: source.Backend, Role: source.Role, Workload: source.Workload,
		TokenFile: source.TokenFile, ForcefieldURL: source.ForcefieldURL, CACert: source.CACert,
		ClientCert: source.ClientCert, ClientKey: source.ClientKey,
		RootFS: source.RootFS, WorkspaceTarget: source.WorkspaceTarget,
		BrokerSocket: source.BrokerSocket, BrokerListen: source.BrokerListen,
		ShareNetwork:   source.ShareNetwork,
		ReadOnlyMounts: append([]Mount(nil), source.ReadOnlyMounts...),
		Environment: Environment{
			Inherit: append([]string(nil), source.Environment.Inherit...),
			Set:     cloneStringMap(source.Environment.Set),
		},
		Hive: HiveConfig{
			URL: source.Hive.URL, Network: source.Hive.Network,
			AllowTo: append([]string(nil), source.Hive.AllowTo...), AllowKinds: append([]string(nil), source.Hive.AllowKinds...),
			AllowBroadcast: source.Hive.AllowBroadcast, AllowDiscovery: source.Hive.AllowDiscovery,
		},
	}
	if source.WorkspaceReadOnly == nil {
		profile.WorkspaceReadOnly = true
	} else {
		profile.WorkspaceReadOnly = *source.WorkspaceReadOnly
	}
	if source.TokenTTL == nil {
		profile.TokenTTL = Duration(defaultTokenTTL)
	} else {
		profile.TokenTTL = *source.TokenTTL
	}
	if source.Resources.MemoryMaxBytes == nil {
		profile.Resources.MemoryMaxBytes = defaultMemoryMaxBytes
	} else {
		profile.Resources.MemoryMaxBytes = *source.Resources.MemoryMaxBytes
	}
	if source.Resources.TasksMax == nil {
		profile.Resources.TasksMax = defaultTasksMax
	} else {
		profile.Resources.TasksMax = *source.Resources.TasksMax
	}
	if source.Resources.CPUQuotaPercent == nil {
		profile.Resources.CPUQuotaPercent = defaultCPUQuota
	} else {
		profile.Resources.CPUQuotaPercent = *source.Resources.CPUQuotaPercent
	}
	if source.Resources.WallTime == nil {
		profile.Resources.WallTime = Duration(defaultWallTime)
	} else {
		profile.Resources.WallTime = *source.Resources.WallTime
	}
	applyStringDefaults(&profile)
	if err := validateProfile(&profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func applyDefaultsAndValidate(profile *Profile) error {
	applyStringDefaults(profile)
	if profile.TokenTTL == 0 {
		profile.TokenTTL = Duration(defaultTokenTTL)
	}
	if profile.Resources.MemoryMaxBytes == 0 {
		profile.Resources.MemoryMaxBytes = defaultMemoryMaxBytes
	}
	if profile.Resources.TasksMax == 0 {
		profile.Resources.TasksMax = defaultTasksMax
	}
	if profile.Resources.CPUQuotaPercent == 0 {
		profile.Resources.CPUQuotaPercent = defaultCPUQuota
	}
	if profile.Resources.WallTime == 0 {
		profile.Resources.WallTime = Duration(defaultWallTime)
	}
	return validateProfile(profile)
}

func applyStringDefaults(profile *Profile) {
	if profile.Backend == "" {
		profile.Backend = "bubblewrap"
	}
	if profile.WorkspaceTarget == "" {
		profile.WorkspaceTarget = defaultWorkspaceTarget
	}
	if profile.BrokerSocket == "" {
		profile.BrokerSocket = defaultBrokerSocket
	}
	if profile.BrokerListen == "" {
		profile.BrokerListen = defaultBrokerListen
	}
	if profile.Hive.Enabled() && profile.Hive.AllowKinds == nil {
		profile.Hive.AllowKinds = []string{"msg", "ask", "answer"}
	}
}

func validateProfile(profile *Profile) error {
	if profile.Backend != "bubblewrap" {
		return errors.New("backend must be bubblewrap")
	}
	if profile.TokenFile == "" {
		if !validIdentifier(profile.Role) {
			return errors.New("role is invalid")
		}
		if !validWorkload(profile.Workload) {
			return errors.New("workload is not canonical")
		}
		if profile.TokenTTL.Value() < time.Second || profile.TokenTTL.Value() > maximumTokenTTL {
			return errors.New("token_ttl must be between 1s and 168h")
		}
	} else {
		if !cleanAbsolutePath(profile.TokenFile) {
			return errors.New("token_file must be a clean absolute path")
		}
		if profile.Role != "" || profile.Workload != "" {
			return errors.New("token_file cannot be combined with role or workload")
		}
	}

	forcefieldURL, err := canonicalForcefieldURL(profile.ForcefieldURL)
	if err != nil {
		return err
	}
	profile.ForcefieldURL = forcefieldURL
	if (profile.ClientCert == "") != (profile.ClientKey == "") {
		return errors.New("client_cert and client_key must be configured together")
	}
	if profile.TokenFile == "" && profile.ClientCert == "" && strings.HasPrefix(profile.Workload, "mtls-spki:") {
		return errors.New("mTLS workload requires client_cert and client_key")
	}
	if profile.TokenFile == "" && profile.ClientCert != "" && !strings.HasPrefix(profile.Workload, "mtls-spki:") {
		return errors.New("client_cert and client_key require an mTLS workload")
	}
	for _, path := range []string{profile.CACert, profile.ClientCert, profile.ClientKey} {
		if path != "" && !cleanAbsolutePath(path) {
			return errors.New("credential paths must be clean absolute paths")
		}
	}

	if !cleanAbsolutePath(profile.RootFS) || profile.RootFS == string(filepath.Separator) {
		return errors.New("rootfs must be a clean, non-root absolute path")
	}
	if !validWorkspaceTarget(profile.WorkspaceTarget) {
		return errors.New("workspace_target is unsafe")
	}
	if !cleanAbsolutePath(profile.BrokerSocket) || profile.BrokerSocket == brokerDirectory || !pathWithin(profile.BrokerSocket, brokerDirectory) {
		return errors.New("broker_socket must be strictly beneath /run/forcefield")
	}
	listen, err := canonicalLoopbackListen(profile.BrokerListen)
	if err != nil {
		return err
	}
	profile.BrokerListen = listen

	if err := validateMounts(profile.ReadOnlyMounts, profile.WorkspaceTarget, profile.BrokerSocket); err != nil {
		return err
	}
	if err := validateEnvironment(profile.Environment); err != nil {
		return err
	}
	if err := validateHiveConfig(&profile.Hive); err != nil {
		return err
	}
	if err := validateResources(profile.Resources); err != nil {
		return err
	}
	return nil
}

func safeConfigFile(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, current := range value {
		if current >= 'a' && current <= 'z' || current >= '0' && current <= '9' || index > 0 && (current == '-' || current == '_') {
			continue
		}
		return false
	}
	return true
}

func validWorkload(value string) bool {
	if address, ok := strings.CutPrefix(value, "ip:"); ok {
		parsed, err := netip.ParseAddr(address)
		return err == nil && address == parsed.Unmap().String()
	}
	if digest, ok := strings.CutPrefix(value, "mtls-spki:"); ok {
		if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
			return false
		}
		_, err := hex.DecodeString(digest)
		return err == nil
	}
	return false
}

func canonicalForcefieldURL(value string) (string, error) {
	return canonicalRunnerOrigin(value, "forcefield_url")
}

func canonicalRunnerOrigin(value, field string) (string, error) {
	if value == "" || len(value) > 512 {
		return "", fmt.Errorf("%s is required and must be at most 512 bytes", field)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%s must be an HTTP(S) origin without credentials, path, query, or fragment", field)
	}
	host := strings.ToLower(parsed.Hostname())
	address, addressErr := netip.ParseAddr(host)
	if addressErr != nil && !validHostname(host) {
		return "", fmt.Errorf("%s has an invalid hostname", field)
	}
	if addressErr == nil {
		if address.Zone() != "" {
			return "", fmt.Errorf("%s has an invalid hostname", field)
		}
		host = address.Unmap().String()
	}
	port := parsed.Port()
	if port != "" {
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65_535 || strconv.Itoa(portNumber) != port {
			return "", fmt.Errorf("%s has an invalid port", field)
		}
	}
	loopback := host == "localhost" || addressErr == nil && address.IsLoopback()
	if parsed.Scheme == "http" && !loopback {
		return "", fmt.Errorf("%s requires HTTPS except for a loopback origin", field)
	}
	hostPort := host
	if addressErr == nil && address.Unmap().Is6() {
		hostPort = "[" + host + "]"
	}
	if port != "" {
		hostPort = net.JoinHostPort(host, port)
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: hostPort}).String(), nil
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, current := range label {
			if current < 'a' || current > 'z' {
				if current < '0' || current > '9' {
					if current != '-' {
						return false
					}
				}
			}
		}
	}
	return true
}

func canonicalLoopbackListen(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return "", errors.New("broker_listen must include a loopback host and numeric port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65_535 || strconv.Itoa(portNumber) != port {
		return "", errors.New("broker_listen has an invalid port")
	}
	host = strings.ToLower(host)
	if host == "localhost" {
		return net.JoinHostPort(host, port), nil
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || !address.IsLoopback() {
		return "", errors.New("broker_listen must be loopback-only")
	}
	address = address.Unmap()
	return net.JoinHostPort(address.String(), port), nil
}

func validWorkspaceTarget(value string) bool {
	if !cleanAbsolutePath(value) || value == string(filepath.Separator) {
		return false
	}
	for _, reserved := range []string{"/proc", "/dev", "/run"} {
		if pathWithin(value, reserved) {
			return false
		}
	}
	return true
}

func validateMounts(mounts []Mount, workspaceTarget, brokerSocket string) error {
	seenTargets := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		if !cleanAbsolutePath(mount.Source) || !cleanAbsolutePath(mount.Target) {
			return errors.New("read-only mount paths must be clean and absolute")
		}
		if _, duplicate := seenTargets[mount.Target]; duplicate {
			return errors.New("read-only mount targets must be unique")
		}
		seenTargets[mount.Target] = struct{}{}
		for _, protected := range []string{workspaceTarget, brokerSocket, "/proc", "/dev", "/run"} {
			if pathsOverlap(mount.Target, protected) {
				return errors.New("read-only mount target overlaps a protected sandbox path")
			}
		}
	}
	return nil
}

func validateEnvironment(environment Environment) error {
	seen := make(map[string]struct{}, len(environment.Inherit)+len(environment.Set))
	for _, name := range environment.Inherit {
		if !validEnvironmentName(name) || reservedEnvironmentName(name) || secretBearingEnvironmentName(name) {
			return errors.New("inherited environment name is unsafe")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("environment names must be unique")
		}
		seen[name] = struct{}{}
	}
	for name, value := range environment.Set {
		if !safeStaticEnvironment(name, value) {
			return errors.New("configured environment entry is unsafe")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("environment names must be unique")
		}
		seen[name] = struct{}{}
	}
	return nil
}

func safeStaticEnvironment(name, value string) bool {
	if !validEnvironmentName(name) || reservedEnvironmentName(name) || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	return !secretBearingEnvironmentName(name) || value == sandboxCredentialPlaceholder
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if index == 0 {
			if current != '_' && (current < 'A' || current > 'Z') && (current < 'a' || current > 'z') {
				return false
			}
			continue
		}
		if current != '_' && (current < 'A' || current > 'Z') && (current < 'a' || current > 'z') && (current < '0' || current > '9') {
			return false
		}
	}
	return true
}

func secretBearingEnvironmentName(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "TMUX", "TMUX_PANE", "KUBECONFIG", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS":
		return true
	}
	for _, marker := range []string{"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH", "API_KEY", "FORCEFIELD"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

func validateHiveConfig(hive *HiveConfig) error {
	if hive == nil || !hive.Enabled() {
		if hive != nil && (hive.Network != "" || len(hive.AllowTo) != 0 || len(hive.AllowKinds) != 0 || hive.AllowBroadcast || hive.AllowDiscovery) {
			return errors.New("hive.url is required when Hive policy is configured")
		}
		return nil
	}
	canonical, err := canonicalRunnerOrigin(hive.URL, "hive.url")
	if err != nil {
		return err
	}
	hive.URL = canonical
	if !validIdentifier(hive.Network) || len(hive.Network) > 32 {
		return errors.New("hive.network is invalid")
	}
	if len(hive.AllowTo) > 128 {
		return errors.New("hive.allow_to exceeds 128 recipients")
	}
	seenRecipients := make(map[string]struct{}, len(hive.AllowTo))
	for _, recipient := range hive.AllowTo {
		if !validHiveAddress(recipient) || recipient == "@all" {
			return errors.New("hive.allow_to contains an invalid recipient")
		}
		if _, duplicate := seenRecipients[recipient]; duplicate {
			return errors.New("hive.allow_to contains a duplicate recipient")
		}
		seenRecipients[recipient] = struct{}{}
	}
	if len(hive.AllowKinds) > 3 {
		return errors.New("hive.allow_kinds is invalid")
	}
	seenKinds := make(map[string]struct{}, len(hive.AllowKinds))
	for _, kind := range hive.AllowKinds {
		if kind != "msg" && kind != "ask" && kind != "answer" {
			return errors.New("hive.allow_kinds contains an unsupported kind")
		}
		if _, duplicate := seenKinds[kind]; duplicate {
			return errors.New("hive.allow_kinds contains a duplicate kind")
		}
		seenKinds[kind] = struct{}{}
	}
	return nil
}

func validHiveAddress(value string) bool {
	if value == "@all" {
		return true
	}
	name, host, found := strings.Cut(value, "@")
	if !validIdentifier(name) || len(name) > 32 {
		return false
	}
	if !found {
		return true
	}
	return validIdentifier(host) && len(host) <= 32 && !strings.Contains(host, "@")
}

func validateResources(resources Resources) error {
	if resources.MemoryMaxBytes < minimumMemoryMaxBytes || resources.MemoryMaxBytes > maximumMemoryMaxBytes {
		return errors.New("memory_max_bytes must be between 64 MiB and 1 TiB")
	}
	if resources.TasksMax < 1 || resources.TasksMax > maximumTasksMax {
		return errors.New("tasks_max must be between 1 and 65536")
	}
	if resources.CPUQuotaPercent < 1 || resources.CPUQuotaPercent > maximumCPUQuota {
		return errors.New("cpu_quota_percent must be between 1 and 10000")
	}
	if resources.WallTime.Value() < time.Second || resources.WallTime.Value() > maximumWallTime {
		return errors.New("wall_time must be between 1s and 168h")
	}
	return nil
}

func cleanAbsolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func pathWithin(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func cloneProfile(profile Profile) Profile {
	profile.ReadOnlyMounts = append([]Mount(nil), profile.ReadOnlyMounts...)
	profile.Environment.Inherit = append([]string(nil), profile.Environment.Inherit...)
	profile.Environment.Set = cloneStringMap(profile.Environment.Set)
	profile.Hive.AllowTo = append([]string(nil), profile.Hive.AllowTo...)
	profile.Hive.AllowKinds = append([]string(nil), profile.Hive.AllowKinds...)
	return profile
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, reason)
}
