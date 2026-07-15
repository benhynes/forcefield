// Package config loads and validates Forcefield's operator configuration.
// Configuration contains secret references, never secret values.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/benhynes/forcefield/internal/gitadapter"
	"github.com/benhynes/forcefield/internal/headersafety"
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/tokens"
	"go.yaml.in/yaml/v3"
)

const (
	maxConfigBytes = 4 << 20

	// AdapterHTTP is the default request/policy adapter used by existing API
	// services. AdapterGitSmartHTTP exposes only Git's smart-HTTP fetch and push
	// protocol surface; repository and ref authority is supplied by policy.
	AdapterHTTP         = "http"
	AdapterGitSmartHTTP = "git-smart-http"

	// CapabilitiesPath is reserved by the data plane for live, authenticated
	// discovery of the calling token's sanitized grants. Configured path routes
	// may not claim this namespace.
	CapabilitiesPath = "/.well-known/forcefield/capabilities"
	// CapabilityManifestMaxBytes and CapabilityManifestMaxServices are shared
	// producer/consumer bounds for the authenticated discovery document.
	CapabilityManifestMaxBytes    = 128 << 10
	CapabilityManifestMaxServices = 64
	CapabilityServiceURLMaxBytes  = 4096
	CapabilityAuthHeaderMaxBytes  = 256

	// BindingEngineRevision is part of every credential binding digest. Bump it
	// whenever routing, transport, header, response-guard, or other authority
	// semantics change so persisted tokens cannot silently inherit new meaning.
	BindingEngineRevision = "forcefield-binding-engine/v2"
)

var ErrInvalidConfig = errors.New("invalid forcefield configuration")

type Duration time.Duration

func (d *Duration) UnmarshalText(value []byte) error {
	parsed, err := time.ParseDuration(string(value))
	if err != nil || parsed < 0 {
		return fmt.Errorf("invalid duration")
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Value() time.Duration { return time.Duration(d) }

type File struct {
	Version     int                         `json:"version" yaml:"version"`
	Server      ServerConfig                `json:"server" yaml:"server"`
	State       StateConfig                 `json:"state" yaml:"state"`
	Secrets     SecretBackendConfig         `json:"secrets" yaml:"secrets"`
	Services    map[string]ServiceConfig    `json:"services" yaml:"services"`
	Credentials map[string]CredentialConfig `json:"credentials" yaml:"credentials"`
	Policies    map[string]PolicyConfig     `json:"policies" yaml:"policies"`
	Roles       map[string]RoleConfig       `json:"roles" yaml:"roles"`
}

type ServerConfig struct {
	Listen               string   `json:"listen" yaml:"listen"`
	Audience             string   `json:"audience" yaml:"audience"`
	AdminSocket          string   `json:"admin_socket" yaml:"admin_socket"`
	AdvertisedBaseURL    string   `json:"advertised_base_url,omitempty" yaml:"advertised_base_url,omitempty"`
	TLSCert              string   `json:"tls_cert,omitempty" yaml:"tls_cert,omitempty"`
	TLSKey               string   `json:"tls_key,omitempty" yaml:"tls_key,omitempty"`
	ClientCA             string   `json:"client_ca,omitempty" yaml:"client_ca,omitempty"`
	AllowInsecureIngress bool     `json:"allow_insecure_ingress,omitempty" yaml:"allow_insecure_ingress,omitempty"`
	ReadHeaderTimeout    Duration `json:"read_header_timeout,omitempty" yaml:"read_header_timeout,omitempty"`
	ReadTimeout          Duration `json:"read_timeout,omitempty" yaml:"read_timeout,omitempty"`
	IdleTimeout          Duration `json:"idle_timeout,omitempty" yaml:"idle_timeout,omitempty"`
	MaxTokenTTL          Duration `json:"max_token_ttl,omitempty" yaml:"max_token_ttl,omitempty"`
	MaxRequestBytes      uint64   `json:"max_request_bytes,omitempty" yaml:"max_request_bytes,omitempty"`
}

type StateConfig struct {
	TokenFile    string `json:"token_file" yaml:"token_file"`
	AuditFile    string `json:"audit_file" yaml:"audit_file"`
	AuditFailure string `json:"audit_failure,omitempty" yaml:"audit_failure,omitempty"`
}

type SecretBackendConfig struct {
	Type            string   `json:"type" yaml:"type"`
	Command         string   `json:"command,omitempty" yaml:"command,omitempty"`
	Args            []string `json:"args,omitempty" yaml:"args,omitempty"`
	EnvPrefix       string   `json:"env_prefix,omitempty" yaml:"env_prefix,omitempty"`
	Timeout         Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	MaxOutputBytes  int      `json:"max_output_bytes,omitempty" yaml:"max_output_bytes,omitempty"`
	CacheTTL        Duration `json:"cache_ttl,omitempty" yaml:"cache_ttl,omitempty"`
	MaxCacheEntries int      `json:"max_cache_entries,omitempty" yaml:"max_cache_entries,omitempty"`
}

type ServiceConfig struct {
	Adapter               string            `json:"adapter,omitempty" yaml:"adapter,omitempty"`
	Git                   *GitServiceConfig `json:"git,omitempty" yaml:"git,omitempty"`
	Upstream              string            `json:"upstream" yaml:"upstream"`
	PathPrefix            string            `json:"path_prefix,omitempty" yaml:"path_prefix,omitempty"`
	Host                  string            `json:"host,omitempty" yaml:"host,omitempty"`
	AllowInsecureUpstream bool              `json:"allow_insecure_upstream,omitempty" yaml:"allow_insecure_upstream,omitempty"`
	AllowedCIDRs          []string          `json:"allowed_cidrs,omitempty" yaml:"allowed_cidrs,omitempty"`
	PinnedSPKISHA256      []string          `json:"pinned_spki_sha256,omitempty" yaml:"pinned_spki_sha256,omitempty"`
	ClientAuth            HeaderAuth        `json:"client_auth" yaml:"client_auth"`
	ForwardHeaders        []string          `json:"forward_headers,omitempty" yaml:"forward_headers,omitempty"`
	StaticHeaders         map[string]string `json:"static_headers,omitempty" yaml:"static_headers,omitempty"`
	Response              ResponseConfig    `json:"response,omitempty" yaml:"response,omitempty"`
}

type GitServiceConfig struct {
	RepositoryCase gitadapter.RepositoryCaseMode `json:"repository_case" yaml:"repository_case"`
}

type HeaderAuth struct {
	Header string `json:"header" yaml:"header"`
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
}

type ResponseConfig struct {
	StripHeaders    []string `json:"strip_headers,omitempty" yaml:"strip_headers,omitempty"`
	RequireIdentity *bool    `json:"require_identity,omitempty" yaml:"require_identity,omitempty"`
}

type CredentialConfig struct {
	Service       string     `json:"service" yaml:"service"`
	SecretRef     string     `json:"secret_ref" yaml:"secret_ref"`
	Inject        HeaderAuth `json:"inject" yaml:"inject"`
	BasicUsername string     `json:"basic_username,omitempty" yaml:"basic_username,omitempty"`
}

type PolicyConfig struct {
	Service           string            `json:"service" yaml:"service"`
	CapabilitySummary string            `json:"capability_summary,omitempty" yaml:"capability_summary,omitempty"`
	BodyLimit         int64             `json:"body_limit,omitempty" yaml:"body_limit,omitempty"`
	CELCostLimit      uint64            `json:"cel_cost_limit,omitempty" yaml:"cel_cost_limit,omitempty"`
	CELTimeout        Duration          `json:"cel_timeout,omitempty" yaml:"cel_timeout,omitempty"`
	Rules             []policy.RuleSpec `json:"rules,omitempty" yaml:"rules,omitempty"`
	Git               *GitPolicyConfig  `json:"git,omitempty" yaml:"git,omitempty"`
}

// GitPolicyConfig is intentionally separate from the generic HTTP policy
// language. Smart-HTTP push authorization is semantic: every receive-pack ref
// update must be parsed and authorized before an upstream credential is used.
type GitPolicyConfig struct {
	Rules []GitRuleConfig `json:"rules" yaml:"rules"`
}

type GitRuleConfig struct {
	ID           string                  `json:"id" yaml:"id"`
	Effect       gitadapter.Effect       `json:"effect" yaml:"effect"`
	Operation    gitadapter.Operation    `json:"operation" yaml:"operation"`
	Repositories []string                `json:"repositories" yaml:"repositories"`
	Refs         []string                `json:"refs,omitempty" yaml:"refs,omitempty"`
	UpdateKinds  []gitadapter.UpdateKind `json:"update_kinds,omitempty" yaml:"update_kinds,omitempty"`
}

type RoleConfig struct {
	Grants []GrantConfig `json:"grants" yaml:"grants"`
}

type GrantConfig struct {
	Service    string       `json:"service" yaml:"service"`
	Credential string       `json:"credential" yaml:"credential"`
	Policy     string       `json:"policy" yaml:"policy"`
	Limits     LimitsConfig `json:"limits,omitempty" yaml:"limits,omitempty"`
}

type LimitsConfig struct {
	RequestsPerSecond uint64 `json:"requests_per_second,omitempty" yaml:"requests_per_second,omitempty"`
	Burst             uint64 `json:"burst,omitempty" yaml:"burst,omitempty"`
	RequestBudget     uint64 `json:"request_budget,omitempty" yaml:"request_budget,omitempty"`
	ByteBudget        uint64 `json:"byte_budget,omitempty" yaml:"byte_budget,omitempty"`
	MaxRequestBytes   uint64 `json:"max_request_bytes,omitempty" yaml:"max_request_bytes,omitempty"`
}

func (l LimitsConfig) TokenLimits() tokens.Limits {
	return tokens.Limits{
		RequestsPerSecond: l.RequestsPerSecond, Burst: l.Burst,
		RequestBudget: l.RequestBudget, ByteBudget: l.ByteBudget, MaxRequestBytes: l.MaxRequestBytes,
	}
}

type CompiledPolicy struct {
	Name              string
	Service           string
	Adapter           string
	Revision          string
	CapabilitySummary string
	Policy            *policy.Policy
	GitPolicy         *gitadapter.Policy
}

// CapabilityProjection is the immutable, agent-visible portion of one
// revision-resolved grant. It contains routing guidance, never authority or
// credential material.
type CapabilityProjection struct {
	Service, Adapter, BaseURL, PathPrefix, Host string
	ClientHeader, ClientPrefix                  string
	CapabilitySummary                           string
}

type Compiled struct {
	File               File
	Upstreams          map[string]*url.URL
	AllowedPrefixes    map[string][]netip.Prefix
	Policies           map[string]CompiledPolicy
	PoliciesByRevision map[string]CompiledPolicy
	Roles              map[string][]tokens.Grant
	BindingRevisions   map[string]string
	capabilityServices map[string]CapabilityProjection
	credentialServices map[string]string
	policyRevisions    map[string]CompiledPolicy
	bindingRevisions   map[string]string
}

func Load(path string) (*Compiled, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: unsafe file", ErrInvalidConfig)
	}
	if stat, ok := pathInfo.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("%w: unsafe file owner", ErrInvalidConfig)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: open", ErrInvalidConfig)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) || info.Size() > maxConfigBytes {
		return nil, fmt.Errorf("%w: unsafe file", ErrInvalidConfig)
	}
	return Decode(io.LimitReader(file, maxConfigBytes+1))
}

func Decode(reader io.Reader) (*Compiled, error) {
	if reader == nil {
		return nil, fmt.Errorf("%w: empty input", ErrInvalidConfig)
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxConfigBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxConfigBytes {
		return nil, fmt.Errorf("%w: read", ErrInvalidConfig)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var file File
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidConfig, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: multiple documents", ErrInvalidConfig)
	}
	return Compile(file)
}

func Compile(file File) (*Compiled, error) {
	if file.Version != 1 {
		return nil, invalid("version must be 1")
	}
	applyDefaults(&file)
	if err := validateServer(file.Server); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(file.State.TokenFile) || !filepath.IsAbs(file.State.AuditFile) {
		return nil, invalid("state paths must be absolute")
	}
	if filepath.Clean(file.State.TokenFile) == filepath.Clean(file.State.AuditFile) {
		return nil, invalid("token and audit files must differ")
	}
	if file.State.AuditFailure != "closed" && file.State.AuditFailure != "open" {
		return nil, invalid("state.audit_failure must be closed or open")
	}
	if err := validateSecretBackend(file.Secrets); err != nil {
		return nil, err
	}

	compiled := &Compiled{
		File: file, Upstreams: make(map[string]*url.URL), AllowedPrefixes: make(map[string][]netip.Prefix),
		Policies: make(map[string]CompiledPolicy), PoliciesByRevision: make(map[string]CompiledPolicy),
		Roles: make(map[string][]tokens.Grant), BindingRevisions: make(map[string]string),
		capabilityServices: make(map[string]CapabilityProjection), credentialServices: make(map[string]string),
		policyRevisions: make(map[string]CompiledPolicy), bindingRevisions: make(map[string]string),
	}
	if err := compileServices(compiled); err != nil {
		return nil, err
	}
	if err := compileCredentials(compiled); err != nil {
		return nil, err
	}
	if err := compilePolicies(compiled); err != nil {
		return nil, err
	}
	if err := compileRoles(compiled); err != nil {
		return nil, err
	}
	if err := validateCapabilityManifestBound(compiled); err != nil {
		return nil, err
	}
	return compiled, nil
}

func applyDefaults(file *File) {
	if file.Server.Listen == "" {
		file.Server.Listen = "127.0.0.1:7902"
	}
	if file.Server.Audience == "" {
		file.Server.Audience = "forcefield"
	}
	if file.Server.ReadHeaderTimeout == 0 {
		file.Server.ReadHeaderTimeout = Duration(5 * time.Second)
	}
	if file.Server.ReadTimeout == 0 {
		file.Server.ReadTimeout = Duration(30 * time.Second)
	}
	if file.Server.IdleTimeout == 0 {
		file.Server.IdleTimeout = Duration(60 * time.Second)
	}
	if file.Server.MaxTokenTTL == 0 {
		file.Server.MaxTokenTTL = Duration(24 * time.Hour)
	}
	if file.Server.MaxRequestBytes == 0 {
		file.Server.MaxRequestBytes = 16 << 20
	}
	if file.State.AuditFailure == "" {
		file.State.AuditFailure = "closed"
	}
	if file.Secrets.Type == "" {
		file.Secrets.Type = "exec"
	}
	if file.Secrets.Timeout == 0 {
		file.Secrets.Timeout = Duration(5 * time.Second)
	}
	if file.Secrets.MaxOutputBytes == 0 {
		file.Secrets.MaxOutputBytes = 16 << 10
	}
	if file.Secrets.MaxCacheEntries == 0 {
		file.Secrets.MaxCacheEntries = 128
	}
	for name, service := range file.Services {
		if service.Adapter == "" {
			service.Adapter = AdapterHTTP
			file.Services[name] = service
		}
	}
}

func validateServer(server ServerConfig) error {
	host, _, err := net.SplitHostPort(server.Listen)
	if err != nil {
		return invalid("server.listen must include host and port")
	}
	if !validID(server.Audience) || server.AdminSocket == "" || !filepath.IsAbs(server.AdminSocket) {
		return invalid("server audience and absolute admin_socket are required")
	}
	if (server.TLSCert == "") != (server.TLSKey == "") {
		return invalid("tls_cert and tls_key must be configured together")
	}
	if server.ClientCA != "" && server.TLSCert == "" {
		return invalid("client_ca requires TLS")
	}
	for _, path := range []string{server.TLSCert, server.TLSKey, server.ClientCA} {
		if path != "" && !filepath.IsAbs(path) {
			return invalid("TLS paths must be absolute")
		}
	}
	if server.MaxTokenTTL.Value() < time.Second || server.MaxTokenTTL.Value() > 7*24*time.Hour {
		return invalid("max_token_ttl must be between 1s and 168h")
	}
	if server.ReadHeaderTimeout.Value() <= 0 || server.ReadTimeout.Value() <= 0 || server.IdleTimeout.Value() <= 0 {
		return invalid("server timeouts must be positive")
	}
	if server.MaxRequestBytes == 0 || server.MaxRequestBytes > 1<<30 {
		return invalid("max_request_bytes must be between 1 byte and 1 GiB")
	}
	if server.AdvertisedBaseURL != "" {
		advertised, err := url.Parse(server.AdvertisedBaseURL)
		if err != nil || len(server.AdvertisedBaseURL) > 512 || advertised.Scheme != "http" && advertised.Scheme != "https" || advertised.Host == "" ||
			advertised.User != nil || advertised.RawQuery != "" || advertised.ForceQuery || advertised.Fragment != "" ||
			advertised.Path != "" && advertised.Path != "/" {
			return invalid("advertised_base_url must be an HTTP(S) origin without credentials, path, query, or fragment")
		}
		advertisedHost := strings.ToLower(advertised.Hostname())
		advertisedIP := net.ParseIP(advertisedHost)
		if advertisedIP == nil && !validHostname(advertisedHost) {
			return invalid("advertised_base_url has an invalid hostname")
		}
		if port := advertised.Port(); port != "" {
			portNumber, portErr := strconv.Atoi(port)
			if portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
				return invalid("advertised_base_url has an invalid port")
			}
		}
		advertised.Path = ""
		if advertised.String() != strings.TrimSuffix(server.AdvertisedBaseURL, "/") {
			return invalid("advertised_base_url must use a canonical origin spelling")
		}
		advertisedLoopback := advertisedHost == "localhost" || advertisedIP != nil && advertisedIP.IsLoopback()
		if advertised.Scheme == "http" && !advertisedLoopback {
			return invalid("advertised_base_url requires HTTPS except for a loopback development origin")
		}
	}
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
	if server.TLSCert == "" && !loopback && !server.AllowInsecureIngress {
		return invalid("non-loopback ingress requires TLS or explicit allow_insecure_ingress")
	}
	return nil
}

func validateSecretBackend(secret SecretBackendConfig) error {
	switch secret.Type {
	case "exec":
		if !filepath.IsAbs(secret.Command) {
			return invalid("exec secret command must be absolute")
		}
	case "env":
		// Development-only backend; the serve command emits a warning.
		if !validEnvPrefix(secret.EnvPrefix) {
			return invalid("env secret backend requires a valid env_prefix")
		}
	default:
		return invalid("secrets.type must be exec or env")
	}
	if secret.MaxOutputBytes < 1 || secret.MaxOutputBytes > 16<<10 || secret.MaxCacheEntries < 0 {
		return invalid("invalid secret backend limits")
	}
	return nil
}

func compileServices(compiled *Compiled) error {
	if len(compiled.File.Services) == 0 {
		return invalid("at least one service is required")
	}
	routes := make(map[string]string)
	for _, name := range sortedKeys(compiled.File.Services) {
		service := compiled.File.Services[name]
		if !validID(name) {
			return invalid("invalid service name " + name)
		}
		if service.Adapter != AdapterHTTP && service.Adapter != AdapterGitSmartHTTP {
			return invalid("service " + name + " has an unsupported adapter")
		}
		if service.Adapter == AdapterHTTP && service.Git != nil {
			return invalid("service " + name + " cannot use git settings with the HTTP adapter")
		}
		if service.Adapter == AdapterGitSmartHTTP {
			if service.Git == nil {
				return invalid("service " + name + " git-smart-http requires git.repository_case")
			}
			if _, err := gitadapter.NormalizeRepository("repository.git", service.Git.RepositoryCase); err != nil {
				return invalid("service " + name + " has an invalid git.repository_case")
			}
		}
		upstream, err := url.Parse(service.Upstream)
		if err != nil || upstream.Host == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery || upstream.Fragment != "" {
			return invalid("service " + name + " has invalid upstream")
		}
		if upstream.Scheme != "https" && !(service.AllowInsecureUpstream && upstream.Scheme == "http") {
			return invalid("service " + name + " upstream must use HTTPS")
		}
		if upstream.Scheme == "http" && len(service.PinnedSPKISHA256) != 0 {
			return invalid("service " + name + " cannot use SPKI pins with HTTP")
		}
		if (service.PathPrefix == "") == (service.Host == "") {
			return invalid("service " + name + " needs exactly one of path_prefix or host")
		}
		if service.PathPrefix != "" {
			if len(service.PathPrefix) > CapabilityServiceURLMaxBytes || service.PathPrefix[0] != '/' || service.PathPrefix == "/" || strings.HasSuffix(service.PathPrefix, "/") || strings.Contains(service.PathPrefix, "//") ||
				!validAgentVisibleText(service.PathPrefix) {
				return invalid("service " + name + " has invalid path_prefix")
			}
			if previous := routes["path:"+service.PathPrefix]; previous != "" {
				return invalid("services " + previous + " and " + name + " share a path route")
			}
			if service.PathPrefix == CapabilitiesPath || strings.HasPrefix(CapabilitiesPath, service.PathPrefix+"/") {
				return invalid("service " + name + " path_prefix overlaps the reserved capabilities namespace")
			}
			routes["path:"+service.PathPrefix] = name
			escaped := (&url.URL{Path: service.PathPrefix}).EscapedPath()
			canonical, err := policy.CanonicalPath(escaped)
			decoded, decodeErr := url.PathUnescape(canonical)
			if err != nil || decodeErr != nil || decoded != service.PathPrefix {
				return invalid("service " + name + " has a non-canonical path_prefix")
			}
		}
		if service.Host != "" {
			host := strings.ToLower(service.Host)
			if !validHostname(host) {
				return invalid("service " + name + " has invalid host route")
			}
			if previous := routes["host:"+host]; previous != "" {
				return invalid("services " + previous + " and " + name + " share a host route")
			}
			if advertised := compiled.File.Server.AdvertisedBaseURL; advertised != "" {
				advertisedURL, _ := url.Parse(advertised)
				if advertisedURL.Scheme == "http" {
					return invalid("service " + name + " host routing requires an HTTPS advertised_base_url")
				}
			}
			routes["host:"+host] = name
		}
		if !validAuthHeader(service.ClientAuth) {
			return invalid("service " + name + " client_auth.header is required")
		}
		if service.Adapter == AdapterGitSmartHTTP {
			if !strings.EqualFold(service.ClientAuth.Header, "Authorization") || service.ClientAuth.Prefix != "Bearer " {
				return invalid("service " + name + " git-smart-http client_auth must be Authorization Bearer")
			}
			if service.Response.RequireIdentity != nil && !*service.Response.RequireIdentity {
				return invalid("service " + name + " git-smart-http requires identity responses")
			}
		}
		forwardedNames := make(map[string]struct{}, len(service.ForwardHeaders))
		for _, header := range service.ForwardHeaders {
			canonicalName := strings.ToLower(header)
			if service.Adapter == AdapterGitSmartHTTP && gitDerivedHeader(canonicalName) {
				return invalid("service " + name + " cannot forward Git protocol-derived header " + header)
			}
			if _, duplicate := forwardedNames[canonicalName]; duplicate {
				return invalid("service " + name + " has duplicate canonical forwarded headers")
			}
			forwardedNames[canonicalName] = struct{}{}
			if !validHeaderName(header) || headersafety.CredentialBearing(header) || isHopHeader(header) || strings.EqualFold(header, "Content-Length") || strings.EqualFold(header, "Accept-Encoding") || strings.EqualFold(header, service.ClientAuth.Header) {
				return invalid("service " + name + " has an unsafe header rule")
			}
		}
		staticNames := make(map[string]struct{}, len(service.StaticHeaders))
		for header, value := range service.StaticHeaders {
			canonicalName := strings.ToLower(header)
			if _, duplicate := staticNames[canonicalName]; duplicate {
				return invalid("service " + name + " has duplicate canonical static headers")
			}
			staticNames[canonicalName] = struct{}{}
			if !validHeaderName(header) || headersafety.CredentialBearing(header) || isHopHeader(header) || isFramingHeader(header) || strings.EqualFold(header, "Host") ||
				strings.EqualFold(header, "Accept-Encoding") || strings.EqualFold(header, service.ClientAuth.Header) || len(value) > 8<<10 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
				return invalid("service " + name + " has an unsafe static header")
			}
			for _, forwarded := range service.ForwardHeaders {
				if strings.EqualFold(forwarded, header) {
					return invalid("service " + name + " header cannot be both forwarded and static")
				}
			}
		}
		for _, header := range service.Response.StripHeaders {
			if !validHeaderName(header) {
				return invalid("service " + name + " has an invalid response strip header")
			}
		}
		for _, pin := range service.PinnedSPKISHA256 {
			raw, err := base64.StdEncoding.DecodeString(pin)
			if err != nil || len(raw) != sha256.Size {
				return invalid("service " + name + " has an invalid SPKI pin")
			}
		}
		prefixes := make([]netip.Prefix, 0, len(service.AllowedCIDRs))
		for _, raw := range service.AllowedCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return invalid("service " + name + " has invalid allowed CIDR")
			}
			prefixes = append(prefixes, prefix.Masked())
		}
		canonicalBase, err := policy.CanonicalPath(upstream.EscapedPath())
		if err != nil {
			return invalid("service " + name + " has a non-canonical upstream path")
		}
		upstream.Path, err = url.PathUnescape(canonicalBase)
		if err != nil {
			return invalid("service " + name + " has an invalid upstream path")
		}
		upstream.RawPath = canonicalBase
		compiled.Upstreams[name] = upstream
		compiled.AllowedPrefixes[name] = prefixes
		advertisedURL := advertisedServiceURL(compiled.File.Server.AdvertisedBaseURL, service)
		if len(advertisedURL) > CapabilityServiceURLMaxBytes {
			return invalid("service " + name + " advertised URL exceeds the capability manifest limit")
		}
		compiled.capabilityServices[name] = CapabilityProjection{
			Service: name, Adapter: service.Adapter, BaseURL: advertisedURL,
			PathPrefix: service.PathPrefix, Host: strings.ToLower(service.Host),
			ClientHeader: service.ClientAuth.Header, ClientPrefix: service.ClientAuth.Prefix,
		}
	}
	return nil
}

func advertisedServiceURL(base string, service ServiceConfig) string {
	if base == "" {
		return ""
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return ""
	}
	if service.PathPrefix != "" {
		parsed.Path = service.PathPrefix
		parsed.RawPath = ""
		return parsed.String()
	}
	port := parsed.Port()
	parsed.Host = strings.ToLower(service.Host)
	if port != "" {
		parsed.Host = net.JoinHostPort(parsed.Host, port)
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed.String()
}

func compileCredentials(compiled *Compiled) error {
	if len(compiled.File.Credentials) == 0 {
		return invalid("at least one credential is required")
	}
	for name, credential := range compiled.File.Credentials {
		if !validID(name) || !validSecretReference(credential.SecretRef, compiled.File.Secrets.Type == "env") || !validAuthHeader(credential.Inject) {
			return invalid("invalid credential " + name)
		}
		if credential.BasicUsername != "" && (!strings.EqualFold(credential.Inject.Header, "Authorization") || credential.Inject.Prefix != "" || !validBasicUsername(credential.BasicUsername)) {
			return invalid("credential " + name + " has an invalid basic_username injection")
		}
		if _, exists := compiled.File.Services[credential.Service]; !exists {
			return invalid("credential " + name + " references unknown service")
		}
		service := compiled.File.Services[credential.Service]
		if strings.EqualFold(credential.Inject.Header, service.ClientAuth.Header) {
			// Replacing the carrier is the normal case and remains allowed.
		} else {
			for _, forwarded := range service.ForwardHeaders {
				if strings.EqualFold(forwarded, credential.Inject.Header) {
					return invalid("credential " + name + " inject header is also forwarded")
				}
			}
		}
		for header := range service.StaticHeaders {
			if strings.EqualFold(header, credential.Inject.Header) {
				return invalid("credential " + name + " inject header is also static")
			}
		}
		revision, err := bindingRevision(compiled, name, credential)
		if err != nil {
			return invalid("credential " + name + " binding could not be hashed")
		}
		compiled.BindingRevisions[name] = revision
		compiled.bindingRevisions[name] = revision
		compiled.credentialServices[name] = credential.Service
	}
	return nil
}

func compilePolicies(compiled *Compiled) error {
	if len(compiled.File.Policies) == 0 {
		return invalid("at least one policy is required")
	}
	for _, name := range sortedKeys(compiled.File.Policies) {
		spec := compiled.File.Policies[name]
		if !validID(name) {
			return invalid("invalid policy name " + name)
		}
		if _, exists := compiled.File.Services[spec.Service]; !exists {
			return invalid("policy " + name + " references unknown service")
		}
		if !validCapabilitySummary(spec.CapabilitySummary) {
			return invalid("policy " + name + " has an invalid capability_summary")
		}
		adapter := compiled.File.Services[spec.Service].Adapter
		entry := CompiledPolicy{
			Name: name, Service: spec.Service, Adapter: adapter,
			CapabilitySummary: spec.CapabilitySummary,
		}
		var err error
		switch adapter {
		case AdapterHTTP:
			if spec.Git != nil {
				return invalid("policy " + name + " cannot use git rules with the HTTP adapter")
			}
			entry.Policy, err = policy.Compile(policy.Spec{Rules: spec.Rules}, policy.Options{
				BodyLimit: spec.BodyLimit, CELCostLimit: spec.CELCostLimit, CELTimeout: spec.CELTimeout.Value(),
			})
			if err != nil {
				return invalid("compile policy " + name + ": " + err.Error())
			}
			if entry.Policy.MaxBodyBytes() > int64(compiled.File.Server.MaxRequestBytes) {
				return invalid("policy " + name + " body limit exceeds server max_request_bytes")
			}
			entry.Revision, err = policyRevision(spec, entry.Policy)
		case AdapterGitSmartHTTP:
			if spec.Git == nil || len(spec.Rules) != 0 || spec.BodyLimit != 0 || spec.CELCostLimit != 0 || spec.CELTimeout != 0 {
				return invalid("policy " + name + " must use only git rules with the git-smart-http adapter")
			}
			entry.GitPolicy, err = compileGitPolicy(*spec.Git, compiled.File.Services[spec.Service].Git.RepositoryCase)
			if err == nil {
				entry.Revision, err = gitPolicyRevision(spec, compiled.File.Services[spec.Service].Git.RepositoryCase)
			}
		default:
			err = errors.New("unsupported adapter")
		}
		if err != nil {
			return invalid("compile policy " + name + ": " + err.Error())
		}
		if previous, exists := compiled.PoliciesByRevision[entry.Revision]; exists && previous.Name != name {
			return invalid("policies have an identical revision")
		}
		compiled.Policies[name] = entry
		compiled.PoliciesByRevision[entry.Revision] = entry
		compiled.policyRevisions[entry.Revision] = entry
	}
	return nil
}

func compileRoles(compiled *Compiled) error {
	if len(compiled.File.Roles) == 0 {
		return invalid("at least one role is required")
	}
	for roleName, role := range compiled.File.Roles {
		if !validID(roleName) || len(role.Grants) == 0 || len(role.Grants) > CapabilityManifestMaxServices {
			return invalid("invalid or empty role " + roleName)
		}
		grants := make([]tokens.Grant, 0, len(role.Grants))
		seen := make(map[string]struct{}, len(role.Grants))
		for _, grant := range role.Grants {
			service, ok := compiled.File.Services[grant.Service]
			_ = service
			if !ok {
				return invalid("role " + roleName + " references unknown service")
			}
			credential, ok := compiled.File.Credentials[grant.Credential]
			if !ok || credential.Service != grant.Service {
				return invalid("role " + roleName + " has a cross-service credential")
			}
			compiledPolicy, ok := compiled.Policies[grant.Policy]
			if !ok || compiledPolicy.Service != grant.Service {
				return invalid("role " + roleName + " has a cross-service policy")
			}
			if grant.Limits.RequestsPerSecond == 0 && grant.Limits.Burst != 0 {
				return invalid("role " + roleName + " burst requires requests_per_second")
			}
			if grant.Limits.RequestsPerSecond > 1_000_000 || grant.Limits.Burst > 1_000_000 {
				return invalid("role " + roleName + " rate limit is unreasonably large")
			}
			if grant.Limits.MaxRequestBytes > compiled.File.Server.MaxRequestBytes {
				return invalid("role " + roleName + " max_request_bytes exceeds server limit")
			}
			key := grant.Service
			if _, duplicate := seen[key]; duplicate {
				return invalid("role " + roleName + " contains more than one grant for a service")
			}
			seen[key] = struct{}{}
			limits := grant.Limits.TokenLimits()
			if limits.MaxRequestBytes == 0 {
				limits.MaxRequestBytes = compiled.File.Server.MaxRequestBytes
			}
			grants = append(grants, tokens.Grant{
				Service: grant.Service, CredentialRef: grant.Credential,
				PolicyRevision: compiledPolicy.Revision, BindingRevision: compiled.BindingRevisions[grant.Credential],
				Limits: limits,
			})
		}
		compiled.Roles[roleName] = grants
	}
	return nil
}

// validateCapabilityManifestBound proves at compile time that every set of
// revision-current concrete grants can produce the bounded discovery
// document. It considers the largest public policy projection for every
// service and then the largest permitted combination, so tokens minted under
// a role that was later changed remain covered. Delegation can replace an
// unlimited numeric ceiling with any finite value, so all numeric fields use
// their longest possible representation here.
func validateCapabilityManifestBound(compiled *Compiled) error {
	type manifestAuth struct {
		Header string `json:"header"`
		Prefix string `json:"prefix,omitempty"`
	}
	type manifestService struct {
		Name              string        `json:"name"`
		Adapter           string        `json:"adapter"`
		BaseURL           string        `json:"base_url,omitempty"`
		PathPrefix        string        `json:"path_prefix,omitempty"`
		Host              string        `json:"host,omitempty"`
		Auth              manifestAuth  `json:"auth"`
		CapabilitySummary string        `json:"capability_summary,omitempty"`
		ConfiguredLimits  tokens.Limits `json:"configured_limits,omitempty"`
	}
	type manifestEnvelope struct {
		Version     int               `json:"version"`
		GeneratedAt time.Time         `json:"generated_at"`
		ExpiresAt   time.Time         `json:"expires_at"`
		Services    []manifestService `json:"services"`
	}

	max := ^uint64(0)
	longestLimits := tokens.Limits{
		RequestsPerSecond: max, Burst: max, RequestBudget: max,
		ByteBudget: max, MaxRequestBytes: max,
	}
	largestByService := make(map[string]manifestService, len(compiled.capabilityServices))
	largestSize := make(map[string]int, len(compiled.capabilityServices))
	for _, policyEntry := range compiled.Policies {
		projection, ok := compiled.capabilityServices[policyEntry.Service]
		if !ok {
			return invalid("policy " + policyEntry.Name + " has no capability projection")
		}
		candidate := manifestService{
			Name: policyEntry.Service, Adapter: projection.Adapter, BaseURL: projection.BaseURL,
			PathPrefix: projection.PathPrefix, Host: projection.Host,
			Auth:              manifestAuth{Header: http.CanonicalHeaderKey(projection.ClientHeader), Prefix: projection.ClientPrefix},
			CapabilitySummary: policyEntry.CapabilitySummary, ConfiguredLimits: longestLimits,
		}
		encoded, err := json.Marshal(candidate)
		if err != nil {
			return invalid("capability projection could not be encoded")
		}
		if len(encoded) > largestSize[policyEntry.Service] {
			largestByService[policyEntry.Service] = candidate
			largestSize[policyEntry.Service] = len(encoded)
		}
	}
	services := make([]manifestService, 0, len(largestByService))
	for _, service := range largestByService {
		services = append(services, service)
	}
	sort.Slice(services, func(i, j int) bool { return largestSize[services[i].Name] > largestSize[services[j].Name] })
	if len(services) > CapabilityManifestMaxServices {
		services = services[:CapabilityManifestMaxServices]
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	generatedAt := time.Date(9998, time.December, 31, 23, 59, 58, 999999999, time.UTC)
	encoded, err := json.Marshal(manifestEnvelope{
		Version: 1, GeneratedAt: generatedAt, ExpiresAt: generatedAt.Add(time.Second), Services: services,
	})
	if err != nil || len(encoded)+1 > CapabilityManifestMaxBytes {
		return invalid("capability manifest projections exceed the size limit")
	}
	return nil
}

func bindingRevision(compiled *Compiled, credentialName string, credential CredentialConfig) (string, error) {
	service := compiled.File.Services[credential.Service]
	var gitRepositoryCase gitadapter.RepositoryCaseMode
	if service.Git != nil {
		gitRepositoryCase = service.Git.RepositoryCase
	}
	prefixes := make([]string, 0, len(compiled.AllowedPrefixes[credential.Service]))
	for _, prefix := range compiled.AllowedPrefixes[credential.Service] {
		prefixes = append(prefixes, prefix.String())
	}
	sort.Strings(prefixes)
	pins := append([]string(nil), service.PinnedSPKISHA256...)
	sort.Strings(pins)
	requireIdentity := true
	if service.Response.RequireIdentity != nil {
		requireIdentity = *service.Response.RequireIdentity
	}
	material := struct {
		Engine                                                     string
		ServiceName, Upstream, AdvertisedBaseURL, PathPrefix, Host string
		AllowInsecureUpstream                                      bool
		AllowedCIDRs, PinnedSPKI, Forward                          []string
		StaticHeaders                                              []string
		ClientHeader, ClientPrefix                                 string
		StripHeaders                                               []string
		RequireIdentity                                            bool
		CredentialName, SecretRef                                  string
		InjectHeader, InjectPrefix                                 string
		SecretBackend, SecretCommand, EnvPrefix                    string
		SecretArgs                                                 []string
		GlobalMaxRequestBytes                                      uint64
		ReadTimeout                                                Duration
	}{
		Engine:      BindingEngineRevision,
		ServiceName: credential.Service, Upstream: compiled.Upstreams[credential.Service].String(),
		AdvertisedBaseURL: compiled.File.Server.AdvertisedBaseURL,
		PathPrefix:        service.PathPrefix, Host: strings.ToLower(service.Host),
		AllowInsecureUpstream: service.AllowInsecureUpstream, AllowedCIDRs: prefixes,
		PinnedSPKI: pins, Forward: canonicalHeaders(service.ForwardHeaders),
		StaticHeaders: canonicalStaticHeaders(service.StaticHeaders),
		ClientHeader:  strings.ToLower(service.ClientAuth.Header), ClientPrefix: service.ClientAuth.Prefix,
		StripHeaders: canonicalHeaders(service.Response.StripHeaders), RequireIdentity: requireIdentity,
		CredentialName: credentialName, SecretRef: credential.SecretRef,
		InjectHeader: strings.ToLower(credential.Inject.Header), InjectPrefix: credential.Inject.Prefix,
		SecretBackend: compiled.File.Secrets.Type, SecretCommand: compiled.File.Secrets.Command,
		EnvPrefix: compiled.File.Secrets.EnvPrefix, SecretArgs: append([]string(nil), compiled.File.Secrets.Args...),
		GlobalMaxRequestBytes: compiled.File.Server.MaxRequestBytes,
		ReadTimeout:           compiled.File.Server.ReadTimeout,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	if credential.BasicUsername != "" {
		basicMaterial := struct {
			Engine   string
			Username string
			Base     [sha256.Size]byte
		}{
			Engine: "forcefield-binding-basic-password/v1", Username: credential.BasicUsername, Base: digest,
		}
		encoded, err = json.Marshal(basicMaterial)
		if err != nil {
			return "", err
		}
		digest = sha256.Sum256(encoded)
	}
	if service.Adapter == AdapterGitSmartHTTP {
		gitMaterial := struct {
			Engine         string
			Adapter        string
			RepositoryCase gitadapter.RepositoryCaseMode
			Base           [sha256.Size]byte
		}{
			Engine: "forcefield-binding-git-smart-http/v1", Adapter: service.Adapter,
			RepositoryCase: gitRepositoryCase, Base: digest,
		}
		encoded, err = json.Marshal(gitMaterial)
		if err != nil {
			return "", err
		}
		digest = sha256.Sum256(encoded)
	}
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalHeaders(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.ToLower(value)
	}
	sort.Strings(result)
	return result
}

func canonicalStaticHeaders(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for name, value := range values {
		result = append(result, strings.ToLower(name)+"\x00"+value)
	}
	sort.Strings(result)
	return result
}

func policyRevision(spec PolicyConfig, compiled *policy.Policy) (string, error) {
	material := struct {
		Engine            string
		Service           string
		CapabilitySummary string
		Options           policy.Options
		Rules             []policy.RuleSpec
	}{
		Engine: policy.EngineRevision, Service: spec.Service, CapabilitySummary: spec.CapabilitySummary,
		Options: compiled.EffectiveOptions(), Rules: canonicalPolicyRules(spec.Rules),
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func compileGitPolicy(spec GitPolicyConfig, repositoryCase gitadapter.RepositoryCaseMode) (*gitadapter.Policy, error) {
	if len(spec.Rules) == 0 || len(spec.Rules) > 256 {
		return nil, errors.New("git policy must contain between 1 and 256 rules")
	}
	compiled := make([]gitadapter.Rule, 0, len(spec.Rules))
	seenIDs := make(map[string]struct{}, len(spec.Rules))
	auditBytes := 0
	for _, source := range spec.Rules {
		if !validID(source.ID) {
			return nil, errors.New("git rule has an invalid id")
		}
		if _, duplicate := seenIDs[source.ID]; duplicate {
			return nil, errors.New("git rule ids must be unique")
		}
		seenIDs[source.ID] = struct{}{}
		auditBytes += len(source.ID)
		if len(seenIDs) > 1 {
			auditBytes++
		}
		if auditBytes > 1024 {
			return nil, errors.New("git rule ids exceed the audit metadata limit")
		}
		if source.Effect != gitadapter.EffectAllow && source.Effect != gitadapter.EffectDeny {
			return nil, errors.New("git rule effect must be allow or deny")
		}
		if source.Operation != gitadapter.OperationFetch && source.Operation != gitadapter.OperationPush {
			return nil, errors.New("git rule operation must be fetch or push")
		}
		repositories, err := compileGitStringMatchers(source.Repositories, true, repositoryCase)
		if err != nil {
			return nil, fmt.Errorf("git rule %s repositories: %w", source.ID, err)
		}
		refs, err := compileGitStringMatchers(source.Refs, false, repositoryCase)
		if err != nil {
			return nil, fmt.Errorf("git rule %s refs: %w", source.ID, err)
		}
		if source.Operation == gitadapter.OperationFetch && (len(source.Refs) != 0 || len(source.UpdateKinds) != 0) {
			return nil, errors.New("fetch rules cannot claim ref-level confidentiality")
		}
		if source.Operation == gitadapter.OperationPush && source.Effect == gitadapter.EffectAllow && (len(source.Refs) == 0 || len(source.UpdateKinds) == 0) {
			return nil, errors.New("allow push rules require explicit refs and update_kinds")
		}
		seenKinds := make(map[gitadapter.UpdateKind]struct{}, len(source.UpdateKinds))
		for _, kind := range source.UpdateKinds {
			if kind != gitadapter.UpdateCreate && kind != gitadapter.UpdateModify && kind != gitadapter.UpdateDelete {
				return nil, errors.New("git update kind must be create, update, or delete")
			}
			if _, duplicate := seenKinds[kind]; duplicate {
				return nil, errors.New("git update kinds must be unique")
			}
			seenKinds[kind] = struct{}{}
		}
		rule := gitadapter.Rule{
			ID: source.ID, Effect: source.Effect, Repositories: repositories,
			Operations: []gitadapter.Operation{source.Operation}, Refs: refs,
			UpdateKinds: append([]gitadapter.UpdateKind(nil), source.UpdateKinds...),
		}
		if source.Operation == gitadapter.OperationFetch {
			rule.Services = []gitadapter.Service{gitadapter.ServiceUploadPack}
		} else {
			rule.Services = []gitadapter.Service{gitadapter.ServiceReceivePack}
			rule.ProtocolVersions = []int{0, 1}
			if source.Effect == gitadapter.EffectAllow {
				rule.Signed = gitadapter.Bool(false)
				rule.HasPushOptions = gitadapter.Bool(false)
			}
		}
		compiled = append(compiled, rule)
	}
	return gitadapter.NewPolicy(compiled)
}

// compileGitStringMatchers accepts exact values and one deliberately small
// recursive form: "prefix/**". A lone "**" is an explicit match-all. There is
// request identities are normalized according to the service's explicit case
// mode before this byte-for-byte matcher is evaluated.
func compileGitStringMatchers(patterns []string, repository bool, repositoryCase gitadapter.RepositoryCaseMode) ([]gitadapter.StringMatcher, error) {
	if repository && len(patterns) == 0 {
		return nil, errors.New("at least one repository pattern is required")
	}
	if len(patterns) > 256 {
		return nil, errors.New("too many patterns")
	}
	seen := make(map[string]struct{}, len(patterns))
	result := make([]gitadapter.StringMatcher, 0, len(patterns))
	for _, pattern := range patterns {
		if repository {
			var err error
			pattern, err = gitadapter.NormalizeRepository(pattern, repositoryCase)
			if err != nil {
				return nil, errors.New("repository pattern is incompatible with repository_case")
			}
		}
		if _, duplicate := seen[pattern]; duplicate {
			return nil, errors.New("duplicate pattern")
		}
		seen[pattern] = struct{}{}
		if pattern == "**" {
			if len(patterns) != 1 {
				return nil, errors.New("match-all must be the only pattern")
			}
			return nil, nil
		}
		if pattern == "" || len(pattern) > 1024 || strings.ContainsAny(pattern, "\\%?#\x00\r\n") || strings.Contains(pattern, "//") || strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "/**") {
			return nil, errors.New("invalid pattern")
		}
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "**")
			if err := validateGitPatternValue(prefix+gitPatternSample(repository), repository); err != nil {
				return nil, err
			}
			result = append(result, gitadapter.StringMatcher{Prefix: prefix})
			continue
		}
		if err := validateGitPatternValue(pattern, repository); err != nil {
			return nil, err
		}
		result = append(result, gitadapter.StringMatcher{Exact: pattern})
	}
	return result, nil
}

func gitPatternSample(repository bool) string {
	if repository {
		return "repository.git"
	}
	return "ref"
}

func validateGitPatternValue(value string, repository bool) error {
	if !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return errors.New("pattern is not canonical")
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("pattern is not canonical")
		}
	}
	if repository {
		if !strings.HasSuffix(value, ".git") {
			return errors.New("repository patterns must resolve to .git paths")
		}
		for _, current := range value {
			if unicode.IsControl(current) || unicode.Is(unicode.Cf, current) || unicode.Is(unicode.Zl, current) || unicode.Is(unicode.Zp, current) {
				return errors.New("repository pattern contains an unsafe character")
			}
		}
		return nil
	}
	if err := gitadapter.ValidateRefName(value); err != nil {
		return errors.New("ref pattern is not a valid full ref")
	}
	return nil
}

func gitPolicyRevision(spec PolicyConfig, repositoryCase gitadapter.RepositoryCaseMode) (string, error) {
	rules := append([]GitRuleConfig(nil), spec.Git.Rules...)
	for index := range rules {
		rules[index].Repositories = append([]string(nil), rules[index].Repositories...)
		rules[index].Refs = append([]string(nil), rules[index].Refs...)
		rules[index].UpdateKinds = append([]gitadapter.UpdateKind(nil), rules[index].UpdateKinds...)
		sort.Strings(rules[index].Repositories)
		sort.Strings(rules[index].Refs)
		sort.Slice(rules[index].UpdateKinds, func(i, j int) bool { return rules[index].UpdateKinds[i] < rules[index].UpdateKinds[j] })
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	material := struct {
		Engine            string
		Service           string
		CapabilitySummary string
		RepositoryCase    gitadapter.RepositoryCaseMode
		Rules             []GitRuleConfig
	}{
		Engine: "forcefield-git-policy/v1", Service: spec.Service,
		CapabilitySummary: spec.CapabilitySummary, RepositoryCase: repositoryCase, Rules: rules,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalPolicyRules(rules []policy.RuleSpec) []policy.RuleSpec {
	result := append([]policy.RuleSpec(nil), rules...)
	for index := range result {
		result[index].Methods = append([]string(nil), result[index].Methods...)
		result[index].Paths = append([]string(nil), result[index].Paths...)
		sort.Strings(result[index].Methods)
		sort.Strings(result[index].Paths)
		if result[index].GraphQL != nil {
			graphql := *result[index].GraphQL
			graphql.RootFields = append([]string(nil), graphql.RootFields...)
			sort.Strings(graphql.RootFields)
			result[index].GraphQL = &graphql
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func GrantID(grant tokens.Grant) string {
	encoded, _ := json.Marshal(grant)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:8])
}

// ResolveGrant verifies that a concrete token grant still names the currently
// loaded service, credential binding, and compiled policy revision. It is the
// shared configuration check used by request authorization and capability
// discovery; it never resolves credential material.
func (compiled *Compiled) ResolveGrant(grant tokens.Grant) (CompiledPolicy, bool) {
	if compiled == nil {
		return CompiledPolicy{}, false
	}
	credentialService, credentialOK := compiled.credentialServices[grant.CredentialRef]
	binding, bindingOK := compiled.bindingRevisions[grant.CredentialRef]
	policyEntry, policyOK := compiled.policyRevisions[grant.PolicyRevision]
	_, serviceOK := compiled.capabilityServices[grant.Service]
	if !serviceOK || !credentialOK || credentialService != grant.Service || !bindingOK ||
		binding == "" || grant.BindingRevision != binding || !policyOK || policyEntry.Service != grant.Service {
		return CompiledPolicy{}, false
	}
	return policyEntry, true
}

// ResolveCapabilityGrant returns an immutable, secret-free projection of a
// concrete grant only while its credential binding and policy revision remain
// current.
func (compiled *Compiled) ResolveCapabilityGrant(grant tokens.Grant) (CapabilityProjection, bool) {
	policyEntry, ok := compiled.ResolveGrant(grant)
	if !ok {
		return CapabilityProjection{}, false
	}
	projection, ok := compiled.capabilityServices[grant.Service]
	if !ok {
		return CapabilityProjection{}, false
	}
	projection.CapabilitySummary = policyEntry.CapabilitySummary
	return projection, true
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || tokens.ContainsBearer(value) {
		return false
	}
	for i, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || i > 0 && (r == '-' || r == '_') {
			continue
		}
		return false
	}
	return true
}

func validCapabilitySummary(value string) bool {
	if len(value) > 512 || strings.TrimSpace(value) != value || !validAgentVisibleText(value) {
		return false
	}
	return true
}

func validAgentVisibleText(value string) bool {
	if !utf8.ValidString(value) || tokens.ContainsBearer(value) {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) || unicode.Is(unicode.Cf, current) || unicode.Is(unicode.Zl, current) || unicode.Is(unicode.Zp, current) {
			return false
		}
	}
	return true
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validHeader(auth HeaderAuth) bool {
	if len(auth.Header) > CapabilityAuthHeaderMaxBytes || !validHeaderName(auth.Header) || len(auth.Prefix) > 256 || tokens.ContainsBearer(auth.Header) || tokens.ContainsBearer(auth.Prefix) {
		return false
	}
	for index := 0; index < len(auth.Prefix); index++ {
		if auth.Prefix[index] < 0x20 || auth.Prefix[index] > 0x7e {
			return false
		}
	}
	return true
}

func validAuthHeader(auth HeaderAuth) bool {
	return validHeader(auth) && !isHopHeader(auth.Header) && !isFramingHeader(auth.Header) && !strings.EqualFold(auth.Header, "Host")
}

func validBasicUsername(value string) bool {
	if value == "" || len(value) > 256 || tokens.ContainsBearer(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == ':' {
			return false
		}
	}
	return true
}

func gitDerivedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "git-protocol", "content-type", "content-encoding", "accept-encoding", "content-length", "transfer-encoding":
		return true
	default:
		return false
	}
}

func isFramingHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "content-encoding", "content-type":
		return true
	default:
		return false
	}
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))) {
			return false
		}
	}
	return true
}

func isHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
		return true
	default:
		return false
	}
}

func validSecretReference(value string, environment bool) bool {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for i, r := range value {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || !environment && i > 0 && strings.ContainsRune(".-:/", r) {
			continue
		}
		return false
	}
	return true
}

func validEnvPrefix(value string) bool {
	if value == "" || len(value) > 128 || value[len(value)-1] != '_' {
		return false
	}
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func invalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalidConfig, message) }
