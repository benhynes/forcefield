// Package capabilities projects live Forcefield token grants into a bounded,
// secret-free description suitable for agent context. A Manifest is advisory:
// the gateway remains authoritative for every request.
package capabilities

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/tokens"
)

const (
	SchemaVersion       = 1
	MaxManifestSize     = config.CapabilityManifestMaxBytes
	MaxContextBytes     = 9_000
	MaxToolContextBytes = 32 << 10
)

var ErrInvalidManifest = errors.New("invalid Forcefield capability manifest")

type Manifest struct {
	Version     int       `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Services    []Service `json:"services"`
}

type Service struct {
	Name              string `json:"name"`
	Adapter           string `json:"adapter"`
	BaseURL           string `json:"base_url,omitempty"`
	PathPrefix        string `json:"path_prefix,omitempty"`
	Host              string `json:"host,omitempty"`
	Auth              Auth   `json:"auth"`
	CapabilitySummary string `json:"capability_summary,omitempty"`
	ConfiguredLimits  Limits `json:"configured_limits,omitempty"`
}

type Auth struct {
	Header string `json:"header"`
	Prefix string `json:"prefix,omitempty"`
}

// Limits is a capability-specific projection of configured grant ceilings.
// Keeping it separate from tokens.Limits prevents future token-store fields
// from becoming agent-visible by accident.
type Limits struct {
	RequestsPerSecond uint64 `json:"requests_per_second,omitempty"`
	Burst             uint64 `json:"burst,omitempty"`
	RequestBudget     uint64 `json:"request_budget,omitempty"`
	ByteBudget        uint64 `json:"byte_budget,omitempty"`
	MaxRequestBytes   uint64 `json:"max_request_bytes,omitempty"`
}

// Build returns the sanitized projection of the supplied concrete grants.
// Grants whose policy or credential binding no longer resolves are omitted.
// Callers must validate the bearer and its workload before calling Build.
func Build(compiled *config.Compiled, generatedAt, expiresAt time.Time, grants []tokens.Grant) (Manifest, error) {
	if compiled == nil || generatedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(generatedAt) {
		return Manifest{}, ErrInvalidManifest
	}
	manifest := Manifest{
		Version: SchemaVersion, GeneratedAt: generatedAt.UTC(), ExpiresAt: expiresAt.UTC(),
		Services: make([]Service, 0, len(grants)),
	}
	seen := make(map[string]struct{}, len(grants))
	for _, grant := range grants {
		if _, duplicate := seen[grant.Service]; duplicate {
			return Manifest{}, ErrInvalidManifest
		}
		seen[grant.Service] = struct{}{}
		projection, ok := compiled.ResolveCapabilityGrant(grant)
		if !ok {
			continue
		}
		manifest.Services = append(manifest.Services, Service{
			Name: grant.Service, Adapter: projection.Adapter,
			BaseURL: projection.BaseURL, PathPrefix: projection.PathPrefix, Host: projection.Host,
			Auth:              Auth{Header: http.CanonicalHeaderKey(projection.ClientHeader), Prefix: projection.ClientPrefix},
			CapabilitySummary: projection.CapabilitySummary, ConfiguredLimits: projectLimits(grant.Limits),
		})
	}
	sort.Slice(manifest.Services, func(i, j int) bool { return manifest.Services[i].Name < manifest.Services[j].Name })
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (manifest Manifest) Validate() error {
	if manifest.Version != SchemaVersion || manifest.GeneratedAt.IsZero() || manifest.ExpiresAt.IsZero() ||
		!manifest.ExpiresAt.After(manifest.GeneratedAt) || len(manifest.Services) > config.CapabilityManifestMaxServices {
		return ErrInvalidManifest
	}
	previous := ""
	for _, service := range manifest.Services {
		if !validID(service.Name) || service.Name <= previous || !validAdapter(service.Adapter) ||
			(service.PathPrefix == "") == (service.Host == "") || !validHeader(service.Auth.Header) ||
			!validAuthPrefix(service.Auth.Prefix) ||
			!validSummary(service.CapabilitySummary) || serviceContainsBearer(service) {
			return ErrInvalidManifest
		}
		if service.PathPrefix != "" && !validPathPrefix(service.PathPrefix) {
			return ErrInvalidManifest
		}
		if service.Host != "" && !validHost(service.Host) {
			return ErrInvalidManifest
		}
		if service.BaseURL != "" && !validServiceURL(service) {
			return ErrInvalidManifest
		}
		if service.ConfiguredLimits.RequestsPerSecond == 0 && service.ConfiguredLimits.Burst != 0 {
			return ErrInvalidManifest
		}
		previous = service.Name
	}
	return nil
}

func validAdapter(value string) bool {
	return value == config.AdapterHTTP || value == config.AdapterGitSmartHTTP
}

func serviceContainsBearer(service Service) bool {
	for _, value := range []string{
		service.Name, service.Adapter, service.BaseURL, service.PathPrefix, service.Host,
		service.Auth.Header, service.Auth.Prefix, service.CapabilitySummary,
	} {
		if tokens.ContainsBearer(value) {
			return true
		}
	}
	return false
}

func validServiceURL(service Service) bool {
	if len(service.BaseURL) > config.CapabilityServiceURLMaxBytes || !validAgentVisibleText(service.BaseURL) {
		return false
	}
	parsed, err := url.Parse(service.BaseURL)
	if err != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if address := net.ParseIP(host); address == nil {
		if !validHost(host) {
			return false
		}
	}
	if parsed.Scheme == "http" && !loopbackHost(host) {
		return false
	}
	if port := parsed.Port(); port != "" {
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
			return false
		}
	}
	if service.PathPrefix != "" {
		return parsed.Path == service.PathPrefix
	}
	return parsed.Path == "" && strings.EqualFold(host, service.Host)
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || tokens.ContainsBearer(value) {
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

func validHost(value string) bool {
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, current := range label {
			if !(current >= 'a' && current <= 'z' || current >= '0' && current <= '9' || current == '-') {
				return false
			}
		}
	}
	return true
}

func validHeader(value string) bool {
	if value == "" || len(value) > config.CapabilityAuthHeaderMaxBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if !(current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(current))) {
			return false
		}
	}
	return true
}

func validAuthPrefix(value string) bool {
	if len(value) > 256 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validPathPrefix(value string) bool {
	if len(value) > config.CapabilityServiceURLMaxBytes || value == "" || value == "/" || value[0] != '/' || strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		!validAgentVisibleText(value) {
		return false
	}
	escaped := (&url.URL{Path: value}).EscapedPath()
	canonical, err := policy.CanonicalPath(escaped)
	if err != nil {
		return false
	}
	decoded, err := url.PathUnescape(canonical)
	return err == nil && decoded == value
}

func validSummary(value string) bool {
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

type RenderOptions struct {
	Now            time.Time
	TokenFile      string
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
}

func RenderMarkdown(manifest Manifest, options RenderOptions) (string, error) {
	if err := manifest.Validate(); err != nil {
		return "", err
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Forcefield configured-grant snapshot (generated %s; token expires %s):\n", manifest.GeneratedAt.Format(time.RFC3339), manifest.ExpiresAt.Format(time.RFC3339))
	if !now.Before(manifest.ExpiresAt) {
		output.WriteString("No revision-current Forcefield service grants were confirmed because this snapshot has expired.\n")
		output.WriteString(contextFooter())
		return output.String(), nil
	}
	if len(manifest.Services) == 0 {
		output.WriteString("No revision-current Forcefield service grants were reported.\n")
		output.WriteString(contextFooter())
		return output.String(), nil
	}

	footer := contextFooter()
	for index, service := range manifest.Services {
		block := renderService(service, options)
		if output.Len()+len(block)+len(footer) > MaxContextBytes {
			remaining := len(manifest.Services) - index
			omitted := fmt.Sprintf("- %d additional configured service grants omitted from startup context; call the Forcefield capabilities tool and follow its cursor pagination.\n", remaining)
			if output.Len()+len(omitted)+len(footer) <= MaxContextBytes {
				output.WriteString(omitted)
			}
			break
		}
		output.WriteString(block)
	}
	output.WriteString(footer)
	if output.Len() > MaxContextBytes {
		return "", ErrInvalidManifest
	}
	return output.String(), nil
}

// RenderMarkdownPage renders a bounded page for an interactive capability
// tool. It is deliberately separate from RenderMarkdown's smaller startup
// context so a tool caller can page lexicographically through services without
// forcing the entire manifest into one model turn. The cursor is the last
// service name returned; this remains monotonic if a live snapshot changes
// between calls. An empty nextCursor means complete.
func RenderMarkdownPage(manifest Manifest, options RenderOptions, cursor string) (text string, nextCursor string, err error) {
	if err := manifest.Validate(); err != nil || cursor != "" && !validID(cursor) {
		return "", "", ErrInvalidManifest
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	var output strings.Builder
	fmt.Fprintf(&output, "Forcefield configured-grant snapshot page (generated %s; token expires %s):\n", manifest.GeneratedAt.Format(time.RFC3339), manifest.ExpiresAt.Format(time.RFC3339))
	footer := contextFooter()
	if !now.Before(manifest.ExpiresAt) {
		output.WriteString("No revision-current Forcefield service grants were confirmed because this snapshot has expired.\n")
		output.WriteString(footer)
		return output.String(), "", nil
	}
	if len(manifest.Services) == 0 {
		output.WriteString("No revision-current Forcefield service grants were reported.\n")
		output.WriteString(footer)
		return output.String(), "", nil
	}
	start := sort.Search(len(manifest.Services), func(index int) bool {
		return manifest.Services[index].Name > cursor
	})
	if start == len(manifest.Services) {
		output.WriteString("No additional configured service grants remain.\n")
		output.WriteString(footer)
		return output.String(), "", nil
	}

	lastRendered := ""
	for index := start; index < len(manifest.Services); index++ {
		block := renderService(manifest.Services[index], options)
		continuationReserve := 0
		if index+1 < len(manifest.Services) {
			continuationReserve = 320
		}
		if output.Len()+len(block)+len(footer)+continuationReserve > MaxToolContextBytes {
			if index == start || lastRendered == "" {
				return "", "", ErrInvalidManifest
			}
			nextCursor = lastRendered
			break
		}
		output.WriteString(block)
		lastRendered = manifest.Services[index].Name
	}
	if nextCursor != "" {
		fmt.Fprintf(&output, "More configured service grants remain. Call this tool again with {\"cursor\":%q}.\n", nextCursor)
	}
	output.WriteString(footer)
	if output.Len() > MaxToolContextBytes {
		return "", "", ErrInvalidManifest
	}
	return output.String(), nextCursor, nil
}

func renderService(service Service, options RenderOptions) string {
	var output strings.Builder
	fmt.Fprintf(&output, "- %s (%s)", service.Name, service.Adapter)
	if service.BaseURL != "" {
		fmt.Fprintf(&output, ": %s", service.BaseURL)
	} else if service.PathPrefix != "" {
		fmt.Fprintf(&output, ": route %s", service.PathPrefix)
	} else {
		fmt.Fprintf(&output, ": host %s", service.Host)
	}
	output.WriteByte('\n')
	fmt.Fprintf(&output, "  Authentication carrier: %s: %s<Forcefield token>", service.Auth.Header, service.Auth.Prefix)
	tokenFile := contextPath(options.TokenFile)
	if tokenFile != "" {
		fmt.Fprintf(&output, " from %q", tokenFile)
	}
	output.WriteByte('\n')
	if service.Adapter == config.AdapterGitSmartHTTP {
		output.WriteString("  Protocol: Git smart HTTP only; repository URLs must end in .git. Git LFS, dumb HTTP, archives, SSH, and provider web/API routes are not part of this service.\n")
		if service.BaseURL != "" && tokenFile != "" {
			fmt.Fprintf(&output, "  Native Git authentication: scope a credential helper to this exact service URL, clear inherited helpers, enable useHttpPath, and invoke `ff git-credential --url %q --token-file %q`.\n", service.BaseURL, tokenFile)
		}
	}
	if service.CapabilitySummary != "" {
		fmt.Fprintf(&output, "  Scope: %s\n", service.CapabilitySummary)
	}
	if limits := renderLimits(service.ConfiguredLimits); limits != "" {
		fmt.Fprintf(&output, "  Configured ceilings: %s\n", limits)
	}
	if caCertPath := contextPath(options.CACertPath); caCertPath != "" && strings.HasPrefix(service.BaseURL, "https://") {
		fmt.Fprintf(&output, "  TLS CA certificate: %q\n", caCertPath)
	}
	clientCertPath := contextPath(options.ClientCertPath)
	clientKeyPath := contextPath(options.ClientKeyPath)
	if clientCertPath != "" && clientKeyPath != "" && strings.HasPrefix(service.BaseURL, "https://") {
		fmt.Fprintf(&output, "  TLS client identity: certificate %q; private key %q\n", clientCertPath, clientKeyPath)
	}
	return output.String()
}

func contextPath(value string) string {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || tokens.ContainsBearer(value) {
		return ""
	}
	for _, current := range value {
		if unicode.IsControl(current) || unicode.Is(unicode.Cf, current) || unicode.Is(unicode.Zl, current) || unicode.Is(unicode.Zp, current) {
			return ""
		}
	}
	return value
}

func projectLimits(limits tokens.Limits) Limits {
	return Limits{
		RequestsPerSecond: limits.RequestsPerSecond,
		Burst:             limits.Burst,
		RequestBudget:     limits.RequestBudget,
		ByteBudget:        limits.ByteBudget,
		MaxRequestBytes:   limits.MaxRequestBytes,
	}
}

func renderLimits(limits Limits) string {
	parts := make([]string, 0, 5)
	if limits.RequestsPerSecond != 0 {
		parts = append(parts, fmt.Sprintf("%d requests/s", limits.RequestsPerSecond))
	}
	if limits.Burst != 0 {
		parts = append(parts, fmt.Sprintf("burst %d", limits.Burst))
	}
	if limits.RequestBudget != 0 {
		parts = append(parts, fmt.Sprintf("%d requests", limits.RequestBudget))
	}
	if limits.ByteBudget != 0 {
		parts = append(parts, fmt.Sprintf("%d bytes", limits.ByteBudget))
	}
	if limits.MaxRequestBytes != 0 {
		parts = append(parts, fmt.Sprintf("%d bytes/request", limits.MaxRequestBytes))
	}
	return strings.Join(parts, ", ")
}

func contextFooter() string {
	return "Remaining request and byte quota is not reported; a listed grant may already be exhausted. Forcefield validates every request and remains authoritative. A generic 404 can mean either nonexistent or outside the current grant. This snapshot contains no provider credential, bearer value, or private-key value.\n"
}

func UnavailableContext() string {
	return "Forcefield capability lookup did not confirm any revision-current configured external-service grants. Do not assume external access; Forcefield remains authoritative for every request.\n"
}
