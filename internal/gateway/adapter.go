package gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/benhynes/forcefield/internal/headersafety"
)

var ErrInvalidBrokerCredential = errors.New("invalid broker credential")

// HeaderAdapter swaps an opaque Forcefield token presented in one request
// header for an upstream secret in another. Header names and schemes are
// independent so Authorization, x-api-key, and Basic-style integrations do
// not require different gateway code.
type HeaderAdapter struct {
	clientHeader   string
	clientPrefix   string
	upstreamHeader string
	upstreamPrefix string
	basicUsername  string
	forwardHeaders map[string]struct{}
	staticHeaders  http.Header
}

type HeaderAdapterConfig struct {
	ClientHeader   string
	ClientPrefix   string
	UpstreamHeader string
	UpstreamPrefix string
	// UpstreamBasicUsername encodes the secret as the password in an HTTP
	// Basic Authorization value. It is mutually exclusive with UpstreamPrefix.
	UpstreamBasicUsername string
	ForwardHeaders        []string
	StaticHeaders         map[string]string
}

func NewHeaderAdapter(cfg HeaderAdapterConfig) (*HeaderAdapter, error) {
	client := http.CanonicalHeaderKey(cfg.ClientHeader)
	upstream := http.CanonicalHeaderKey(cfg.UpstreamHeader)
	if !validHeaderName(client) || !validHeaderName(upstream) || unsafeCredentialHeader(client) || unsafeCredentialHeader(upstream) {
		return nil, fmt.Errorf("invalid authentication header")
	}
	if containsHeaderControl(cfg.ClientPrefix) || containsHeaderControl(cfg.UpstreamPrefix) {
		return nil, fmt.Errorf("invalid authentication prefix")
	}
	if cfg.UpstreamBasicUsername != "" && (upstream != "Authorization" || cfg.UpstreamPrefix != "" || !validBasicUsername(cfg.UpstreamBasicUsername)) {
		return nil, fmt.Errorf("invalid upstream Basic authentication")
	}
	forward := make(map[string]struct{}, len(cfg.ForwardHeaders))
	for _, name := range cfg.ForwardHeaders {
		name = http.CanonicalHeaderKey(name)
		if !validHeaderName(name) || headersafety.CredentialBearing(name) || isHopByHopHeader(name) || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Accept-Encoding") || strings.EqualFold(name, client) || strings.EqualFold(name, upstream) {
			return nil, fmt.Errorf("unsafe forwarded header %q", name)
		}
		if _, duplicate := forward[name]; duplicate {
			return nil, fmt.Errorf("duplicate forwarded header %q", name)
		}
		forward[name] = struct{}{}
	}
	static := make(http.Header, len(cfg.StaticHeaders))
	for name, value := range cfg.StaticHeaders {
		name = http.CanonicalHeaderKey(name)
		if !validHeaderName(name) || headersafety.CredentialBearing(name) || unsafeCredentialHeader(name) || strings.EqualFold(name, "Accept-Encoding") || strings.EqualFold(name, client) || strings.EqualFold(name, upstream) ||
			len(value) > 8<<10 || strings.TrimSpace(value) != value || containsHeaderControl(value) {
			return nil, fmt.Errorf("unsafe static header %q", name)
		}
		if _, forwarded := forward[name]; forwarded {
			return nil, fmt.Errorf("header %q cannot be forwarded and static", name)
		}
		if _, duplicate := static[name]; duplicate {
			return nil, fmt.Errorf("duplicate canonical static header %q", name)
		}
		static.Set(name, value)
	}
	return &HeaderAdapter{
		clientHeader: client, clientPrefix: cfg.ClientPrefix,
		upstreamHeader: upstream, upstreamPrefix: cfg.UpstreamPrefix, basicUsername: cfg.UpstreamBasicUsername,
		forwardHeaders: forward,
		staticHeaders:  static,
	}, nil
}

func unsafeCredentialHeader(name string) bool {
	return isHopByHopHeader(name) || unsafeFramingHeader(name) || strings.EqualFold(name, "Host")
}

func unsafeFramingHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Content-Length", "Content-Encoding", "Content-Type":
		return true
	default:
		return false
	}
}

func (a *HeaderAdapter) ExtractToken(r *http.Request) (string, error) {
	if a == nil || r == nil {
		return "", ErrInvalidBrokerCredential
	}
	values := r.Header.Values(a.clientHeader)
	if len(values) != 1 || !strings.HasPrefix(values[0], a.clientPrefix) {
		return "", ErrInvalidBrokerCredential
	}
	token := strings.TrimPrefix(values[0], a.clientPrefix)
	if !strings.HasPrefix(token, "ff_") || len(token) < 16 || strings.TrimSpace(token) != token {
		return "", ErrInvalidBrokerCredential
	}
	return token, nil
}

// RewriteHeaders creates outbound headers from an allowlist, then injects the
// upstream credential with Set semantics. It never mutates the inbound map.
func (a *HeaderAdapter) RewriteHeaders(in, out http.Header, secret []byte) error {
	if a == nil || !validHeaderCredential(secret) {
		return errors.New("missing upstream credential")
	}
	for name := range out {
		out.Del(name)
	}
	for name := range a.forwardHeaders {
		for _, value := range in.Values(name) {
			if containsHeaderControl(value) {
				return fmt.Errorf("invalid value for forwarded header %q", name)
			}
			out.Add(name, value)
		}
	}
	for name, values := range a.staticHeaders {
		for _, value := range values {
			out.Add(name, value)
		}
	}
	value := a.upstreamPrefix + string(secret)
	if a.basicUsername != "" {
		payload := append([]byte(a.basicUsername+":"), secret...)
		value = "Basic " + base64.StdEncoding.EncodeToString(payload)
		zeroBytes(payload)
	}
	out.Set(a.upstreamHeader, value)
	return nil
}

// LeakPatterns returns independent copies of every exact credential
// representation the response guard can recognize. Basic authentication adds
// the base64 payload because reflecting it would expose the upstream password
// even though the raw secret bytes are absent.
func (a *HeaderAdapter) LeakPatterns(secret []byte) ([][]byte, error) {
	if a == nil || !validHeaderCredential(secret) {
		return nil, errors.New("missing upstream credential")
	}
	patterns := [][]byte{append([]byte(nil), secret...)}
	if a.basicUsername != "" {
		payload := append([]byte(a.basicUsername+":"), secret...)
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
		base64.StdEncoding.Encode(encoded, payload)
		zeroBytes(payload)
		patterns = append(patterns, encoded)
	}
	return patterns, nil
}

func validBasicUsername(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == ':' {
			return false
		}
	}
	return true
}

func zeroCredentialPatterns(patterns [][]byte) {
	for _, pattern := range patterns {
		zeroBytes(pattern)
	}
}

func validHeaderCredential(secret []byte) bool {
	if len(secret) == 0 || len(secret) > 16<<10 {
		return false
	}
	// Forcefield v1 injects credentials into HTTP fields. Restrict their wire
	// representation to visible ASCII so intermediaries cannot trim, fold, or
	// transcode the value into something the response leak guard did not scan.
	for _, value := range secret {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
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

func containsHeaderControl(value string) bool {
	return strings.ContainsAny(value, "\r\n\x00")
}

func isHopByHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return true
	default:
		return false
	}
}
