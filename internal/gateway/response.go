package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrSecretReflection = errors.New("upstream response contained injected credential")
	ErrUnsafeRedirect   = errors.New("upstream returned an unsafe redirect")
	ErrEncodedResponse  = errors.New("upstream returned an encoded response")
)

// ResponseGuard prevents the most direct ways an upstream response can turn
// an injected credential into a credential visible to the agent. It is
// defense in depth: a malicious upstream can transform a secret in ways that
// exact-value filtering cannot detect, so trusted upstreams and narrow grants
// remain mandatory.
type ResponseGuard struct {
	Upstream         *url.URL
	PublicPathPrefix string
	StripHeaders     []string
	RequireIdentity  bool
}

func (g ResponseGuard) Guard(resp *http.Response, secret []byte) error {
	if resp == nil || g.Upstream == nil || len(secret) == 0 {
		return errors.New("invalid response guard state")
	}
	strip := append([]string{"Set-Cookie", "Authentication-Info", "Proxy-Authenticate", "Alt-Svc", "Refresh", "Link"}, g.StripHeaders...)
	for _, name := range strip {
		resp.Header.Del(name)
	}
	for name, values := range resp.Header {
		if bytes.Contains(bytes.ToLower([]byte(name)), bytes.ToLower(secret)) {
			return ErrSecretReflection
		}
		for _, value := range values {
			if bytes.Contains([]byte(value), secret) {
				return ErrSecretReflection
			}
		}
	}
	if location := resp.Header.Get("Location"); location != "" {
		rewritten, err := g.rewriteLocation(resp.Request, location)
		if err != nil {
			return err
		}
		resp.Header.Set("Location", rewritten)
	}
	if g.RequireIdentity {
		encodings := headerValues(resp.Header, "Content-Encoding")
		if len(encodings) > 1 || len(encodings) == 1 && strings.TrimSpace(encodings[0]) != "" && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
			return ErrEncodedResponse
		}
	}
	if resp.Body != nil {
		resp.Body = newSecretFilteringBody(resp.Body, secret)
	}
	return nil
}

func headerValues(header http.Header, name string) []string {
	var result []string
	for key, values := range header {
		if strings.EqualFold(key, name) {
			result = append(result, values...)
		}
	}
	return result
}

func (g ResponseGuard) rewriteLocation(request *http.Request, raw string) (string, error) {
	location, err := url.Parse(raw)
	if err != nil || location.User != nil {
		return "", ErrUnsafeRedirect
	}
	base := g.Upstream
	if request != nil && request.URL != nil {
		base = request.URL
	}
	resolved := base.ResolveReference(location)
	if !strings.EqualFold(resolved.Scheme, g.Upstream.Scheme) || !equalAuthority(resolved, g.Upstream) {
		return "", ErrUnsafeRedirect
	}

	upstreamBase := strings.TrimSuffix(g.Upstream.EscapedPath(), "/")
	resolvedPath := resolved.EscapedPath()
	if upstreamBase != "" && upstreamBase != "/" {
		if resolvedPath != upstreamBase && !strings.HasPrefix(resolvedPath, upstreamBase+"/") {
			return "", ErrUnsafeRedirect
		}
		resolvedPath = strings.TrimPrefix(resolvedPath, upstreamBase)
	}
	if resolvedPath == "" {
		resolvedPath = "/"
	}
	prefix := strings.TrimSuffix(g.PublicPathPrefix, "/")
	result := prefix + resolvedPath
	if result == "" {
		result = "/"
	}
	if resolved.RawQuery != "" {
		result += "?" + resolved.RawQuery
	}
	if resolved.Fragment != "" {
		result += "#" + url.QueryEscape(resolved.Fragment)
	}
	return result, nil
}

func equalAuthority(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}

type secretFilteringBody struct {
	source      io.ReadCloser
	secret      []byte
	failure     []int
	pending     []byte
	terminalErr error
	found       bool
	noProgress  int
}

func newSecretFilteringBody(source io.ReadCloser, secret []byte) io.ReadCloser {
	copyOfSecret := append([]byte(nil), secret...)
	return &secretFilteringBody{source: source, secret: copyOfSecret, failure: prefixFailure(copyOfSecret)}
}

func (b *secretFilteringBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.found {
		return 0, ErrSecretReflection
	}
	if len(b.secret) == 0 {
		return b.source.Read(p)
	}

	for {
		if bytes.Contains(b.pending, b.secret) {
			b.found = true
			zeroBytes(b.pending)
			b.pending = nil
			return 0, ErrSecretReflection
		}
		hold := suffixPrefixOverlap(b.pending, b.secret, b.failure)
		if b.terminalErr != nil {
			hold = 0
		}
		safe := len(b.pending) - hold
		if safe > 0 {
			if safe > len(p) {
				safe = len(p)
			}
			copy(p, b.pending[:safe])
			copy(b.pending, b.pending[safe:])
			b.pending = b.pending[:len(b.pending)-safe]
			return safe, nil
		}
		if b.terminalErr != nil {
			err := b.terminalErr
			b.terminalErr = nil
			return 0, err
		}

		buffer := make([]byte, 32<<10)
		n, err := b.source.Read(buffer)
		if n > 0 {
			b.pending = append(b.pending, buffer[:n]...)
			b.noProgress = 0
		}
		if err != nil {
			b.terminalErr = err
		}
		if n == 0 && err == nil {
			b.noProgress++
			if b.noProgress >= 100 {
				b.terminalErr = io.ErrNoProgress
			}
			continue
		}
	}
}

func prefixFailure(pattern []byte) []int {
	failure := make([]int, len(pattern))
	for index, matched := 1, 0; index < len(pattern); index++ {
		for matched > 0 && pattern[index] != pattern[matched] {
			matched = failure[matched-1]
		}
		if pattern[index] == pattern[matched] {
			matched++
		}
		failure[index] = matched
	}
	return failure
}

func suffixPrefixOverlap(value, pattern []byte, failure []int) int {
	matched := 0
	for _, current := range value {
		for matched > 0 && current != pattern[matched] {
			matched = failure[matched-1]
		}
		if current == pattern[matched] {
			matched++
		}
		if matched == len(pattern) {
			matched = failure[matched-1]
		}
	}
	return matched
}

func (b *secretFilteringBody) Close() error {
	zeroBytes(b.secret)
	zeroBytes(b.pending)
	b.secret = nil
	b.failure = nil
	b.pending = nil
	return b.source.Close()
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func responseGuardError(err error) error {
	return fmt.Errorf("forcefield response guard: %w", err)
}
