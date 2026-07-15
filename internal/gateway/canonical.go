package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/benhynes/forcefield/internal/policy"
)

const (
	defaultMaxQueryBytes = 16 << 10
	defaultMaxQueryPairs = 256
)

var ErrInvalidTarget = errors.New("invalid request target")

// CanonicalURL is the single representation used by policy evaluation and by
// the outbound request. Raw attacker-controlled URL bytes are never replayed.
type CanonicalURL struct {
	Path     string
	RawQuery string
	Query    url.Values
}

// CanonicalizeURL rejects ambiguous request targets, normalizes their path,
// and parses/re-encodes their query string. In particular, encoded path
// separators and encoded percent-triplets are rejected to prevent a second
// decoder upstream from seeing a different resource than Forcefield did.
func CanonicalizeURL(u *url.URL) (CanonicalURL, error) {
	if u == nil || u.IsAbs() || u.Host != "" || u.Opaque != "" {
		return CanonicalURL{}, ErrInvalidTarget
	}

	if u.RawPath != "" {
		decodedRawPath, err := url.PathUnescape(u.RawPath)
		if err != nil || decodedRawPath != u.Path {
			return CanonicalURL{}, ErrInvalidTarget
		}
	}
	escapedPath, err := policy.CanonicalPath(u.EscapedPath())
	if err != nil {
		return CanonicalURL{}, ErrInvalidTarget
	}
	path, err := url.PathUnescape(escapedPath)
	if err != nil {
		return CanonicalURL{}, ErrInvalidTarget
	}

	if len(u.RawQuery) > defaultMaxQueryBytes {
		return CanonicalURL{}, ErrInvalidTarget
	}
	canonicalQuery, err := policy.CanonicalQuery(u.RawQuery)
	if err != nil {
		return CanonicalURL{}, ErrInvalidTarget
	}
	query, err := url.ParseQuery(canonicalQuery)
	if err != nil {
		return CanonicalURL{}, ErrInvalidTarget
	}
	pairs := 0
	for key, values := range query {
		if key == "" {
			return CanonicalURL{}, ErrInvalidTarget
		}
		pairs += len(values)
	}
	if pairs > defaultMaxQueryPairs {
		return CanonicalURL{}, ErrInvalidTarget
	}

	return CanonicalURL{Path: path, RawQuery: canonicalQuery, Query: query}, nil
}

// Apply makes an outbound URL use the exact representation that policy saw.
func (c CanonicalURL) Apply(u *url.URL) error {
	if u == nil || c.Path == "" || !strings.HasPrefix(c.Path, "/") {
		return fmt.Errorf("%w: incomplete canonical URL", ErrInvalidTarget)
	}
	u.Path = c.Path
	u.RawPath = ""
	u.RawQuery = c.RawQuery
	u.ForceQuery = false
	return nil
}
