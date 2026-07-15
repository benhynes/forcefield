package policy

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

type canonicalRequest struct {
	method         string
	path           string
	pathSegments   []string
	query          url.Values
	canonicalQuery string
	contentType    string
	body           []byte
	json           any
	jsonParsed     bool
	jsonErr        error
	graphql        *graphqlRequest
	graphqlParsed  bool
	graphqlErr     error
}

func canonicalizeRequest(req Request) (*canonicalRequest, error) {
	if !validMethod(req.Method) {
		return nil, fmt.Errorf("%w: invalid HTTP method", ErrInvalidRequest)
	}
	path, segments, err := canonicalPathParts(req.EscapedPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	query, canonicalQuery, err := canonicalQuery(req.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return &canonicalRequest{
		method:         req.Method,
		path:           path,
		pathSegments:   segments,
		query:          query,
		canonicalQuery: canonicalQuery,
		contentType:    req.ContentType,
		body:           req.Body,
	}, nil
}

// CanonicalPath returns the single escaped spelling Forcefield uses for a
// path. Empty paths become "/". Dot segments, encoded slash/backslash, control
// characters, invalid UTF-8, and repeated slashes are rejected rather than
// normalized across a trust boundary.
func CanonicalPath(escapedPath string) (string, error) {
	path, _, err := canonicalPathParts(escapedPath)
	return path, err
}

func canonicalPathParts(escapedPath string) (string, []string, error) {
	if escapedPath == "" {
		escapedPath = "/"
	}
	if !strings.HasPrefix(escapedPath, "/") {
		return "", nil, fmt.Errorf("path must be absolute")
	}
	if strings.ContainsAny(escapedPath, "?#") {
		return "", nil, fmt.Errorf("path contains query or fragment delimiter")
	}
	if escapedPath == "/" {
		return "/", nil, nil
	}

	rawSegments := strings.Split(escapedPath[1:], "/")
	segments := make([]string, len(rawSegments))
	encoded := make([]string, len(rawSegments))
	for i, raw := range rawSegments {
		if raw == "" && i != len(rawSegments)-1 {
			return "", nil, fmt.Errorf("path contains repeated slash")
		}
		segment, err := url.PathUnescape(raw)
		if err != nil {
			return "", nil, fmt.Errorf("invalid escape in path segment %d", i)
		}
		if !utf8.ValidString(segment) {
			return "", nil, fmt.Errorf("path segment %d is not UTF-8", i)
		}
		if strings.ContainsAny(segment, "/\\;") {
			return "", nil, fmt.Errorf("path segment %d contains encoded separator", i)
		}
		if containsPercentTriplet(segment) {
			return "", nil, fmt.Errorf("path segment %d contains double-encoded octet", i)
		}
		if segment == "." || segment == ".." {
			return "", nil, fmt.Errorf("path contains dot segment")
		}
		if containsControl(segment) {
			return "", nil, fmt.Errorf("path segment %d contains control character", i)
		}
		segments[i] = segment
		encoded[i] = url.PathEscape(segment)
	}
	return "/" + strings.Join(encoded, "/"), segments, nil
}

// CanonicalQuery parses a query with Go's strict URL decoder and returns a
// deterministic spelling. Values are sorted by key and value. Invalid escapes,
// raw semicolons, invalid UTF-8, and control characters are rejected.
func CanonicalQuery(rawQuery string) (string, error) {
	_, canonical, err := canonicalQuery(rawQuery)
	return canonical, err
}

func canonicalQuery(rawQuery string) (url.Values, string, error) {
	if strings.Contains(rawQuery, "+") {
		return nil, "", fmt.Errorf("raw plus is ambiguous in query")
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, "", fmt.Errorf("invalid query: %w", err)
	}
	for key, entries := range values {
		if !utf8.ValidString(key) || containsControl(key) || containsPercentTriplet(key) {
			return nil, "", fmt.Errorf("invalid query key")
		}
		for _, entry := range entries {
			if !utf8.ValidString(entry) || containsControl(entry) || containsPercentTriplet(entry) {
				return nil, "", fmt.Errorf("invalid query value for %q", key)
			}
		}
		// url.Values.Encode sorts keys but preserves value order. Sorting values
		// eliminates spelling-dependent policy outcomes.
		sort.Strings(entries)
		values[key] = entries
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0)
	for _, key := range keys {
		for _, value := range values[key] {
			parts = append(parts, rfc3986QueryEscape(key)+"="+rfc3986QueryEscape(value))
		}
	}
	return values, strings.Join(parts, "&"), nil
}

func rfc3986QueryEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func validMethod(method string) bool {
	if method == "" {
		return false
	}
	for i := 0; i < len(method); i++ {
		c := method[i]
		if c >= 'a' && c <= 'z' || !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') &&
			!strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func containsPercentTriplet(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHex(s[i+1]) && isHex(s[i+2]) {
			return true
		}
	}
	return false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

type pathSegmentKind uint8

const (
	pathLiteral pathSegmentKind = iota
	pathOne
	pathMany
)

type pathSegment struct {
	kind    pathSegmentKind
	literal string
}

type pathGlob struct {
	segments []pathSegment
}

func compilePathGlob(pattern string) (pathGlob, error) {
	_, segments, err := canonicalPathParts(pattern)
	if err != nil {
		return pathGlob{}, err
	}
	compiled := make([]pathSegment, len(segments))
	for i, segment := range segments {
		switch segment {
		case "*":
			compiled[i].kind = pathOne
		case "**":
			compiled[i].kind = pathMany
		default:
			compiled[i] = pathSegment{kind: pathLiteral, literal: segment}
		}
	}
	return pathGlob{segments: compiled}, nil
}

func (g pathGlob) matches(path []string) bool {
	// Dynamic programming avoids exponential backtracking with repeated **.
	dp := make([][]bool, len(g.segments)+1)
	for i := range dp {
		dp[i] = make([]bool, len(path)+1)
	}
	dp[0][0] = true
	for i, pattern := range g.segments {
		for j := 0; j <= len(path); j++ {
			if !dp[i][j] {
				continue
			}
			switch pattern.kind {
			case pathLiteral:
				if j < len(path) && path[j] == pattern.literal {
					dp[i+1][j+1] = true
				}
			case pathOne:
				if j < len(path) && path[j] != "" {
					dp[i+1][j+1] = true
				}
			case pathMany:
				dp[i+1][j] = true
				for k := j; k < len(path) && path[k] != ""; k++ {
					dp[i+1][k+1] = true
				}
			}
		}
	}
	return dp[len(g.segments)][len(path)]
}
