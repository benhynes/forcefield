package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/benhynes/forcefield/internal/capabilities"
)

const maxGitCredentialInputBytes = 16 << 10

var errGitCredential = errors.New("Forcefield Git credential unavailable")

type gitCredentialScope struct {
	scheme     string
	host       string
	pathPrefix string
}

type gitCredentialRequest struct {
	protocol string
	host     string
	path     string
}

// runGitCredential implements Git's credential-helper protocol. Git appends
// the operation to the configured helper command, so flags precede exactly one
// positional get, store, or erase operation.
func runGitCredential(args []string, stdin io.Reader, stdout io.Writer) error {
	if stdout == nil {
		return errGitCredential
	}
	flags := newFlagSet("git-credential")
	baseURL := flags.String("url", "", "Forcefield Git service URL prefix")
	tokenFile := flags.String("token-file", "", "0600 Forcefield bearer file")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stdout, "Usage: ff git-credential --url URL --token-file PATH get|store|erase")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errGitCredential
	}
	if flags.NArg() != 1 || *baseURL == "" || *tokenFile == "" {
		return errGitCredential
	}
	operation := flags.Arg(0)
	if operation != "get" && operation != "store" && operation != "erase" {
		return errGitCredential
	}
	scope, err := parseGitCredentialScope(*baseURL)
	if err != nil {
		return errGitCredential
	}
	request, err := readGitCredentialRequest(stdin)
	if err != nil {
		return errGitCredential
	}

	// This helper is a read-only view of the separately delivered Forcefield
	// token. In particular, it never persists credentials Git offers to store.
	if operation != "get" || !scope.matches(request) {
		return nil
	}
	bearer, err := capabilities.ReadBearerFile(*tokenFile)
	if err != nil {
		return errGitCredential
	}
	if _, err := fmt.Fprintf(stdout, "username=forcefield\npassword=%s\n\n", bearer); err != nil {
		return err
	}
	return nil
}

func parseGitCredentialScope(raw string) (gitCredentialScope, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Scheme != "https" && parsed.Scheme != "http" {
		return gitCredentialScope{}, errGitCredential
	}
	if parsed.Host != strings.ToLower(parsed.Host) || strings.ContainsAny(parsed.Host, "\\\r\n\x00") {
		return gitCredentialScope{}, errGitCredential
	}
	prefix := parsed.Path
	if prefix == "" {
		prefix = "/"
	}
	if !validGitCredentialPath(prefix) || prefix != "/" && strings.HasSuffix(prefix, "/") {
		return gitCredentialScope{}, errGitCredential
	}
	return gitCredentialScope{scheme: parsed.Scheme, host: parsed.Host, pathPrefix: prefix}, nil
}

func (scope gitCredentialScope) matches(request gitCredentialRequest) bool {
	if request.protocol != scope.scheme || strings.ToLower(request.host) != scope.host {
		return false
	}
	path := request.path
	if path == "" {
		path = "/"
	} else if path[0] != '/' {
		path = "/" + path
	}
	if !validGitCredentialPath(path) {
		return false
	}
	if scope.pathPrefix == "/" {
		return true
	}
	return path == scope.pathPrefix || strings.HasPrefix(path, scope.pathPrefix+"/")
}

func validGitCredentialPath(value string) bool {
	if value == "" || value[0] != '/' || strings.Contains(value, "//") || strings.ContainsAny(value, "\\\r\n\x00?#") {
		return false
	}
	for _, component := range strings.Split(value[1:], "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}

func readGitCredentialRequest(reader io.Reader) (gitCredentialRequest, error) {
	if reader == nil {
		return gitCredentialRequest{}, errGitCredential
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxGitCredentialInputBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxGitCredentialInputBytes {
		clear(data)
		return gitCredentialRequest{}, errGitCredential
	}
	defer clear(data)
	if bytes.IndexByte(data, 0) >= 0 || bytes.IndexByte(data, '\r') >= 0 || !bytes.HasSuffix(data, []byte("\n\n")) {
		return gitCredentialRequest{}, errGitCredential
	}
	data = data[:len(data)-2]
	if bytes.Contains(data, []byte("\n\n")) {
		return gitCredentialRequest{}, errGitCredential
	}

	var request gitCredentialRequest
	seen := make(map[string]struct{}, 3)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		key, value, found := bytes.Cut(line, []byte{'='})
		if !found || !validGitCredentialKey(key) || bytes.IndexByte(value, 0) >= 0 {
			return gitCredentialRequest{}, errGitCredential
		}
		name := string(key)
		switch name {
		case "protocol", "host", "path":
			if _, duplicate := seen[name]; duplicate {
				return gitCredentialRequest{}, errGitCredential
			}
			seen[name] = struct{}{}
		case "url":
			// Git may add new attributes, but accepting its compound URL form in
			// addition to components would create duplicate-source ambiguity.
			return gitCredentialRequest{}, errGitCredential
		}
		switch name {
		case "protocol":
			request.protocol = string(value)
		case "host":
			request.host = string(value)
		case "path":
			request.path = string(value)
		}
	}
	if request.protocol == "" || request.host == "" || strings.ContainsAny(request.protocol+request.host, " /\\\t") {
		return gitCredentialRequest{}, errGitCredential
	}
	return request, nil
}

func validGitCredentialKey(value []byte) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, current := range value {
		if current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' ||
			current == '-' || current == '_' || current == '[' || current == ']' {
			continue
		}
		return false
	}
	return true
}
