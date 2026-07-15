package capabilities

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
)

var ErrLookup = errors.New("Forcefield capability lookup was not confirmed")

type ClientOptions struct {
	BaseURL       string
	TokenFile     string
	CACertPath    string
	ClientCert    string
	ClientKey     string
	AllowInsecure bool
	Timeout       time.Duration
	UserAgent     string

	// Transport is a test seam. Production callers should leave it nil so the
	// client uses the direct, proxy-free TLS transport below.
	Transport http.RoundTripper
	Now       func() time.Time
}

func Fetch(ctx context.Context, options ClientOptions) (Manifest, error) {
	endpoint, err := capabilityEndpoint(options.BaseURL, options.AllowInsecure)
	if err != nil {
		return Manifest{}, err
	}
	bearer, err := readBearerFile(options.TokenFile)
	if err != nil {
		return Manifest{}, ErrLookup
	}
	transport := options.Transport
	if transport == nil {
		transport, err = capabilityTransport(options)
		if err != nil {
			return Manifest{}, err
		}
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			defer closer.CloseIdleConnections()
		}
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if timeout < time.Second || timeout > 30*time.Second {
		return Manifest{}, fmt.Errorf("%w: timeout must be between 1s and 30s", ErrLookup)
	}
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Forcefield capability redirects are not allowed")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Manifest{}, ErrLookup
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	if options.UserAgent != "" {
		request.Header.Set("User-Agent", options.UserAgent)
	}
	defer request.Header.Del("Authorization")

	response, err := client.Do(request)
	if err != nil {
		return Manifest{}, ErrLookup
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxManifestSize))
		return Manifest{}, ErrLookup
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return Manifest{}, ErrLookup
	}
	mediaType, parameters, mediaErr := mime.ParseMediaType(contentTypes[0])
	if mediaErr != nil || mediaType != "application/json" || len(parameters) != 0 ||
		len(response.Header.Values("Content-Encoding")) != 0 || !hasNoStore(response.Header.Values("Cache-Control")) {
		return Manifest{}, ErrLookup
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, MaxManifestSize+1))
	if err != nil || len(encoded) > MaxManifestSize {
		return Manifest{}, ErrLookup
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrLookup
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, ErrLookup
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, ErrLookup
	}
	now := time.Now
	if options.Now != nil {
		now = options.Now
	}
	current := now().UTC()
	if !current.Before(manifest.ExpiresAt) || manifest.GeneratedAt.Before(current.Add(-5*time.Minute)) || manifest.GeneratedAt.After(current.Add(5*time.Minute)) {
		return Manifest{}, ErrLookup
	}
	return manifest, nil
}

func capabilityEndpoint(base string, allowInsecure bool) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("%w: url must be a Forcefield origin", ErrLookup)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !allowInsecure || !loopbackHost(parsed.Hostname()) {
			return "", fmt.Errorf("%w: HTTPS is required", ErrLookup)
		}
	}
	parsed.Path = config.CapabilitiesPath
	parsed.RawPath = ""
	return parsed.String(), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func capabilityTransport(options ClientOptions) (http.RoundTripper, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.CACertPath != "" {
		contents, err := readBoundedRegularFile(options.CACertPath, 1<<20, false)
		if err != nil {
			return nil, fmt.Errorf("%w: read CA certificate", ErrLookup)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(contents) {
			return nil, fmt.Errorf("%w: parse CA certificate", ErrLookup)
		}
		tlsConfig.RootCAs = pool
	}
	if (options.ClientCert == "") != (options.ClientKey == "") {
		return nil, fmt.Errorf("%w: client certificate and key must be configured together", ErrLookup)
	}
	if options.ClientCert != "" {
		certificatePEM, err := readBoundedRegularFile(options.ClientCert, 1<<20, false)
		if err != nil {
			return nil, fmt.Errorf("%w: read client certificate", ErrLookup)
		}
		keyPEM, err := readBoundedRegularFile(options.ClientKey, 1<<20, true)
		if err != nil {
			return nil, fmt.Errorf("%w: read client private key", ErrLookup)
		}
		defer clear(keyPEM)
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: load client certificate", ErrLookup)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
	}, nil
}

func readBearerFile(path string) (string, error) {
	path, err := expandHome(path)
	if err != nil {
		return "", err
	}
	contents, err := readBoundedRegularFile(path, 1024, true)
	if err != nil {
		return "", err
	}
	defer clear(contents)
	contents = bytes.TrimSuffix(contents, []byte{'\n'})
	contents = bytes.TrimSuffix(contents, []byte{'\r'})
	if len(contents) == 0 || bytes.IndexAny(contents, " \t\r\n") >= 0 || !bytes.HasPrefix(contents, []byte(tokens.BearerPrefix)) {
		return "", ErrLookup
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(contents[len(tokens.BearerPrefix):]))
	if err != nil || len(raw) != 32 {
		clear(raw)
		return "", ErrLookup
	}
	clear(raw)
	return string(contents), nil
}

func readBoundedRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	path, err := expandHome(path)
	if err != nil {
		return nil, ErrLookup
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum || private && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrLookup
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return nil, ErrLookup
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrLookup
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrLookup
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		clear(contents)
		return nil, ErrLookup
	}
	return contents, nil
}

func expandHome(path string) (string, error) {
	if path == "" {
		return "", ErrLookup
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", ErrLookup
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}
