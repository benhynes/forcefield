package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var ErrUpstreamAddressDenied = errors.New("upstream address denied")

type IPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type TransportOptions struct {
	Resolver          IPResolver
	AllowedCIDRs      []netip.Prefix
	PinnedSPKISHA256  []string
	ConnectTimeout    time.Duration
	ResponseTimeout   time.Duration
	IdleTimeout       time.Duration
	MaxResponseHeader int64
}

// NewHardenedTransport returns a direct-only transport whose dialer resolves a
// hostname once, validates every answer, and dials one of those exact IPs. The
// request URL retains the hostname, so TLS certificate validation and SNI stay
// pinned to the configured upstream authority.
func NewHardenedTransport(opts TransportOptions) (*http.Transport, error) {
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 5 * time.Second
	}
	if opts.ResponseTimeout <= 0 {
		opts.ResponseTimeout = 30 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 60 * time.Second
	}
	if opts.MaxResponseHeader <= 0 {
		opts.MaxResponseHeader = 1 << 20
	}
	pins := make(map[[sha256.Size]byte]struct{}, len(opts.PinnedSPKISHA256))
	for _, encoded := range opts.PinnedSPKISHA256 {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("invalid SPKI pin")
		}
		var pin [sha256.Size]byte
		copy(pin[:], raw)
		pins[pin] = struct{}{}
	}

	dialer := &safeDialer{resolver: opts.Resolver, allowed: append([]netip.Prefix(nil), opts.AllowedCIDRs...), timeout: opts.ConnectTimeout}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(pins) > 0 {
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("upstream did not present a leaf certificate")
			}
			// Pin the authenticated endpoint key, never an arbitrary certificate
			// appended to the peer-supplied chain.
			digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if _, ok := pins[digest]; ok {
				return nil
			}
			return errors.New("upstream SPKI pin mismatch")
		}
	}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    opts.ConnectTimeout,
		ResponseHeaderTimeout:  opts.ResponseTimeout,
		IdleConnTimeout:        opts.IdleTimeout,
		MaxResponseHeaderBytes: opts.MaxResponseHeader,
		DisableCompression:     true,
	}, nil
}

type safeDialer struct {
	resolver IPResolver
	allowed  []netip.Prefix
	timeout  time.Duration
}

func (d *safeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.timeout <= 0 {
		return nil, errors.New("invalid connect timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("dial target: %w", err)
	}
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addresses = []netip.Addr{literal.Unmap()}
	} else {
		addresses, err = d.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			return nil, fmt.Errorf("resolve upstream: %w", err)
		}
	}
	for i := range addresses {
		addresses[i] = addresses[i].Unmap()
		if !d.addressAllowed(addresses[i]) {
			return nil, ErrUpstreamAddressDenied
		}
	}

	var errs []error
	for _, ip := range addresses {
		conn, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (d *safeDialer) addressAllowed(addr netip.Addr) bool {
	for _, prefix := range d.allowed {
		if prefix.Contains(addr) {
			return true
		}
	}
	return isPublicAddress(addr)
}

var deniedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
	"2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
)

func isPublicAddress(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range deniedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

// VerifySystemRoots is a small test seam ensuring production transports never
// opt out of normal x509 verification.
func VerifySystemRoots(cfg *tls.Config) bool {
	return cfg != nil && !cfg.InsecureSkipVerify && cfg.RootCAs == (*x509.CertPool)(nil)
}
