package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type staticResolver []netip.Addr

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r...), nil
}

type blockingResolver struct{}

func (blockingResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSafeDialerUsesOneOverallConnectDeadline(t *testing.T) {
	t.Parallel()
	dialer := &safeDialer{resolver: blockingResolver{}, timeout: 10 * time.Millisecond}
	started := time.Now()
	if _, err := dialer.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("timed-out resolution succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("connect deadline was not applied to DNS: %s", elapsed)
	}
}

func TestSafeDialerRejectsAnyMixedPrivateAnswer(t *testing.T) {
	t.Parallel()
	dialer := &safeDialer{
		resolver: staticResolver{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")},
		timeout:  time.Second,
	}
	if _, err := dialer.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrUpstreamAddressDenied) {
		t.Fatalf("mixed DNS answers error = %v", err)
	}
}

func TestSPKIPinAppliesOnlyToLeaf(t *testing.T) {
	t.Parallel()
	pinnedKey := []byte("pinned-key")
	digest := sha256.Sum256(pinnedKey)
	transport, err := NewHardenedTransport(TransportOptions{
		PinnedSPKISHA256: []string{base64.StdEncoding.EncodeToString(digest[:])},
	})
	if err != nil {
		t.Fatal(err)
	}
	verify := transport.TLSClientConfig.VerifyConnection
	if verify == nil {
		t.Fatal("pin verifier was not installed")
	}
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{RawSubjectPublicKeyInfo: []byte("untrusted-leaf-key")},
		{RawSubjectPublicKeyInfo: pinnedKey},
	}}); err == nil {
		t.Fatal("pin on an appended non-leaf certificate was accepted")
	}
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{RawSubjectPublicKeyInfo: pinnedKey},
	}}); err != nil {
		t.Fatalf("pinned leaf was rejected: %v", err)
	}
}

func TestSafeDialerAddressPolicy(t *testing.T) {
	t.Parallel()
	d := &safeDialer{}
	for _, raw := range []string{
		"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.88.99.1",
		"::1", "fc00::1", "2001:db8::1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::7f00:1",
		"100::1", "2001::1", "2002:7f00:1::",
	} {
		if d.addressAllowed(netip.MustParseAddr(raw)) {
			t.Errorf("address %s unexpectedly allowed", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !d.addressAllowed(netip.MustParseAddr(raw)) {
			t.Errorf("address %s unexpectedly denied", raw)
		}
	}
	private := netip.MustParsePrefix("127.0.0.0/8")
	d.allowed = []netip.Prefix{private}
	if !d.addressAllowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("explicit allowed CIDR was ignored")
	}
}

func TestNewHardenedTransport(t *testing.T) {
	t.Parallel()
	transport, err := NewHardenedTransport(TransportOptions{Resolver: staticResolver{netip.MustParseAddr("1.1.1.1")}})
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil || !transport.DisableCompression || !VerifySystemRoots(transport.TLSClientConfig) {
		t.Fatalf("transport is not hardened: %#v", transport)
	}
}
