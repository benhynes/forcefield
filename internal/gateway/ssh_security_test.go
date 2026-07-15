package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRestrictedSSHSignerExcludesLegacyRSA(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := restrictedSSHSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	multi, ok := restricted.(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatalf("restricted RSA signer type = %T", restricted)
	}
	if got, want := multi.Algorithms(), []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}; !slices.Equal(got, want) {
		t.Fatalf("RSA signature algorithms = %v, want %v", got, want)
	}
	if slices.Contains(multi.Algorithms(), ssh.KeyAlgoRSA) {
		t.Fatal("restricted RSA signer retained legacy SHA-1 ssh-rsa")
	}
}

func TestRestrictedSSHSignerRejectsWeakRSA(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restrictedSSHSigner(signer); err == nil {
		t.Fatal("1024-bit RSA private key was accepted")
	}
}

func TestSSHPublicKeyStrengthRejectsWeakRSACertificate(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := newSSHSigner(t)
	certificate := &ssh.Certificate{
		Key: signer.PublicKey(), CertType: ssh.HostCert,
		ValidPrincipals: []string{"weak.example"}, ValidBefore: ssh.CertTimeInfinity,
	}
	if err := certificate.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if err := validateSSHPublicKeyStrength(certificate); err == nil {
		t.Fatal("certificate wrapping a 1024-bit RSA host key was accepted")
	}
}

func TestSSHProtocolLimiterBoundsRateAndTotal(t *testing.T) {
	t.Parallel()
	current := time.Unix(0, 0)
	rateLimiter := newSSHProtocolLimiter(func() time.Time { return current })
	for attempt := 0; attempt < sshProtocolRequestBurst; attempt++ {
		if !rateLimiter.allowRequest() {
			t.Fatalf("request %d inside burst was denied", attempt+1)
		}
	}
	if rateLimiter.allowRequest() {
		t.Fatal("request above the fixed burst was allowed")
	}
	select {
	case <-rateLimiter.exhausted:
	default:
		t.Fatal("rate exhaustion did not terminate the session")
	}

	current = time.Unix(0, 0)
	totalLimiter := newSSHProtocolLimiter(func() time.Time { return current })
	for attempt := 0; attempt < maxSSHProtocolRequestsPerSession; attempt++ {
		current = current.Add(time.Second)
		if !totalLimiter.allowRequest() {
			t.Fatalf("request %d inside total limit was denied", attempt+1)
		}
	}
	if totalLimiter.allowRequest() {
		t.Fatal("request above the per-session total was allowed")
	}
}

func TestSSHInputLimiterIsSharedAcrossConcurrentPayloads(t *testing.T) {
	t.Parallel()
	var counted atomic.Uint64
	limiter := &sshInputLimiter{maximum: 100, counted: &counted, allow: func(uint64) bool { return true }}
	var accepted atomic.Int64
	var workers sync.WaitGroup
	for attempt := 0; attempt < 100; attempt++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if limiter.consume(2) {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 50 || counted.Load() != 100 {
		t.Fatalf("accepted=%d counted=%d, want 50 and 100", accepted.Load(), counted.Load())
	}
	if limiter.consume(1) {
		t.Fatal("payload above the shared maximum was allowed")
	}
}
