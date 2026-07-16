package runner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyWorkloadIdentity(t *testing.T) {
	t.Parallel()
	if err := VerifyWorkloadIdentity(Profile{Workload: "ip:127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkloadIdentity(Profile{Workload: "mtls-spki:" + strings.Repeat("a", 64)}); err == nil {
		t.Fatal("mTLS workload without a certificate was accepted")
	}
	certificatePath, workload := writeRunnerCertificate(t)
	if err := VerifyWorkloadIdentity(Profile{Workload: workload, ClientCert: certificatePath}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWorkloadIdentity(Profile{Workload: "mtls-spki:" + strings.Repeat("b", 64), ClientCert: certificatePath}); err == nil {
		t.Fatal("mismatched certificate was accepted")
	}
	if err := VerifyWorkloadIdentity(Profile{Workload: "ip:127.0.0.1", ClientCert: certificatePath}); err == nil {
		t.Fatal("IP workload with mTLS was accepted")
	}
}

func writeRunnerCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runner-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return path, "mtls-spki:" + hex.EncodeToString(digest[:])
}
