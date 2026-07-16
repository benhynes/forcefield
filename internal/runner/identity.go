package runner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// VerifyWorkloadIdentity prevents a profile from minting an IP-bound token
// while the broker presents mTLS (which Forcefield would resolve first), and
// ensures an mTLS workload exactly matches the configured leaf certificate.
func VerifyWorkloadIdentity(profile Profile) error {
	if profile.ClientCert == "" {
		if !strings.HasPrefix(profile.Workload, "ip:") {
			return errors.New("mTLS runner workload requires a client certificate")
		}
		return nil
	}
	if !strings.HasPrefix(profile.Workload, "mtls-spki:") {
		return errors.New("runner profile with a client certificate requires an mTLS workload")
	}
	contents, err := readRunnerFile(profile.ClientCert, 1<<20, false)
	if err != nil {
		return errors.New("read runner client certificate")
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("parse runner client certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("parse runner client certificate")
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	if profile.Workload != "mtls-spki:"+hex.EncodeToString(digest[:]) {
		return errors.New("runner workload does not match the client certificate SPKI")
	}
	return nil
}
