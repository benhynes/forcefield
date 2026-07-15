package config_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
)

func TestSSHCapabilityManifestBoundIncludesNestedModes(t *testing.T) {
	t.Parallel()
	temp := t.TempDir()
	build := func(pathPadding int) (*config.Compiled, error) {
		file := config.File{
			Version: 1,
			Server: config.ServerConfig{
				Listen: "127.0.0.1:7902", Audience: "bound-test",
				AdminSocket: filepath.Join(temp, "admin.sock"), AdvertisedBaseURL: "https://forcefield.example",
			},
			State: config.StateConfig{
				TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl"),
			},
			Secrets:     config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_BOUND_"},
			Services:    make(map[string]config.ServiceConfig, config.CapabilityManifestMaxServices),
			Credentials: make(map[string]config.CredentialConfig, config.CapabilityManifestMaxServices),
			Policies:    make(map[string]config.PolicyConfig, config.CapabilityManifestMaxServices),
			Roles:       map[string]config.RoleConfig{"ssh-bound": {}},
		}
		grants := make([]config.GrantConfig, 0, config.CapabilityManifestMaxServices)
		for index := 0; index < config.CapabilityManifestMaxServices; index++ {
			serviceName := fmt.Sprintf("ssh%02d", index)
			credentialName := fmt.Sprintf("key%02d", index)
			policyName := fmt.Sprintf("policy%02d", index)
			file.Services[serviceName] = config.ServiceConfig{
				Adapter: config.AdapterSSHSession, Upstream: "ssh://192.0.2.10:22",
				PathPrefix: "/" + serviceName + "-" + strings.Repeat("x", pathPadding),
				ClientAuth: config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
				SSH: &config.SSHServiceConfig{
					User: "deploy", HostKeySHA256: []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
				},
			}
			file.Credentials[credentialName] = config.CredentialConfig{
				Service: serviceName, SecretRef: fmt.Sprintf("SSH_KEY_%02d", index),
			}
			file.Policies[policyName] = config.PolicyConfig{
				Service: serviceName, CapabilitySummary: strings.Repeat("s", 512),
				SSH: &config.SSHPolicyConfig{
					AllowShell: true, AllowExec: true, AllowPTY: true,
					MaxSessionDuration: config.Duration(24 * time.Hour),
				},
			}
			grants = append(grants, config.GrantConfig{Service: serviceName, Credential: credentialName, Policy: policyName})
		}
		file.Roles["ssh-bound"] = config.RoleConfig{Grants: grants}
		return config.Compile(file)
	}

	var largest *config.Compiled
	largestPadding := 0
	for low, high := 1, 2000; low <= high; {
		middle := low + (high-low)/2
		compiled, err := build(middle)
		if err == nil {
			largest, largestPadding = compiled, middle
			low = middle + 1
		} else {
			high = middle - 1
		}
	}
	if largest == nil || largestPadding == 2000 {
		t.Fatalf("did not find a capability-size boundary; padding=%d", largestPadding)
	}
	now := time.Date(9998, time.December, 31, 23, 59, 58, 999999999, time.UTC)
	grants := append([]tokens.Grant(nil), largest.Roles["ssh-bound"]...)
	maximum := ^uint64(0)
	for index := range grants {
		grants[index].Limits = tokens.Limits{
			RequestsPerSecond: maximum, Burst: maximum, RequestBudget: maximum,
			ByteBudget: maximum, MaxRequestBytes: maximum,
		}
	}
	manifest, err := capabilities.Build(largest, now, now.Add(time.Second), grants)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 > config.CapabilityManifestMaxBytes {
		t.Fatalf("compiled SSH manifest exceeds bound: padding=%d bytes=%d limit=%d", largestPadding, len(encoded)+1, config.CapabilityManifestMaxBytes)
	}
	// One more padding byte appears once in base_url and once in path_prefix
	// for every service. A larger gap would mean this test had not actually
	// reached the manifest proof boundary.
	if remaining := config.CapabilityManifestMaxBytes - (len(encoded) + 1); remaining >= 2*config.CapabilityManifestMaxServices {
		t.Fatalf("SSH manifest boundary was not tight: padding=%d remaining=%d", largestPadding, remaining)
	}
	for _, service := range manifest.Services {
		if service.SSH == nil || !service.SSH.AllowShell || !service.SSH.AllowExec || !service.SSH.AllowPTY || service.SSH.MaxSessionDuration != "24h0m0s" {
			t.Fatalf("nested SSH projection was not represented exactly: %#v", service.SSH)
		}
	}
}
