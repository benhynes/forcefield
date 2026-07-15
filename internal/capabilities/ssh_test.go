package capabilities

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/config"
)

func TestBuildAndRenderSSHSessionCapabilityWithoutUpstreamDetails(t *testing.T) {
	t.Parallel()
	compiled := sshCapabilityConfig(t)
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	manifest, err := Build(compiled, now, now.Add(time.Hour), compiled.Roles["infra-operator"])
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Services) != 1 {
		t.Fatalf("SSH services = %#v", manifest.Services)
	}
	service := manifest.Services[0]
	if service.Name != "infra" || service.Adapter != config.AdapterSSHSession ||
		service.BaseURL != "https://forcefield.example:7902/ssh/infra" || service.PathPrefix != "/ssh/infra" ||
		service.Auth.Header != "Authorization" || service.Auth.Prefix != "Bearer " || service.SSH == nil ||
		!service.SSH.AllowShell || !service.SSH.AllowExec || !service.SSH.AllowPTY || service.SSH.MaxSessionDuration != "30m0s" {
		t.Fatalf("SSH capability = %#v", service)
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	privateDetails := []string{
		"infra-private.internal", "svc-hidden", "HIDDEN_INFRA_KEY", "10.0.0.0/8",
		"SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
	}
	for _, private := range privateDetails {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatalf("SSH manifest exposed private detail %q: %s", private, encoded)
		}
	}

	markdown, err := RenderMarkdown(manifest, RenderOptions{
		Now: now, TokenFile: "/run/forcefield/token", CACertPath: "/run/forcefield/ca.crt",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"infra (ssh-session)", "one terminating SSH session", "configured Unix account's filesystem and network authority",
		"SSH protocol port, agent, and X11 forwarding", "environment and subsystem requests are denied",
		"Granted SSH modes: shell yes; exec yes; PTY yes; maximum session duration 30m0s",
		"Native shell", "Native command", "ff ssh --url", `--url "https://forcefield.example:7902"`,
		`--token-file "/run/forcefield/token" infra`, "infra -- COMMAND ...",
	} {
		if !strings.Contains(markdown, expected) {
			t.Fatalf("SSH capability recipe omitted %q:\n%s", expected, markdown)
		}
	}
	for _, private := range privateDetails {
		if strings.Contains(markdown, private) {
			t.Fatalf("SSH capability recipe exposed private detail %q:\n%s", private, markdown)
		}
	}
}

func TestSSHSessionManifestRequiresUsableBrokerRouteAndBearerCarrier(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	base := Manifest{
		Version: SchemaVersion, GeneratedAt: now, ExpiresAt: now.Add(time.Hour),
		Services: []Service{{
			Name: "infra", Adapter: config.AdapterSSHSession,
			BaseURL: "https://forcefield.example/ssh/infra", PathPrefix: "/ssh/infra",
			Auth: Auth{Header: "Authorization", Prefix: "Bearer "},
			SSH:  &SSHCapability{AllowShell: true, AllowExec: true, AllowPTY: true, MaxSessionDuration: "30m0s"},
		}},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid SSH capability: %v", err)
	}

	hostRoute := base
	hostRoute.Services = append([]Service(nil), base.Services...)
	hostRoute.Services[0].BaseURL = "https://infra.forcefield.example"
	hostRoute.Services[0].PathPrefix = ""
	hostRoute.Services[0].Host = "infra.forcefield.example"
	if err := hostRoute.Validate(); err != nil {
		t.Fatalf("valid SSH virtual-host capability: %v", err)
	}

	for name, mutate := range map[string]func(*Service){
		"missing advertised route":   func(service *Service) { service.BaseURL = "" },
		"mismatched advertised path": func(service *Service) { service.BaseURL = "https://forcefield.example/other" },
		"non-bearer header":          func(service *Service) { service.Auth = Auth{Header: "X-Forcefield-Token"} },
		"non-bearer prefix":          func(service *Service) { service.Auth.Prefix = "token " },
		"missing SSH modes":          func(service *Service) { service.SSH = nil },
		"neither shell nor exec": func(service *Service) {
			service.SSH.AllowShell = false
			service.SSH.AllowExec = false
		},
		"short session duration":    func(service *Service) { service.SSH.MaxSessionDuration = "999ms" },
		"long session duration":     func(service *Service) { service.SSH.MaxSessionDuration = "24h0m1s" },
		"noncanonical duration":     func(service *Service) { service.SSH.MaxSessionDuration = "1800s" },
		"SSH block on HTTP adapter": func(service *Service) { service.Adapter = config.AdapterHTTP },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manifest := base
			manifest.Services = append([]Service(nil), base.Services...)
			if base.Services[0].SSH != nil {
				sshCopy := *base.Services[0].SSH
				manifest.Services[0].SSH = &sshCopy
			}
			mutate(&manifest.Services[0])
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid SSH capability was accepted")
			}
		})
	}
}

func TestRenderSSHRecipeMatchesGrantedModes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	base := Service{
		Name: "infra", Adapter: config.AdapterSSHSession,
		BaseURL: "https://forcefield.example/ssh/infra", PathPrefix: "/ssh/infra",
		Auth: Auth{Header: "Authorization", Prefix: "Bearer "},
	}
	for _, test := range []struct {
		name       string
		capability SSHCapability
		contains   []string
		excludes   []string
	}{
		{
			name: "exec only", capability: SSHCapability{AllowExec: true, MaxSessionDuration: "5m0s"},
			contains: []string{"shell no; exec yes; PTY no", "Native command:", "infra -- COMMAND ..."},
			excludes: []string{"Native shell:"},
		},
		{
			name: "shell without PTY", capability: SSHCapability{AllowShell: true, MaxSessionDuration: "5m0s"},
			contains: []string{"shell yes; exec no; PTY no", "Native shell:", "--no-pty infra"},
			excludes: []string{"Native command:"},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := base
			service.SSH = &test.capability
			manifest := Manifest{Version: SchemaVersion, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), Services: []Service{service}}
			markdown, err := RenderMarkdown(manifest, RenderOptions{Now: now, TokenFile: "/run/forcefield/token"})
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range test.contains {
				if !strings.Contains(markdown, expected) {
					t.Fatalf("recipe omitted %q:\n%s", expected, markdown)
				}
			}
			for _, excluded := range test.excludes {
				if strings.Contains(markdown, excluded) {
					t.Fatalf("recipe exposed unavailable mode %q:\n%s", excluded, markdown)
				}
			}
		})
	}
}

func TestSSHManifestJSONReportsDeniedModesExplicitly(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	manifest := Manifest{
		Version: SchemaVersion, GeneratedAt: now, ExpiresAt: now.Add(time.Hour),
		Services: []Service{{
			Name: "infra", Adapter: config.AdapterSSHSession,
			BaseURL: "https://forcefield.example/ssh/infra", PathPrefix: "/ssh/infra",
			Auth: Auth{Header: "Authorization", Prefix: "Bearer "},
			SSH:  &SSHCapability{AllowExec: true, MaxSessionDuration: "5m0s"},
		}},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"allow_shell":false`, `"allow_exec":true`, `"allow_pty":false`} {
		if !bytes.Contains(encoded, []byte(expected)) {
			t.Fatalf("SSH manifest omitted explicit mode %s: %s", expected, encoded)
		}
	}
}

func sshCapabilityConfig(t *testing.T) *config.Compiled {
	t.Helper()
	temp := t.TempDir()
	compiled, err := config.Compile(config.File{
		Version: 1,
		Server: config.ServerConfig{
			Listen: "127.0.0.1:7902", Audience: "test", AdminSocket: filepath.Join(temp, "admin.sock"),
			AdvertisedBaseURL: "https://forcefield.example:7902",
		},
		State:   config.StateConfig{TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl")},
		Secrets: config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_"},
		Services: map[string]config.ServiceConfig{
			"infra": {
				Adapter: config.AdapterSSHSession, Upstream: "ssh://infra-private.internal:2222", PathPrefix: "/ssh/infra",
				ClientAuth: config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "}, AllowedCIDRs: []string{"10.0.0.0/8"},
				SSH: &config.SSHServiceConfig{
					User: "svc-hidden", HostKeySHA256: []string{"SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},
				},
			},
		},
		Credentials: map[string]config.CredentialConfig{
			"infra-key": {Service: "infra", SecretRef: "HIDDEN_INFRA_KEY"},
		},
		Policies: map[string]config.PolicyConfig{
			"infra-shell": {
				Service: "infra", CapabilitySummary: "Open a shell or run a command through the pinned broker target.",
				SSH: &config.SSHPolicyConfig{
					AllowShell: true, AllowExec: true, AllowPTY: true,
					MaxSessionDuration: config.Duration(30 * time.Minute),
				},
			},
		},
		Roles: map[string]config.RoleConfig{
			"infra-operator": {Grants: []config.GrantConfig{{Service: "infra", Credential: "infra-key", Policy: "infra-shell"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}
