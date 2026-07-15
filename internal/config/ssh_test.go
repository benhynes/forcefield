package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/gitadapter"
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/tokens"
)

const validSSHConfig = `
version: 1
server:
  listen: 127.0.0.1:7902
  audience: forcefield-test
  admin_socket: /tmp/forcefield-ssh-test/admin.sock
  advertised_base_url: https://forcefield.example:7902
state:
  token_file: /tmp/forcefield-ssh-test/tokens.json
  audit_file: /tmp/forcefield-ssh-test/audit.jsonl
  audit_failure: closed
secrets:
  type: env
  env_prefix: FF_TEST_
services:
  infra:
    adapter: ssh-session
    upstream: ssh://192.0.2.10:22
    path_prefix: /ssh/infra
    client_auth: {header: Authorization, prefix: "Bearer "}
    ssh:
      user: deploy
      host_key_sha256: [SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]
credentials:
  infra-key:
    service: infra
    secret_ref: INFRA_SSH_KEY
policies:
  infra-shell:
    service: infra
    capability_summary: Open a shell or run a command as the configured account.
    ssh:
      allow_shell: true
      allow_exec: true
      allow_pty: true
      max_session_duration: 30m
roles:
  infra-operator:
    grants:
      - service: infra
        credential: infra-key
        policy: infra-shell
`

func TestSSHSessionConfigCompilesAndProjectsOnlyPublicRouting(t *testing.T) {
	t.Parallel()
	compiled := mustSSHConfig(t)
	service := compiled.File.Services["infra"]
	if service.Adapter != AdapterSSHSession || service.SSH == nil || service.SSH.ConnectTimeout.Value() != 5*time.Second {
		t.Fatalf("compiled SSH service = %#v", service)
	}
	if got := compiled.Upstreams["infra"].String(); got != "ssh://192.0.2.10:22" {
		t.Fatalf("SSH upstream = %q", got)
	}
	entry := compiled.Policies["infra-shell"]
	if entry.Adapter != AdapterSSHSession || entry.SSHPolicy == nil || entry.Policy != nil || entry.GitPolicy != nil ||
		!entry.SSHPolicy.AllowShell || !entry.SSHPolicy.AllowExec || !entry.SSHPolicy.AllowPTY ||
		entry.SSHPolicy.MaxSessionDuration.Value() != 30*time.Minute {
		t.Fatalf("compiled SSH policy = %#v", entry)
	}
	grant := compiled.Roles["infra-operator"][0]
	if resolved, ok := compiled.ResolveGrant(grant); !ok || resolved.Revision != entry.Revision {
		t.Fatalf("SSH grant did not resolve: ok=%v policy=%#v", ok, resolved)
	}
	projection, ok := compiled.ResolveCapabilityGrant(grant)
	if !ok {
		t.Fatal("SSH capability grant did not resolve")
	}
	if projection.Service != "infra" || projection.Adapter != AdapterSSHSession ||
		projection.BaseURL != "https://forcefield.example:7902/ssh/infra" || projection.PathPrefix != "/ssh/infra" ||
		projection.ClientHeader != "Authorization" || projection.ClientPrefix != "Bearer " || projection.SSH == nil ||
		!projection.SSH.AllowShell || !projection.SSH.AllowExec || !projection.SSH.AllowPTY ||
		projection.SSH.MaxSessionDuration.Value() != 30*time.Minute {
		t.Fatalf("SSH capability projection = %#v", projection)
	}
	for _, private := range []string{service.Upstream, service.SSH.User, service.SSH.HostKeySHA256[0], "INFRA_SSH_KEY"} {
		if strings.Contains(projection.BaseURL+projection.CapabilitySummary, private) {
			t.Fatalf("capability projection exposed private SSH detail %q: %#v", private, projection)
		}
	}
}

func TestSSHSessionConfigSupportsPinnedVirtualHostRoute(t *testing.T) {
	t.Parallel()
	file := mustSSHConfig(t).File
	service := file.Services["infra"]
	service.PathPrefix = ""
	service.Host = "infra.forcefield.example"
	file.Services["infra"] = service
	compiled, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := compiled.ResolveCapabilityGrant(compiled.Roles["infra-operator"][0])
	if !ok {
		t.Fatal("SSH virtual-host capability grant did not resolve")
	}
	if projection.Host != "infra.forcefield.example" || projection.PathPrefix != "" ||
		projection.BaseURL != "https://infra.forcefield.example:7902" {
		t.Fatalf("SSH virtual-host projection = %#v", projection)
	}
}

func TestSSHSessionConfigRejectsInvalidAuthorityAndHTTPFields(t *testing.T) {
	t.Parallel()
	trueValue := true
	validSPKI := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name   string
		mutate func(*File)
	}{
		{"missing ssh settings", func(file *File) {
			service := file.Services["infra"]
			service.SSH = nil
			file.Services["infra"] = service
		}},
		{"mixed git settings", func(file *File) {
			service := file.Services["infra"]
			service.Git = &GitServiceConfig{RepositoryCase: gitadapter.RepositoryCaseSensitive}
			file.Services["infra"] = service
		}},
		{"missing user", func(file *File) { file.Services["infra"].SSH.User = "" }},
		{"user with whitespace", func(file *File) { file.Services["infra"].SSH.User = "deploy user" }},
		{"user with bidi control", func(file *File) { file.Services["infra"].SSH.User = "deploy\u202e" }},
		{"missing host key pin", func(file *File) { file.Services["infra"].SSH.HostKeySHA256 = nil }},
		{"wrong host key prefix", func(file *File) { file.Services["infra"].SSH.HostKeySHA256 = []string{"MD5:00"} }},
		{"short host key digest", func(file *File) { file.Services["infra"].SSH.HostKeySHA256 = []string{"SHA256:AAAA"} }},
		{"padded host key digest", func(file *File) {
			file.Services["infra"].SSH.HostKeySHA256 = []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
		}},
		{"duplicate host key pin", func(file *File) {
			pin := file.Services["infra"].SSH.HostKeySHA256[0]
			file.Services["infra"].SSH.HostKeySHA256 = []string{pin, pin}
		}},
		{"too many host key pins", func(file *File) {
			pin := file.Services["infra"].SSH.HostKeySHA256[0]
			file.Services["infra"].SSH.HostKeySHA256 = []string{pin, pin + "A", pin + "B", pin + "C", pin + "D", pin + "E", pin + "F", pin + "G", pin + "H"}
		}},
		{"short connect timeout", func(file *File) { file.Services["infra"].SSH.ConnectTimeout = Duration(time.Second - time.Nanosecond) }},
		{"long connect timeout", func(file *File) {
			file.Services["infra"].SSH.ConnectTimeout = Duration(30*time.Second + time.Nanosecond)
		}},
		{"missing advertised origin", func(file *File) { file.Server.AdvertisedBaseURL = "" }},
		{"missing path route", func(file *File) {
			service := file.Services["infra"]
			service.PathPrefix = ""
			file.Services["infra"] = service
		}},
		{"two routes", func(file *File) {
			service := file.Services["infra"]
			service.Host = "infra.forcefield.example"
			file.Services["infra"] = service
		}},
		{"wrong auth header", func(file *File) {
			service := file.Services["infra"]
			service.ClientAuth.Header = "X-Forcefield-Token"
			file.Services["infra"] = service
		}},
		{"wrong auth prefix", func(file *File) {
			service := file.Services["infra"]
			service.ClientAuth.Prefix = "token "
			file.Services["infra"] = service
		}},
		{"insecure upstream flag", func(file *File) {
			service := file.Services["infra"]
			service.AllowInsecureUpstream = true
			file.Services["infra"] = service
		}},
		{"TLS SPKI pin", func(file *File) {
			service := file.Services["infra"]
			service.PinnedSPKISHA256 = []string{validSPKI}
			file.Services["infra"] = service
		}},
		{"forward headers", func(file *File) {
			service := file.Services["infra"]
			service.ForwardHeaders = []string{"User-Agent"}
			file.Services["infra"] = service
		}},
		{"static headers", func(file *File) {
			service := file.Services["infra"]
			service.StaticHeaders = map[string]string{"X-Version": "1"}
			file.Services["infra"] = service
		}},
		{"response strip headers", func(file *File) {
			service := file.Services["infra"]
			service.Response.StripHeaders = []string{"Server"}
			file.Services["infra"] = service
		}},
		{"response identity", func(file *File) {
			service := file.Services["infra"]
			service.Response.RequireIdentity = &trueValue
			file.Services["infra"] = service
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			file := mustSSHConfig(t).File
			test.mutate(&file)
			if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Compile() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestSSHSessionConfigRejectsInvalidUpstream(t *testing.T) {
	t.Parallel()
	for name, upstream := range map[string]string{
		"HTTPS":             "https://192.0.2.10:22",
		"missing port":      "ssh://192.0.2.10",
		"zero port":         "ssh://192.0.2.10:0",
		"noncanonical port": "ssh://192.0.2.10:022",
		"userinfo":          "ssh://deploy@192.0.2.10:22",
		"path":              "ssh://192.0.2.10:22/home",
		"query":             "ssh://192.0.2.10:22?user=deploy",
		"fragment":          "ssh://192.0.2.10:22#host",
		"bad hostname":      "ssh://bad_host:22",
	} {
		name, upstream := name, upstream
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			file := mustSSHConfig(t).File
			service := file.Services["infra"]
			service.Upstream = upstream
			file.Services["infra"] = service
			if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("upstream %q error = %v", upstream, err)
			}
		})
	}
}

func TestSSHSessionCredentialAndPolicyValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*File)
	}{
		{"credential header injection", func(file *File) {
			credential := file.Credentials["infra-key"]
			credential.Inject = HeaderAuth{Header: "Authorization", Prefix: "Bearer "}
			file.Credentials["infra-key"] = credential
		}},
		{"credential basic transform", func(file *File) {
			credential := file.Credentials["infra-key"]
			credential.BasicUsername = "deploy"
			file.Credentials["infra-key"] = credential
		}},
		{"missing SSH policy", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.SSH = nil
			file.Policies["infra-shell"] = spec
		}},
		{"mixed Git policy", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.Git = &GitPolicyConfig{Rules: []GitRuleConfig{}}
			file.Policies["infra-shell"] = spec
		}},
		{"mixed HTTP rule", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.Rules = []policy.RuleSpec{{ID: "allow", Effect: policy.EffectAllow, Methods: []string{"GET"}, Paths: []string{"/**"}}}
			file.Policies["infra-shell"] = spec
		}},
		{"mixed body limit", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.BodyLimit = 1024
			file.Policies["infra-shell"] = spec
		}},
		{"missing capability summary", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.CapabilitySummary = ""
			file.Policies["infra-shell"] = spec
		}},
		{"no session mode", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.SSH.AllowShell = false
			spec.SSH.AllowExec = false
			file.Policies["infra-shell"] = spec
		}},
		{"PTY without session mode", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.SSH.AllowShell = false
			spec.SSH.AllowExec = false
			spec.SSH.AllowPTY = true
			file.Policies["infra-shell"] = spec
		}},
		{"short session duration", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.SSH.MaxSessionDuration = Duration(time.Second - time.Nanosecond)
			file.Policies["infra-shell"] = spec
		}},
		{"long session duration", func(file *File) {
			spec := file.Policies["infra-shell"]
			spec.SSH.MaxSessionDuration = Duration(24*time.Hour + time.Nanosecond)
			file.Policies["infra-shell"] = spec
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			file := mustSSHConfig(t).File
			test.mutate(&file)
			if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Compile() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestSSHSessionAuthorityChangesInvalidateOnlySSHRevisions(t *testing.T) {
	t.Parallel()
	base, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	file := base.File
	file.Server.AdvertisedBaseURL = "https://forcefield.example:7902"
	file = addGitTestService(file, []GitRuleConfig{{
		ID: "allow-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch,
		Repositories: []string{"acme/repository.git"},
	}})
	file = addSSHTestService(file)
	baseline, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}

	sshGrant := baseline.Roles["infra-operator"][0]
	httpGrant := baseline.Roles["repo-reader"][0]
	gitGrant := baseline.Roles["git-agent"][0]

	service := file.Services["infra"]
	service.SSH.User = "operator"
	file.Services["infra"] = service
	userChanged, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := userChanged.Roles["infra-operator"][0]; got.BindingRevision == sshGrant.BindingRevision || got.PolicyRevision != sshGrant.PolicyRevision {
		t.Fatalf("SSH user revision delta = %#v, baseline %#v", got, sshGrant)
	}
	assertGrantRevisionsEqual(t, "HTTP after SSH binding change", userChanged.Roles["repo-reader"][0], httpGrant)
	assertGrantRevisionsEqual(t, "Git after SSH binding change", userChanged.Roles["git-agent"][0], gitGrant)

	policySpec := file.Policies["infra-shell"]
	policySpec.SSH.AllowPTY = !policySpec.SSH.AllowPTY
	file.Policies["infra-shell"] = policySpec
	policyChanged, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := policyChanged.Roles["infra-operator"][0]; got.PolicyRevision == sshGrant.PolicyRevision {
		t.Fatalf("SSH policy change did not alter policy revision: %#v", got)
	} else if got.BindingRevision != userChanged.Roles["infra-operator"][0].BindingRevision {
		t.Fatalf("SSH policy change unexpectedly changed binding: %#v", got)
	}
	assertGrantRevisionsEqual(t, "HTTP after SSH policy change", policyChanged.Roles["repo-reader"][0], httpGrant)
	assertGrantRevisionsEqual(t, "Git after SSH policy change", policyChanged.Roles["git-agent"][0], gitGrant)

	httpService := file.Services["github"]
	httpService.Upstream = "https://api.github.example"
	file.Services["github"] = httpService
	httpChanged, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if httpChanged.Roles["repo-reader"][0].BindingRevision == httpGrant.BindingRevision {
		t.Fatal("HTTP authority change did not alter the HTTP binding revision")
	}
	assertGrantRevisionsEqual(t, "SSH after HTTP binding change", httpChanged.Roles["infra-operator"][0], policyChanged.Roles["infra-operator"][0])
	assertGrantRevisionsEqual(t, "Git after HTTP binding change", httpChanged.Roles["git-agent"][0], gitGrant)
}

func TestSSHSessionBindingAndPolicyFieldsAreRevisionBound(t *testing.T) {
	t.Parallel()
	baseline := mustSSHConfig(t)
	baseGrant := baseline.Roles["infra-operator"][0]

	bindingMutations := map[string]func(*File){
		"upstream": func(file *File) {
			service := file.Services["infra"]
			service.Upstream = "ssh://192.0.2.11:22"
			file.Services["infra"] = service
		},
		"path route": func(file *File) {
			service := file.Services["infra"]
			service.PathPrefix = "/ssh/other"
			file.Services["infra"] = service
		},
		"user": func(file *File) { file.Services["infra"].SSH.User = "operator" },
		"host key": func(file *File) {
			file.Services["infra"].SSH.HostKeySHA256 = []string{"SHA256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}
		},
		"connect timeout": func(file *File) { file.Services["infra"].SSH.ConnectTimeout = Duration(10 * time.Second) },
		"allowed CIDR": func(file *File) {
			service := file.Services["infra"]
			service.AllowedCIDRs = []string{"192.0.2.0/24"}
			file.Services["infra"] = service
		},
		"secret reference": func(file *File) {
			credential := file.Credentials["infra-key"]
			credential.SecretRef = "OTHER_SSH_KEY"
			file.Credentials["infra-key"] = credential
		},
	}
	for name, mutate := range bindingMutations {
		name, mutate := name, mutate
		t.Run("binding "+name, func(t *testing.T) {
			t.Parallel()
			file := mustSSHConfig(t).File
			mutate(&file)
			changed, err := Compile(file)
			if err != nil {
				t.Fatal(err)
			}
			got := changed.Roles["infra-operator"][0]
			if got.BindingRevision == baseGrant.BindingRevision || got.PolicyRevision != baseGrant.PolicyRevision {
				t.Fatalf("revision delta = %#v, baseline %#v", got, baseGrant)
			}
		})
	}

	policyMutations := map[string]func(*PolicyConfig){
		"shell":    func(policy *PolicyConfig) { policy.SSH.AllowShell = false },
		"exec":     func(policy *PolicyConfig) { policy.SSH.AllowExec = false },
		"PTY":      func(policy *PolicyConfig) { policy.SSH.AllowPTY = false },
		"duration": func(policy *PolicyConfig) { policy.SSH.MaxSessionDuration = Duration(time.Hour) },
		"summary":  func(policy *PolicyConfig) { policy.CapabilitySummary = "Use the configured infrastructure account." },
	}
	for name, mutate := range policyMutations {
		name, mutate := name, mutate
		t.Run("policy "+name, func(t *testing.T) {
			t.Parallel()
			file := mustSSHConfig(t).File
			spec := file.Policies["infra-shell"]
			mutate(&spec)
			file.Policies["infra-shell"] = spec
			changed, err := Compile(file)
			if err != nil {
				t.Fatal(err)
			}
			got := changed.Roles["infra-operator"][0]
			if got.PolicyRevision == baseGrant.PolicyRevision || got.BindingRevision != baseGrant.BindingRevision {
				t.Fatalf("revision delta = %#v, baseline %#v", got, baseGrant)
			}
		})
	}
}

func mustSSHConfig(t *testing.T) *Compiled {
	t.Helper()
	compiled, err := Decode(strings.NewReader(validSSHConfig))
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func addSSHTestService(file File) File {
	file.Services["infra"] = ServiceConfig{
		Adapter: AdapterSSHSession, Upstream: "ssh://192.0.2.10:22", PathPrefix: "/ssh/infra",
		ClientAuth: HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
		SSH: &SSHServiceConfig{
			User: "deploy", HostKeySHA256: []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			ConnectTimeout: Duration(5 * time.Second),
		},
	}
	file.Credentials["infra-key"] = CredentialConfig{Service: "infra", SecretRef: "INFRA_SSH_KEY"}
	file.Policies["infra-shell"] = PolicyConfig{
		Service: "infra", CapabilitySummary: "Open a shell or run a command as the configured account.",
		SSH: &SSHPolicyConfig{AllowShell: true, AllowExec: true, AllowPTY: true, MaxSessionDuration: Duration(30 * time.Minute)},
	}
	file.Roles["infra-operator"] = RoleConfig{Grants: []GrantConfig{{Service: "infra", Credential: "infra-key", Policy: "infra-shell"}}}
	return file
}

func assertGrantRevisionsEqual(t *testing.T, label string, got, want tokens.Grant) {
	t.Helper()
	if got.PolicyRevision != want.PolicyRevision || got.BindingRevision != want.BindingRevision {
		t.Fatalf("%s revisions changed: got %#v, want %#v", label, got, want)
	}
}
