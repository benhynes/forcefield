package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/benhynes/forcefield/internal/policy"
)

const validConfig = `
version: 1
server:
  listen: 127.0.0.1:7902
  audience: forcefield-test
  admin_socket: /tmp/forcefield-test/admin.sock
state:
  token_file: /tmp/forcefield-test/tokens.json
  audit_file: /tmp/forcefield-test/audit.jsonl
  audit_failure: closed
secrets:
  type: env
  env_prefix: FF_TEST_
services:
  github:
    upstream: https://api.github.com
    path_prefix: /github
    client_auth: {header: Authorization, prefix: "Bearer "}
    forward_headers: [Accept, Content-Type]
credentials:
  github-reader:
    service: github
    secret_ref: GITHUB_READER
    inject: {header: Authorization, prefix: "Bearer "}
policies:
  github-read:
    service: github
    rules:
      - id: deny-keys
        effect: deny
        methods: [GET]
        paths: [/user/keys]
      - id: allow-repos
        effect: allow
        methods: [GET]
        paths: [/repos/**]
roles:
  repo-reader:
    grants:
      - service: github
        credential: github-reader
        policy: github-read
        limits: {requests_per_second: 5, burst: 10}
`

func TestDecodeAndCompile(t *testing.T) {
	t.Parallel()
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Roles["repo-reader"]) != 1 {
		t.Fatalf("role grants: %#v", compiled.Roles)
	}
	grant := compiled.Roles["repo-reader"][0]
	if grant.Service != "github" || grant.CredentialRef != "github-reader" || grant.PolicyRevision == "" || grant.BindingRevision == "" {
		t.Fatalf("grant: %#v", grant)
	}
	if compiled.PoliciesByRevision[grant.PolicyRevision].Name != "github-read" {
		t.Fatal("policy revision was not indexed")
	}
}

func TestBindingRevisionInvalidatesRetargetedCredential(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	original := compiled.Roles["repo-reader"][0].BindingRevision
	file := compiled.File
	credential := file.Credentials["github-reader"]
	credential.SecretRef = "GITHUB_OTHER"
	file.Credentials["github-reader"] = credential
	recompiled, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if recompiled.Roles["repo-reader"][0].BindingRevision == original {
		t.Fatal("credential retargeting did not change binding revision")
	}
}

func TestStaticHeadersAreBoundAndCanonicalized(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	service := compiled.File.Services["github"]
	service.StaticHeaders = map[string]string{"X-GitHub-Api-Version": "2022-11-28"}
	compiled.File.Services["github"] = service
	first, err := Compile(compiled.File)
	if err != nil {
		t.Fatal(err)
	}
	service.StaticHeaders["X-GitHub-Api-Version"] = "2099-01-01"
	compiled.File.Services["github"] = service
	second, err := Compile(compiled.File)
	if err != nil {
		t.Fatal(err)
	}
	if first.Roles["repo-reader"][0].BindingRevision == second.Roles["repo-reader"][0].BindingRevision {
		t.Fatal("static header value did not affect binding revision")
	}

	service.StaticHeaders = map[string]string{"X-Version": "1", "x-version": "2"}
	compiled.File.Services["github"] = service
	if _, err := Compile(compiled.File); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("case-distinct static headers error = %v", err)
	}
}

func TestCompileRejectsSecondaryCredentialHeaders(t *testing.T) {
	t.Parallel()
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	service := compiled.File.Services["github"]
	service.ClientAuth = HeaderAuth{Header: "X-Forcefield-Token"}
	service.ForwardHeaders = []string{"Authorization"}
	compiled.File.Services["github"] = service
	credential := compiled.File.Credentials["github-reader"]
	credential.Inject = HeaderAuth{Header: "X-Api-Key"}
	compiled.File.Credentials["github-reader"] = credential
	if _, err := Compile(compiled.File); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("secondary Authorization error = %v", err)
	}

	service.ForwardHeaders = nil
	service.StaticHeaders = map[string]string{"X-Client-Secret": "configured-secret"}
	compiled.File.Services["github"] = service
	if _, err := Compile(compiled.File); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("static credential error = %v", err)
	}
}

func TestDecodeRejectsUnknownField(t *testing.T) {
	t.Parallel()
	_, err := Decode(strings.NewReader(strings.Replace(validConfig, "audience: forcefield-test", "audience: forcefield-test\n  typo: true", 1)))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestCompileRejectsCrossServiceGrant(t *testing.T) {
	t.Parallel()
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	file := compiled.File
	file.Services["slack"] = ServiceConfig{Upstream: "https://slack.com", PathPrefix: "/slack", ClientAuth: HeaderAuth{Header: "Authorization"}}
	file.Roles["repo-reader"] = RoleConfig{Grants: []GrantConfig{{Service: "slack", Credential: "github-reader", Policy: "github-read"}}}
	if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestCompileRejectsOpenBridgeByDefault(t *testing.T) {
	t.Parallel()
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	file := compiled.File
	file.Server.Listen = "0.0.0.0:7902"
	if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestCapabilitiesConfigurationAndGrantResolution(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	originalGrant := compiled.Roles["repo-reader"][0]
	if _, ok := compiled.ResolveGrant(originalGrant); !ok {
		t.Fatal("freshly compiled grant did not resolve")
	}

	file := compiled.File
	file.Server.AdvertisedBaseURL = "https://forcefield.test"
	policyConfig := file.Policies["github-read"]
	policyConfig.CapabilitySummary = "Read repository metadata and contents under the configured paths."
	file.Policies["github-read"] = policyConfig
	recompiled, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := recompiled.File.Server.AdvertisedBaseURL; got != "https://forcefield.test" {
		t.Fatalf("advertised_base_url = %q", got)
	}
	if got := recompiled.File.Policies["github-read"].CapabilitySummary; got != policyConfig.CapabilitySummary {
		t.Fatalf("capability_summary = %q", got)
	}
	if recompiled.Roles["repo-reader"][0].PolicyRevision == originalGrant.PolicyRevision {
		t.Fatal("capability summary did not invalidate the policy revision")
	}
	if recompiled.Roles["repo-reader"][0].BindingRevision == originalGrant.BindingRevision {
		t.Fatal("advertised base URL did not invalidate the credential binding revision")
	}
	if _, ok := recompiled.ResolveGrant(originalGrant); ok {
		t.Fatal("grant with the superseded policy revision still resolved")
	}
	if _, ok := recompiled.ResolveGrant(recompiled.Roles["repo-reader"][0]); !ok {
		t.Fatal("grant carrying the current policy revision did not resolve")
	}

	staleBinding := recompiled.Roles["repo-reader"][0]
	staleBinding.BindingRevision = "sha256:" + strings.Repeat("0", 64)
	if _, ok := recompiled.ResolveGrant(staleBinding); ok {
		t.Fatal("grant carrying a stale credential binding resolved")
	}
}

func TestCompileRejectsInvalidCapabilitiesConfiguration(t *testing.T) {
	t.Parallel()

	for name, advertisedURL := range map[string]string{
		"credentials":  "https://agent:secret@forcefield.test",
		"path":         "https://forcefield.test/api",
		"query":        "https://forcefield.test?debug=true",
		"fragment":     "https://forcefield.test#debug",
		"non-http":     "ssh://forcefield.test",
		"plaintext":    "http://forcefield.test",
		"bad hostname": "https://.",
		"bad port":     "https://forcefield.test:00080",
		"too long":     "https://" + strings.Repeat("a", 513),
	} {
		t.Run("advertised_"+name, func(t *testing.T) {
			compiled, err := Decode(strings.NewReader(validConfig))
			if err != nil {
				t.Fatal(err)
			}
			file := compiled.File
			file.Server.AdvertisedBaseURL = advertisedURL
			if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("advertised_base_url %q error = %v", advertisedURL, err)
			}
		})
	}

	for name, summary := range map[string]string{
		"leading whitespace":  " scope",
		"trailing whitespace": "scope ",
		"newline":             "read\nwrite",
		"tab":                 "read\twrite",
		"unicode line":        "read\u2028write",
		"bidi override":       "read\u202ewrite",
		"bidi isolate":        "read\u2066write",
		"embedded bearer":     "read " + "ff_" + strings.Repeat("A", 43),
		"nul":                 "read\x00write",
		"too long":            strings.Repeat("x", 513),
		"invalid utf8":        string([]byte{0xff}),
	} {
		t.Run("summary_"+name, func(t *testing.T) {
			compiled, err := Decode(strings.NewReader(validConfig))
			if err != nil {
				t.Fatal(err)
			}
			file := compiled.File
			policyConfig := file.Policies["github-read"]
			policyConfig.CapabilitySummary = summary
			file.Policies["github-read"] = policyConfig
			if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("capability_summary error = %v", err)
			}
		})
	}

	for _, pathPrefix := range []string{
		CapabilitiesPath,
		"/.well-known",
		"/.well-known/forcefield",
	} {
		t.Run("reserved_"+strings.ReplaceAll(pathPrefix, "/", "_"), func(t *testing.T) {
			compiled, err := Decode(strings.NewReader(validConfig))
			if err != nil {
				t.Fatal(err)
			}
			file := compiled.File
			service := file.Services["github"]
			service.PathPrefix = pathPrefix
			file.Services["github"] = service
			if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("reserved path_prefix %q error = %v", pathPrefix, err)
			}
		})
	}

	t.Run("oversized_path_prefix", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		service := file.Services["github"]
		service.PathPrefix = "/" + strings.Repeat("a", 4096)
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("oversized path_prefix error = %v", err)
		}
	})

	t.Run("control_in_auth_prefix", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		service := file.Services["github"]
		service.ClientAuth.Prefix = "Bearer \x1b"
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("control-bearing auth prefix error = %v", err)
		}
	})

	t.Run("bearer_in_auth_prefix", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		service := file.Services["github"]
		service.ClientAuth.Prefix = "Token ff_" + strings.Repeat("A", 43)
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("bearer-bearing auth prefix error = %v", err)
		}
	})

	t.Run("oversized_client_auth_header", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		service := file.Services["github"]
		service.ClientAuth.Header = strings.Repeat("X", CapabilityAuthHeaderMaxBytes+1)
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("oversized client auth header error = %v", err)
		}
	})

	t.Run("bidi_in_path_prefix", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		service := file.Services["github"]
		service.PathPrefix = "/github\u202eadmin"
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("bidi path_prefix error = %v", err)
		}
	})

	t.Run("advertised_service_url_too_long", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		file.Server.AdvertisedBaseURL = "https://forcefield.test"
		service := file.Services["github"]
		service.PathPrefix = "/" + strings.Repeat("a", CapabilityServiceURLMaxBytes-1)
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("oversized advertised service URL error = %v", err)
		}
	})

	t.Run("plaintext_host_route", func(t *testing.T) {
		compiled, err := Decode(strings.NewReader(validConfig))
		if err != nil {
			t.Fatal(err)
		}
		file := compiled.File
		file.Server.AdvertisedBaseURL = "http://127.0.0.1:7902"
		service := file.Services["github"]
		service.PathPrefix = ""
		service.Host = "github.forcefield.test"
		file.Services["github"] = service
		if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("plaintext host route error = %v", err)
		}
	})
}

func TestCompileRejectsCapabilityProjectionSetThatWouldExceedBound(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	file := compiled.File
	file.Services = make(map[string]ServiceConfig)
	file.Credentials = make(map[string]CredentialConfig)
	file.Policies = make(map[string]PolicyConfig)
	grants := make([]GrantConfig, 0, CapabilityManifestMaxServices)
	for index := 0; index < CapabilityManifestMaxServices; index++ {
		serviceName := fmt.Sprintf("service%02d", index)
		credentialName := fmt.Sprintf("credential%02d", index)
		policyName := fmt.Sprintf("policy%02d", index)
		file.Services[serviceName] = ServiceConfig{
			Upstream:   "https://api.example.test/" + serviceName,
			PathPrefix: "/" + serviceName + "-" + strings.Repeat("x", 3000),
			ClientAuth: HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
		}
		file.Credentials[credentialName] = CredentialConfig{
			Service: serviceName, SecretRef: strings.ToUpper(credentialName),
			Inject: HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
		}
		file.Policies[policyName] = PolicyConfig{
			Service: serviceName, CapabilitySummary: strings.Repeat("scope", 100),
			Rules: []policy.RuleSpec{{ID: "allow", Effect: policy.EffectAllow, Methods: []string{"GET"}, Paths: []string{"/**"}}},
		}
		grants = append(grants, GrantConfig{Service: serviceName, Credential: credentialName, Policy: policyName})
	}
	file.Roles = map[string]RoleConfig{"too-large": {Grants: grants}}
	if _, err := Compile(file); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("oversized capability manifest error = %v", err)
	}

	for index := 8; index < CapabilityManifestMaxServices; index++ {
		delete(file.Services, fmt.Sprintf("service%02d", index))
		delete(file.Credentials, fmt.Sprintf("credential%02d", index))
		delete(file.Policies, fmt.Sprintf("policy%02d", index))
	}
	file.Roles = map[string]RoleConfig{"bounded": {Grants: grants[:8]}}
	if _, err := Compile(file); err != nil {
		t.Fatalf("bounded capability manifest was rejected: %v", err)
	}
}

func TestPoliciesDefaultDeny(t *testing.T) {
	t.Parallel()
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	entry := compiled.Policies["github-read"]
	decision := entry.Policy.Evaluate(t.Context(), policyRequest("POST", "/repos/acme/widget"))
	if decision.Allowed() {
		t.Fatal("unmatched request was allowed")
	}
}

func policyRequest(method, path string) policy.Request {
	return policy.Request{Method: method, EscapedPath: path}
}
