package config

import (
	"errors"
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
