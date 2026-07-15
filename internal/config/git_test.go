package config

import (
	"strings"
	"testing"

	"github.com/benhynes/forcefield/internal/gitadapter"
)

func TestGitSmartHTTPPolicyIsGenericAndDenyWins(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	file := addGitTestService(compiled.File, []GitRuleConfig{
		{
			ID: "allow-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch,
			Repositories: []string{"acme/**"},
		},
		{
			ID: "allow-branches", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationPush,
			Repositories: []string{"acme/**"}, Refs: []string{"refs/heads/**"},
			UpdateKinds: []gitadapter.UpdateKind{gitadapter.UpdateCreate, gitadapter.UpdateModify, gitadapter.UpdateDelete},
		},
		{
			ID: "deny-stable", Effect: gitadapter.EffectDeny, Operation: gitadapter.OperationPush,
			Repositories: []string{"acme/infrastructure.git"}, Refs: []string{"refs/heads/stable"},
		},
	})
	withGit, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	entry := withGit.Policies["git-access"]
	if entry.Adapter != AdapterGitSmartHTTP || entry.Policy != nil || entry.GitPolicy == nil {
		t.Fatalf("compiled git policy = %#v", entry)
	}
	preflight := entry.GitPolicy.CanAccessRepository(gitadapter.RepositoryAccessRequest{
		Repository: "acme/infrastructure.git", Service: gitadapter.ServiceReceivePack,
		Operation: gitadapter.OperationPush, ProtocolVersion: 0,
	})
	if !preflight.Allowed {
		t.Fatalf("ref-scoped push grant did not authorize discovery: %#v", preflight)
	}

	request := func(repository, ref string) gitadapter.PolicyRequest {
		return gitadapter.PolicyRequest{
			Repository: repository, Service: gitadapter.ServiceReceivePack,
			Operation: gitadapter.OperationPush, ProtocolVersion: 0,
			ReceivePack: &gitadapter.ReceivePackRequest{
				Kind: gitadapter.ReceivePackPush, ObjectFormat: gitadapter.ObjectFormatSHA1,
				Updates: []gitadapter.Update{{
					OldOID: strings.Repeat("0", 40), NewOID: strings.Repeat("a", 40),
					Ref: ref, Kind: gitadapter.UpdateCreate,
				}},
			},
		}
	}
	if decision := entry.GitPolicy.Evaluate(request("acme/infrastructure.git", "refs/heads/main")); !decision.Allowed {
		t.Fatalf("adapter hardcoded a main-branch restriction: %#v", decision)
	}
	if decision := entry.GitPolicy.Evaluate(request("acme/infrastructure.git", "refs/heads/stable")); decision.Allowed || decision.Reason != gitadapter.ReasonExplicitDeny {
		t.Fatalf("configured protected ref was not denied: %#v", decision)
	}
	canonicalRepository, err := gitadapter.NormalizeRepository("acme/INFRASTRUCTURE.git", file.Services["git"].Git.RepositoryCase)
	if err != nil {
		t.Fatal(err)
	}
	if decision := entry.GitPolicy.Evaluate(request(canonicalRepository, "refs/heads/stable")); decision.Allowed || decision.Reason != gitadapter.ReasonExplicitDeny {
		t.Fatalf("case alias bypassed the configured repository deny: %#v", decision)
	}
}

func TestGitSmartHTTPConfigValidationAndRevisionIsolation(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	originalBinding := compiled.Roles["repo-reader"][0].BindingRevision
	file := addGitTestService(compiled.File, []GitRuleConfig{
		{
			ID: "allow-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch,
			Repositories: []string{"acme/repository.git"},
		},
	})
	withGit, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := withGit.Roles["repo-reader"][0].BindingRevision; got != originalBinding {
		t.Fatalf("adding an independent Git adapter invalidated an HTTP grant: %q != %q", got, originalBinding)
	}

	bad := withGit.File
	policyConfig := bad.Policies["git-access"]
	policyConfig.Git = &GitPolicyConfig{Rules: []GitRuleConfig{{
		ID: "fake-force", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationPush,
		Repositories: []string{"acme/repository.git"}, Refs: []string{"refs/heads/**"},
		UpdateKinds: []gitadapter.UpdateKind{"force"},
	}}}
	bad.Policies["git-access"] = policyConfig
	if _, err := Compile(bad); err == nil {
		t.Fatal("unobservable force update kind was accepted")
	}

	bad = withGit.File
	policyConfig = bad.Policies["git-access"]
	policyConfig.Git = &GitPolicyConfig{Rules: []GitRuleConfig{{
		ID: "ref-filtered-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch,
		Repositories: []string{"acme/repository.git"}, Refs: []string{"refs/heads/main"},
	}}}
	bad.Policies["git-access"] = policyConfig
	if _, err := Compile(bad); err == nil {
		t.Fatal("fetch policy incorrectly claimed ref-level confidentiality")
	}

	bad = withGit.File
	service := bad.Services["git"]
	service.ForwardHeaders = append(service.ForwardHeaders, "Git-Protocol")
	bad.Services["git"] = service
	if _, err := Compile(bad); err == nil {
		t.Fatal("Git adapter accepted a client-forwarded protocol header")
	}
}

func TestBasicPasswordInjectionIsValidatedAndRevisionBound(t *testing.T) {
	compiled, err := Decode(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	file := addGitTestService(compiled.File, []GitRuleConfig{{
		ID: "allow-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch,
		Repositories: []string{"acme/repository.git"},
	}})
	headerCredential, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	original := headerCredential.Roles["git-agent"][0].BindingRevision
	credential := file.Credentials["git-user"]
	credential.Inject.Prefix = ""
	credential.BasicUsername = "broker"
	file.Credentials["git-user"] = credential
	basicCredential, err := Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	if basicCredential.Roles["git-agent"][0].BindingRevision == original {
		t.Fatal("Basic-password transform did not change the credential binding revision")
	}
	credential.BasicUsername = "bad:user"
	file.Credentials["git-user"] = credential
	if _, err := Compile(file); err == nil {
		t.Fatal("invalid Basic username was accepted")
	}
}

func addGitTestService(file File, rules []GitRuleConfig) File {
	file.Services["git"] = ServiceConfig{
		Adapter: AdapterGitSmartHTTP, Upstream: "https://git.example.test", PathPrefix: "/git",
		Git:            &GitServiceConfig{RepositoryCase: gitadapter.RepositoryCaseASCIIInsensitive},
		ClientAuth:     HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
		ForwardHeaders: []string{"User-Agent"},
	}
	file.Credentials["git-user"] = CredentialConfig{
		Service: "git", SecretRef: "GIT_TOKEN", Inject: HeaderAuth{Header: "Authorization", Prefix: "token "},
	}
	file.Policies["git-access"] = PolicyConfig{
		Service: "git", CapabilitySummary: "Fetch configured repositories and push configured refs.",
		Git: &GitPolicyConfig{Rules: rules},
	}
	file.Roles["git-agent"] = RoleConfig{Grants: []GrantConfig{{Service: "git", Credential: "git-user", Policy: "git-access"}}}
	return file
}
