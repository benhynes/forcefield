package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/gitadapter"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/tokens"
)

func TestGitSmartHTTPGatewayClonePushAndGenericRefPolicy(t *testing.T) {
	t.Parallel()
	const upstreamSecret = "forge-upstream-token"
	var calls atomic.Int64
	var lastAuthorization atomic.Value
	var lastBody atomic.Value
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		lastAuthorization.Store(request.Header.Get("Authorization"))
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		lastBody.Store(string(body))
		contentType := "application/x-git-upload-pack-advertisement"
		if strings.HasSuffix(request.URL.Path, "/git-receive-pack") {
			contentType = "application/x-git-receive-pack-result"
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentType}},
			Body: io.NopCloser(strings.NewReader("0000")), Request: request,
		}, nil
	})
	gateway, bearer, auditBuffer := newGitTestGateway(t, transport, upstreamSecret)

	request := func(method, target string, body io.Reader, authorization, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, body)
		req.Host = "forcefield.test"
		req.RemoteAddr = "192.0.2.44:4321"
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, req)
		return recorder
	}

	discoveryURL := "/git/acme/infrastructure.git/info/refs?service=git-upload-pack"
	challenge := request(http.MethodGet, discoveryURL, nil, "", "")
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("WWW-Authenticate") == "" || calls.Load() != 0 {
		t.Fatalf("Git credential challenge = code %d headers %#v calls %d", challenge.Code, challenge.Header(), calls.Load())
	}
	malformed := request(http.MethodGet, "/git/acme/infrastructure.git/HEAD", nil, "", "")
	if malformed.Code != http.StatusNotFound || malformed.Header().Get("WWW-Authenticate") != "" || calls.Load() != 0 {
		t.Fatalf("non-smart route was challenged or forwarded: code=%d calls=%d", malformed.Code, calls.Load())
	}

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(gitClientUsername+":"+bearer))
	fetched := request(http.MethodGet, discoveryURL, nil, basic, "")
	if fetched.Code != http.StatusOK || fetched.Body.String() != "0000" {
		t.Fatalf("fetch discovery = code %d body %q audit %q", fetched.Code, fetched.Body.String(), auditBuffer.String())
	}
	wantUpstreamAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("broker:"+upstreamSecret))
	if got, _ := lastAuthorization.Load().(string); got != wantUpstreamAuthorization {
		t.Fatalf("upstream authorization = %q", got)
	}

	allowedBody := receivePackBody([]string{"refs/heads/main"})
	allowed := request(http.MethodPost, "/git/acme/infrastructure.git/git-receive-pack", bytes.NewReader(allowedBody),
		"Bearer "+bearer, "application/x-git-receive-pack-request")
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed push = code %d body %q audit %q", allowed.Code, allowed.Body.String(), auditBuffer.String())
	}
	if got, _ := lastBody.Load().(string); got != string(allowedBody) {
		t.Fatalf("receive-pack body changed across inspection: %q != %q", got, allowedBody)
	}

	before := calls.Load()
	deniedBody := receivePackBody([]string{"refs/heads/feature", "refs/heads/stable"})
	denied := request(http.MethodPost, "/git/acme/infrastructure.git/git-receive-pack", bytes.NewReader(deniedBody),
		"Bearer "+bearer, "application/x-git-receive-pack-request")
	if denied.Code != http.StatusNotFound || calls.Load() != before {
		t.Fatalf("mixed allowed/denied push reached upstream: code=%d calls=%d before=%d", denied.Code, calls.Load(), before)
	}
	caseAlias := request(http.MethodPost, "/git/acme/INFRASTRUCTURE.git/git-receive-pack", bytes.NewReader(receivePackBody([]string{"refs/heads/stable"})),
		"Bearer "+bearer, "application/x-git-receive-pack-request")
	if caseAlias.Code != http.StatusNotFound || calls.Load() != before {
		t.Fatalf("case-alias repository deny was bypassed: code=%d calls=%d", caseAlias.Code, calls.Load())
	}
	emptyOptions := receivePackBodyWithEmptyPushOptions("refs/heads/feature")
	unsupported := request(http.MethodPost, "/git/acme/infrastructure.git/git-receive-pack", bytes.NewReader(emptyOptions),
		"Bearer "+bearer, "application/x-git-receive-pack-request")
	if unsupported.Code != http.StatusNotFound || calls.Load() != before {
		t.Fatalf("empty negotiated push-options reached upstream: code=%d calls=%d", unsupported.Code, calls.Load())
	}
	if strings.Contains(auditBuffer.String(), bearer) || strings.Contains(auditBuffer.String(), upstreamSecret) || strings.Contains(auditBuffer.String(), "refs/heads/stable") {
		t.Fatal("Git audit log contains credential or raw ref material")
	}
}

func receivePackBodyWithEmptyPushOptions(ref string) []byte {
	payload := strings.Repeat("0", 40) + " " + strings.Repeat("a", 40) + " " + ref + "\x00report-status push-options"
	return []byte(fmt.Sprintf("%04x%s", len(payload)+4, payload) + "0000" + "0000" + "PACKpayload")
}

func newGitTestGateway(t *testing.T, transport http.RoundTripper, upstreamSecret string) (*Gateway, string, *bytes.Buffer) {
	t.Helper()
	temp := t.TempDir()
	compiled, err := config.Compile(config.File{
		Version: 1,
		Server: config.ServerConfig{
			Listen: "127.0.0.1:7902", Audience: "git-test", AdminSocket: filepath.Join(temp, "admin.sock"),
		},
		State: config.StateConfig{
			TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl"), AuditFailure: "closed",
		},
		Secrets: config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_", MaxOutputBytes: 1024, MaxCacheEntries: 8},
		Services: map[string]config.ServiceConfig{
			"git": {
				Adapter: config.AdapterGitSmartHTTP, Upstream: "https://git.example.test", PathPrefix: "/git",
				Git:            &config.GitServiceConfig{RepositoryCase: gitadapter.RepositoryCaseASCIIInsensitive},
				ClientAuth:     config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
				ForwardHeaders: []string{"User-Agent"},
			},
		},
		Credentials: map[string]config.CredentialConfig{
			"git-user": {
				Service: "git", SecretRef: "GIT", Inject: config.HeaderAuth{Header: "Authorization"}, BasicUsername: "broker",
			},
		},
		Policies: map[string]config.PolicyConfig{
			"git-access": {
				Service: "git", Git: &config.GitPolicyConfig{Rules: []config.GitRuleConfig{
					{ID: "allow-fetch", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationFetch, Repositories: []string{"acme/**"}},
					{
						ID: "allow-branches", Effect: gitadapter.EffectAllow, Operation: gitadapter.OperationPush,
						Repositories: []string{"acme/**"}, Refs: []string{"refs/heads/**"},
						UpdateKinds: []gitadapter.UpdateKind{gitadapter.UpdateCreate, gitadapter.UpdateModify, gitadapter.UpdateDelete},
					},
					{
						ID: "deny-stable", Effect: gitadapter.EffectDeny, Operation: gitadapter.OperationPush,
						Repositories: []string{"acme/infrastructure.git"}, Refs: []string{"refs/heads/stable"},
					},
				}},
			},
		},
		Roles: map[string]config.RoleConfig{
			"git-agent": {Grants: []config.GrantConfig{{Service: "git", Credential: "git-user", Policy: "git-access"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := tokens.Open(compiled.File.State.TokenFile, tokens.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	issued, err := store.Mint(context.Background(), tokens.MintRequest{
		Workload: "ip:192.0.2.44", Audience: compiled.File.Server.Audience,
		ExpiresAt: time.Now().Add(time.Hour), Grants: compiled.Roles["git-agent"],
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := secrets.NewFixedBackend([]byte(upstreamSecret))
	t.Cleanup(func() { _ = backend.Close() })
	auditBuffer := &bytes.Buffer{}
	auditor, err := audit.New(auditBuffer, audit.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(compiled, store, backend, auditor, Options{Transports: map[string]http.RoundTripper{"git": transport}})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, issued.Bearer, auditBuffer
}

func receivePackBody(refs []string) []byte {
	var result strings.Builder
	oldOID := strings.Repeat("0", 40)
	for index, ref := range refs {
		payload := oldOID + " " + strings.Repeat(string(rune('a'+index)), 40) + " " + ref
		if index == 0 {
			payload += "\x00report-status"
		}
		result.WriteString(fmt.Sprintf("%04x%s", len(payload)+4, payload))
	}
	result.WriteString("0000PACKpayload")
	return []byte(result.String())
}
