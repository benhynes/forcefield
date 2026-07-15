package gateway

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/tokens"
)

func TestGatewayEndToEndInjectionPolicyAndResponseGuard(t *testing.T) {
	t.Parallel()
	const realSecret = "real-upstream-secret"
	var upstreamCalls atomic.Int64
	var upstreamAuthorization atomic.Value
	upstreamURL := "http://127.0.0.1:43210"
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		upstreamAuthorization.Store(r.Header.Get("Authorization"))
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: r}
		switch r.URL.Path {
		case "/resource":
			response.Header.Set("Content-Type", "application/json")
			response.Body = io.NopCloser(strings.NewReader(`{"ok":true}`))
		case "/echo":
			response.Body = io.NopCloser(strings.NewReader(fmt.Sprintf("debug authorization=%s", r.Header.Get("Authorization"))))
		case "/redirect":
			response.StatusCode = http.StatusFound
			response.Header.Set("Location", upstreamURL+"/resource")
			response.Body = io.NopCloser(strings.NewReader("redirect"))
		default:
			response.StatusCode = http.StatusNotFound
			response.Body = io.NopCloser(strings.NewReader("not found"))
		}
		return response, nil
	})

	temp := t.TempDir()
	requireIdentity := true
	compiled, err := config.Compile(config.File{
		Version: 1,
		Server:  config.ServerConfig{Listen: "127.0.0.1:7902", Audience: "test-audience", AdminSocket: filepath.Join(temp, "admin.sock")},
		State:   config.StateConfig{TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl"), AuditFailure: "closed"},
		Secrets: config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_", MaxOutputBytes: 1024, MaxCacheEntries: 8},
		Services: map[string]config.ServiceConfig{
			"demo": {
				Upstream: upstreamURL, PathPrefix: "/demo", AllowInsecureUpstream: true,
				AllowedCIDRs: []string{"127.0.0.0/8"}, ClientAuth: config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
				ForwardHeaders: []string{"Accept", "Content-Type"}, Response: config.ResponseConfig{RequireIdentity: &requireIdentity},
			},
		},
		Credentials: map[string]config.CredentialConfig{
			"demo-reader": {Service: "demo", SecretRef: "DEMO", Inject: config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "}},
		},
		Policies: map[string]config.PolicyConfig{
			"demo-read": {Service: "demo", Rules: []policy.RuleSpec{
				{ID: "deny-admin", Effect: policy.EffectDeny, Paths: []string{"/admin/**"}},
				{ID: "allow-demo", Effect: policy.EffectAllow, Methods: []string{http.MethodGet}, Paths: []string{"/resource", "/echo", "/redirect"}},
			}},
		},
		Roles: map[string]config.RoleConfig{
			"reader": {Grants: []config.GrantConfig{{Service: "demo", Credential: "demo-reader", Policy: "demo-read"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := tokens.Open(compiled.File.State.TokenFile, tokens.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	issued, err := store.Mint(context.Background(), tokens.MintRequest{
		Workload: "ip:192.0.2.10", Audience: compiled.File.Server.Audience,
		ExpiresAt: time.Now().Add(time.Hour), Grants: compiled.Roles["reader"],
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := secrets.NewFixedBackend([]byte(realSecret))
	defer backend.Close()
	var auditBuffer bytes.Buffer
	auditor, err := audit.New(&auditBuffer, audit.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(compiled, store, backend, auditor, Options{Transports: map[string]http.RoundTripper{"demo": transport}})
	if err != nil {
		t.Fatal(err)
	}

	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "forcefield.test"
		req.RemoteAddr = "192.0.2.10:4321"
		req.Header.Set("Authorization", "Bearer "+issued.Bearer)
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, req)
		return recorder
	}

	recorder := request("/demo/resource")
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("resource response: code=%d body=%q audit=%q", recorder.Code, recorder.Body.String(), auditBuffer.String())
	}
	if got, _ := upstreamAuthorization.Load().(string); got != "Bearer "+realSecret {
		t.Fatalf("upstream authorization=%q", got)
	}
	if strings.Contains(auditBuffer.String(), issued.Bearer) || strings.Contains(auditBuffer.String(), realSecret) {
		t.Fatal("audit log contains credential material")
	}

	calls := upstreamCalls.Load()
	recorder = request("/demo/admin/secrets")
	if recorder.Code != http.StatusNotFound || upstreamCalls.Load() != calls {
		t.Fatalf("denied request reached upstream: code=%d calls=%d", recorder.Code, upstreamCalls.Load())
	}
	auditLines := strings.Split(strings.TrimSpace(auditBuffer.String()), "\n")
	var deniedRecord map[string]any
	if err := json.Unmarshal([]byte(auditLines[len(auditLines)-1]), &deniedRecord); err != nil {
		t.Fatalf("decode deny audit record: %v", err)
	}
	if deniedRecord["decision"] != "deny" || deniedRecord["status"] != float64(http.StatusNotFound) {
		t.Fatalf("deny audit did not record wire outcome: %#v", deniedRecord)
	}

	recorder = request("/demo/redirect")
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "/demo/resource" {
		t.Fatalf("redirect was not safely rewritten: code=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}

	recorder = request("/demo/echo")
	if strings.Contains(recorder.Body.String(), realSecret) {
		t.Fatalf("reflected secret reached client: %q", recorder.Body.String())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestGatewayRejectsWrongWorkloadAndAmbiguousCredentials(t *testing.T) {
	t.Parallel()
	// Header extraction itself rejects duplicate authentication fields before
	// token validation, providing a cheap request-smuggling boundary.
	a, err := NewHeaderAdapter(HeaderAdapterConfig{ClientHeader: "Authorization", ClientPrefix: "Bearer ", UpstreamHeader: "Authorization", UpstreamPrefix: "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://forcefield.test/demo/resource", nil)
	r.Header.Add("Authorization", "Bearer ff_abcdefghijklmnopqrstuvwxyz")
	r.Header.Add("Authorization", "Bearer ff_bbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if _, err := a.ExtractToken(r); err == nil {
		t.Fatal("duplicate token header accepted")
	}
}
