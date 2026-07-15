package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/tokens"
)

const capabilityTestSecret = "real-upstream-capability-test-secret"

type countingCapabilityBackend struct {
	calls atomic.Int64
}

func (b *countingCapabilityBackend) Get(context.Context, string) (*secrets.Lease, error) {
	b.calls.Add(1)
	return secrets.NewLease([]byte(capabilityTestSecret)), nil
}

type capabilityGatewayFixture struct {
	gateway       *Gateway
	compiled      *config.Compiled
	store         *tokens.Store
	issued        tokens.IssuedToken
	backend       *countingCapabilityBackend
	upstreamCalls *atomic.Int64
	upstreamURL   string
	auditLog      *bytes.Buffer
}

type failingCapabilityResponseWriter struct {
	header http.Header
	status int
	wrote  int
}

func (writer *failingCapabilityResponseWriter) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *failingCapabilityResponseWriter) WriteHeader(status int) { writer.status = status }

func (writer *failingCapabilityResponseWriter) Write(value []byte) (int, error) {
	writer.wrote = len(value) / 2
	return writer.wrote, io.ErrUnexpectedEOF
}

func newCapabilityGatewayFixture(t *testing.T) *capabilityGatewayFixture {
	t.Helper()
	temp := t.TempDir()
	upstreamURL := "http://upstream.forcefield.invalid"
	compiled, err := config.Compile(config.File{
		Version: 1,
		Server: config.ServerConfig{
			Listen:            "127.0.0.1:7902",
			Audience:          "capability-test-audience",
			AdminSocket:       filepath.Join(temp, "admin.sock"),
			AdvertisedBaseURL: "https://forcefield.test:7902",
		},
		State: config.StateConfig{
			TokenFile: filepath.Join(temp, "tokens.json"),
			AuditFile: filepath.Join(temp, "audit.jsonl"),
		},
		Secrets: config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_CAPABILITY_TEST_"},
		Services: map[string]config.ServiceConfig{
			"demo": {
				Upstream: upstreamURL, PathPrefix: "/demo", AllowInsecureUpstream: true,
				ClientAuth: config.HeaderAuth{Header: "X-Forcefield-Token", Prefix: "Token "},
			},
		},
		Credentials: map[string]config.CredentialConfig{
			"demo-reader": {
				Service: "demo", SecretRef: "DEMO_SECRET",
				Inject: config.HeaderAuth{Header: "Authorization", Prefix: "Bearer "},
			},
		},
		Policies: map[string]config.PolicyConfig{
			"demo-read": {
				Service:           "demo",
				CapabilitySummary: "Read the explicitly allowed demo resource.",
				Rules: []policy.RuleSpec{{
					ID: "allow-resource", Effect: policy.EffectAllow,
					Methods: []string{http.MethodGet}, Paths: []string{"/resource"},
				}},
			},
		},
		Roles: map[string]config.RoleConfig{
			"reader": {Grants: []config.GrantConfig{{
				Service: "demo", Credential: "demo-reader", Policy: "demo-read",
				Limits: config.LimitsConfig{RequestBudget: 1},
			}}},
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
	issued, err := store.Mint(t.Context(), tokens.MintRequest{
		Workload: "ip:192.0.2.10", Audience: compiled.File.Server.Audience,
		ExpiresAt: time.Now().Add(time.Hour), Grants: compiled.Roles["reader"],
	})
	if err != nil {
		t.Fatal(err)
	}

	backend := &countingCapabilityBackend{}
	var upstreamCalls atomic.Int64
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		if got := request.Header.Get("Authorization"); got != "Bearer "+capabilityTestSecret {
			t.Errorf("upstream Authorization = %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    request,
		}, nil
	})
	var auditLog bytes.Buffer
	auditor, err := audit.New(&auditLog, audit.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(compiled, store, backend, auditor, Options{
		Transports: map[string]http.RoundTripper{"demo": transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &capabilityGatewayFixture{
		gateway: gateway, compiled: compiled, store: store, issued: issued,
		backend: backend, upstreamCalls: &upstreamCalls, upstreamURL: upstreamURL,
		auditLog: &auditLog,
	}
}

func (fixture *capabilityGatewayFixture) request(method, target, remoteAddr, header, bearer string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	request.Host = "forcefield.test"
	request.RemoteAddr = remoteAddr
	if bearer != "" {
		request.Header.Set(header, bearer)
	}
	recorder := httptest.NewRecorder()
	fixture.gateway.ServeHTTP(recorder, request)
	return recorder
}

func (fixture *capabilityGatewayFixture) capabilities(remoteAddr, bearer string) *httptest.ResponseRecorder {
	return fixture.request(http.MethodGet, config.CapabilitiesPath, remoteAddr, "Authorization", "Bearer "+bearer)
}

func TestCapabilityEndpointReturnsSanitizedLiveGrantWithoutExercisingAuthority(t *testing.T) {
	fixture := newCapabilityGatewayFixture(t)

	for attempt := 0; attempt < 2; attempt++ {
		response := fixture.capabilities("192.0.2.10:4321", fixture.issued.Bearer)
		if response.Code != http.StatusOK {
			t.Fatalf("capability response %d: code=%d body=%q audit=%q", attempt, response.Code, response.Body.String(), fixture.auditLog.String())
		}
		if got := response.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := response.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q", got)
		}
		if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("X-Content-Type-Options = %q", got)
		}

		body := response.Body.String()
		var manifest capabilities.Manifest
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			t.Fatal(err)
		}
		if err := manifest.Validate(); err != nil {
			t.Fatal(err)
		}
		if len(manifest.Services) != 1 {
			t.Fatalf("services = %#v", manifest.Services)
		}
		service := manifest.Services[0]
		if service.Name != "demo" || service.Adapter != "http" || service.BaseURL != "https://forcefield.test:7902/demo" || service.PathPrefix != "/demo" {
			t.Fatalf("service route = %#v", service)
		}
		if service.Auth.Header != "X-Forcefield-Token" || service.Auth.Prefix != "Token " {
			t.Fatalf("service auth convention = %#v", service.Auth)
		}
		if service.CapabilitySummary != "Read the explicitly allowed demo resource." || service.ConfiguredLimits.RequestBudget != 1 {
			t.Fatalf("service policy projection = %#v", service)
		}
		if !manifest.ExpiresAt.Equal(fixture.issued.Claims.ExpiresAt) {
			t.Fatalf("manifest expiry %s != token expiry %s", manifest.ExpiresAt, fixture.issued.Claims.ExpiresAt)
		}

		for label, forbidden := range map[string]string{
			"bearer":            fixture.issued.Bearer,
			"upstream":          fixture.upstreamURL,
			"upstream secret":   capabilityTestSecret,
			"credential name":   "demo-reader",
			"secret reference":  "DEMO_SECRET",
			"policy revision":   fixture.issued.Claims.Grants[0].PolicyRevision,
			"binding revision":  fixture.issued.Claims.Grants[0].BindingRevision,
			"internal token id": fixture.issued.Claims.TokenID,
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("capability response contains %s", label)
			}
		}
	}
	if got := fixture.backend.calls.Load(); got != 0 {
		t.Fatalf("capability discovery fetched %d secrets", got)
	}
	if got := fixture.upstreamCalls.Load(); got != 0 {
		t.Fatalf("capability discovery made %d upstream requests", got)
	}

	allowed := fixture.request(
		http.MethodGet, "/demo/resource", "192.0.2.10:4321",
		"X-Forcefield-Token", "Token "+fixture.issued.Bearer,
	)
	if allowed.Code != http.StatusOK || allowed.Body.String() != `{"ok":true}` {
		t.Fatalf("first authorized request: code=%d body=%q", allowed.Code, allowed.Body.String())
	}
	if fixture.backend.calls.Load() != 1 || fixture.upstreamCalls.Load() != 1 {
		t.Fatalf("authorized request activity: secrets=%d upstream=%d", fixture.backend.calls.Load(), fixture.upstreamCalls.Load())
	}

	exhausted := fixture.request(
		http.MethodGet, "/demo/resource", "192.0.2.10:4321",
		"X-Forcefield-Token", "Token "+fixture.issued.Bearer,
	)
	if exhausted.Code != http.StatusTooManyRequests {
		t.Fatalf("second authorized request code = %d", exhausted.Code)
	}
	if fixture.backend.calls.Load() != 1 || fixture.upstreamCalls.Load() != 1 {
		t.Fatal("budget-denied request exercised secret or upstream authority")
	}
}

func TestCapabilityEndpointAuthenticationFailuresAreGeneric(t *testing.T) {
	fixture := newCapabilityGatewayFixture(t)

	malformed := fixture.capabilities("192.0.2.10:4321", "not-a-forcefield-token")
	resolverFailure := fixture.capabilities("not-a-remote-address", fixture.issued.Bearer)
	wrongWorkload := fixture.capabilities("192.0.2.11:4321", fixture.issued.Bearer)
	wrongCarrier := fixture.request(
		http.MethodGet, config.CapabilitiesPath, "192.0.2.10:4321",
		"X-Forcefield-Token", "Token "+fixture.issued.Bearer,
	)
	if err := fixture.store.Revoke(t.Context(), fixture.issued.Bearer); err != nil {
		t.Fatal(err)
	}
	revoked := fixture.capabilities("192.0.2.10:4321", fixture.issued.Bearer)

	for name, response := range map[string]*httptest.ResponseRecorder{
		"malformed": malformed, "workload resolution": resolverFailure, "wrong workload": wrongWorkload,
		"wrong carrier": wrongCarrier, "revoked": revoked,
	} {
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s response code = %d", name, response.Code)
		}
		if response.Body.String() != malformed.Body.String() || response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s response was distinguishable: headers=%#v body=%q", name, response.Header(), response.Body.String())
		}
	}
	if fixture.backend.calls.Load() != 0 || fixture.upstreamCalls.Load() != 0 {
		t.Fatal("denied capability discovery exercised secret or upstream authority")
	}
	if got := strings.Count(fixture.auditLog.String(), "\n"); got != 5 {
		t.Fatalf("sampled authentication-failure audit records = %d, want 5", got)
	}
	if got := len(fixture.gateway.discoveryDenials.states); got < 1 || got > 2 {
		t.Fatalf("denied discovery allocated %d sampler states, want only the global hourly state(s)", got)
	}
	if len(fixture.gateway.discoveryLimits.states) != 0 || len(fixture.gateway.limits.states) != 0 {
		t.Fatal("denied discovery touched authenticated discovery or service-budget state")
	}
}

func TestCapabilityEndpointRejectsNonExactRequests(t *testing.T) {
	fixture := newCapabilityGatewayFixture(t)
	tests := map[string]*http.Request{
		"method":      httptest.NewRequest(http.MethodPost, config.CapabilitiesPath, nil),
		"query":       httptest.NewRequest(http.MethodGet, config.CapabilitiesPath+"?refresh=true", nil),
		"empty query": httptest.NewRequest(http.MethodGet, config.CapabilitiesPath+"?", nil),
		"body":        httptest.NewRequest(http.MethodGet, config.CapabilitiesPath, strings.NewReader("unexpected")),
	}
	unknownLength := httptest.NewRequest(http.MethodGet, config.CapabilitiesPath, nil)
	unknownLength.Body = io.NopCloser(strings.NewReader("unexpected"))
	unknownLength.ContentLength = -1
	tests["unknown-length body"] = unknownLength

	for name, request := range tests {
		request.Host = "forcefield.test"
		request.RemoteAddr = "192.0.2.10:4321"
		request.Header.Set("Authorization", "Bearer "+fixture.issued.Bearer)
		recorder := httptest.NewRecorder()
		fixture.gateway.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound || recorder.Body.String() != "{\"error\":\"request denied\"}\n" {
			t.Fatalf("%s request: code=%d body=%q", name, recorder.Code, recorder.Body.String())
		}
	}
	if fixture.backend.calls.Load() != 0 || fixture.upstreamCalls.Load() != 0 {
		t.Fatal("non-exact capability request exercised authority")
	}
}

func TestCapabilityEndpointUsesIndependentDiscoveryRateLimit(t *testing.T) {
	fixture := newCapabilityGatewayFixture(t)
	fixedNow := time.Now()
	fixture.gateway.discoveryLimits.now = func() time.Time { return fixedNow }
	second, err := fixture.store.Mint(t.Context(), tokens.MintRequest{
		Workload: "ip:192.0.2.10", Audience: fixture.compiled.File.Server.Audience,
		ExpiresAt: time.Now().Add(time.Hour), Grants: fixture.compiled.Roles["reader"],
	})
	if err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < capabilityBurst; attempt++ {
		bearer := fixture.issued.Bearer
		if attempt%2 != 0 {
			bearer = second.Bearer
		}
		response := fixture.capabilities("192.0.2.10:4321", bearer)
		if response.Code != http.StatusOK {
			t.Fatalf("discovery request %d code = %d", attempt, response.Code)
		}
	}
	limited := fixture.capabilities("192.0.2.10:4321", fixture.issued.Bearer)
	if limited.Code != http.StatusTooManyRequests || limited.Body.String() != "{\"error\":\"request denied\"}\n" {
		t.Fatalf("limited discovery: code=%d body=%q", limited.Code, limited.Body.String())
	}
	if fixture.backend.calls.Load() != 0 || fixture.upstreamCalls.Load() != 0 {
		t.Fatal("discovery rate limiting exercised secret or upstream authority")
	}
	if got := strings.Count(fixture.auditLog.String(), "\n"); got != capabilityBurst*2 {
		t.Fatalf("throttled discovery amplified audit records: got %d, want %d", got, capabilityBurst*2)
	}
	if len(fixture.gateway.limits.states) != 0 {
		t.Fatal("discovery allocated service-budget limiter state")
	}

	allowed := fixture.request(
		http.MethodGet, "/demo/resource", "192.0.2.10:4321",
		"X-Forcefield-Token", "Token "+fixture.issued.Bearer,
	)
	if allowed.Code != http.StatusOK {
		t.Fatalf("independent service budget was charged: code=%d body=%q", allowed.Code, allowed.Body.String())
	}
}

func TestCapabilityEndpointAuditsActualResponseWriteFailure(t *testing.T) {
	fixture := newCapabilityGatewayFixture(t)
	request := httptest.NewRequest(http.MethodGet, config.CapabilitiesPath, nil)
	request.Host = "forcefield.test"
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("Authorization", "Bearer "+fixture.issued.Bearer)
	writer := &failingCapabilityResponseWriter{}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		fixture.gateway.ServeHTTP(writer, request)
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("write failure panic = %#v", recovered)
	}
	if writer.status != http.StatusOK || writer.wrote == 0 {
		t.Fatalf("writer status=%d bytes=%d", writer.status, writer.wrote)
	}

	lines := strings.Split(strings.TrimSpace(fixture.auditLog.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit records = %d: %q", len(lines), fixture.auditLog.String())
	}
	var authorization, completion struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Status   int    `json:"status"`
		BytesOut int64  `json:"bytes_out"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &authorization); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &completion); err != nil {
		t.Fatal(err)
	}
	if authorization.Decision != string(audit.DecisionAllow) || authorization.Status != 0 || authorization.BytesOut != 0 {
		t.Fatalf("authorization audit = %#v", authorization)
	}
	if completion.Decision != string(audit.DecisionError) || completion.Reason != "response_write" || completion.Status != http.StatusOK || completion.BytesOut != int64(writer.wrote) {
		t.Fatalf("completion audit = %#v", completion)
	}
}

func TestCapabilityEndpointOmitsSupersededGrant(t *testing.T) {
	fixture := newCapabilityGatewayFixture(t)
	stale := fixture.compiled.Roles["reader"][0]
	stale.PolicyRevision = "sha256:" + strings.Repeat("0", 64)
	issued, err := fixture.store.Mint(t.Context(), tokens.MintRequest{
		Workload: "ip:192.0.2.10", Audience: fixture.compiled.File.Server.Audience,
		ExpiresAt: time.Now().Add(time.Hour), Grants: []tokens.Grant{stale},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.capabilities("192.0.2.10:4321", issued.Bearer)
	if response.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", response.Code, response.Body.String())
	}
	var manifest capabilities.Manifest
	if err := json.Unmarshal(response.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Services) != 0 {
		t.Fatalf("superseded grant was advertised: %#v", manifest.Services)
	}
	if fixture.backend.calls.Load() != 0 || fixture.upstreamCalls.Load() != 0 {
		t.Fatal("superseded grant discovery exercised authority")
	}
}
