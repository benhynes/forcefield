package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/tokens"
)

type failingWriter struct {
	header http.Header
	status int
	cancel context.CancelFunc
}

type shortWriter struct {
	header http.Header
	writes int
}

func (w *shortWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (*shortWriter) WriteHeader(int) {}
func (w *shortWriter) Write(value []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(value) / 2, nil
	}
	return 0, nil
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *failingWriter) WriteHeader(status int) { w.status = status }
func (w *failingWriter) Write([]byte) (int, error) {
	if w.cancel != nil {
		w.cancel()
	}
	return 0, io.ErrClosedPipe
}

type issuedStore struct {
	revoked          string
	revocationCtxErr error
}

func (s *issuedStore) Mint(context.Context, tokens.MintRequest) (tokens.IssuedToken, error) {
	return tokens.IssuedToken{Bearer: "ff_only-copy", Claims: tokens.Claims{TokenID: strings.Repeat("a", 64), RootTokenID: strings.Repeat("a", 64)}}, nil
}
func (*issuedStore) Validate(context.Context, string, tokens.ValidationRequest) (tokens.Claims, error) {
	return tokens.Claims{}, tokens.ErrInvalidToken
}
func (*issuedStore) Delegate(context.Context, string, tokens.DelegateRequest) (tokens.IssuedToken, error) {
	return tokens.IssuedToken{}, tokens.ErrInvalidToken
}
func (s *issuedStore) RevokeTokenID(ctx context.Context, tokenID string) error {
	s.revocationCtxErr = ctx.Err()
	if s.revocationCtxErr != nil {
		return s.revocationCtxErr
	}
	s.revoked = tokenID
	return nil
}

func TestControlMintAndRevoke(t *testing.T) {
	t.Parallel()
	temp := t.TempDir()
	compiled, err := config.Compile(config.File{
		Version:     1,
		Server:      config.ServerConfig{Listen: "127.0.0.1:7902", Audience: "test", AdminSocket: filepath.Join(temp, "run", "admin.sock"), MaxTokenTTL: config.Duration(time.Hour)},
		State:       config.StateConfig{TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl"), AuditFailure: "closed"},
		Secrets:     config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_", MaxOutputBytes: 1024, MaxCacheEntries: 8},
		Services:    map[string]config.ServiceConfig{"demo": {Upstream: "https://api.example.com", PathPrefix: "/demo", ClientAuth: config.HeaderAuth{Header: "Authorization"}}},
		Credentials: map[string]config.CredentialConfig{"demo": {Service: "demo", SecretRef: "DEMO", Inject: config.HeaderAuth{Header: "Authorization"}}},
		Policies:    map[string]config.PolicyConfig{"read": {Service: "demo", Rules: []policy.RuleSpec{{ID: "read", Effect: policy.EffectAllow, Methods: []string{"GET"}, Paths: []string{"/**"}}}}},
		Roles:       map[string]config.RoleConfig{"reader": {Grants: []config.GrantConfig{{Service: "demo", Credential: "demo", Policy: "read"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := tokens.Open(compiled.File.State.TokenFile, tokens.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var auditBuffer bytes.Buffer
	auditor, err := audit.New(&auditBuffer, audit.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(compiled, store, auditor)
	if err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(MintRequest{Role: "reader", Workload: "ip:127.0.0.1", TTLSeconds: 60})
	request := httptest.NewRequest(http.MethodPost, "/v1/tokens/mint", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("mint status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	var issued tokenResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Validate(context.Background(), issued.Bearer, tokens.ValidationRequest{Workload: "ip:127.0.0.1", Audience: "test"}); err != nil {
		t.Fatal(err)
	}

	payload, _ = json.Marshal(RevokeRequest{TokenID: issued.Claims.TokenID})
	request = httptest.NewRequest(http.MethodPost, "/v1/tokens/revoke", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d", recorder.Code)
	}
	if _, err := store.Validate(context.Background(), issued.Bearer, tokens.ValidationRequest{Workload: "ip:127.0.0.1", Audience: "test"}); err == nil {
		t.Fatal("revoked token still validates")
	}

	maliciousBearer := "ff_" + strings.Repeat("A", 43)
	payload, _ = json.Marshal(RevokeRequest{TokenID: maliciousBearer})
	request = httptest.NewRequest(http.MethodPost, "/v1/tokens/revoke", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bearer-shaped token ID status=%d", recorder.Code)
	}
	if strings.Contains(auditBuffer.String(), maliciousBearer) {
		t.Fatal("bearer-shaped token ID leaked to audit output")
	}

	payload, _ = json.Marshal(MintRequest{Role: "reader", Workload: maliciousBearer, TTLSeconds: 60})
	request = httptest.NewRequest(http.MethodPost, "/v1/tokens/mint", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bearer-shaped workload status=%d", recorder.Code)
	}
	if strings.Contains(auditBuffer.String(), maliciousBearer) {
		t.Fatal("bearer-shaped workload leaked to audit output")
	}
}

func TestControlIdentifiersAreCanonical(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"ip:127.0.0.1",
		"ip:2001:db8::1",
		"mtls-spki:" + strings.Repeat("a", 64),
	} {
		if !validWorkloadID(value) {
			t.Errorf("valid workload rejected: %q", value)
		}
	}
	for _, value := range []string{
		"ip:127.000.000.001",
		"ip:2001:0db8::1",
		"mtls-spki:" + strings.Repeat("A", 64),
		"vm://runner",
		"ff_" + strings.Repeat("A", 43),
	} {
		if validWorkloadID(value) {
			t.Errorf("invalid workload accepted: %q", value)
		}
	}
	if !validTokenID(strings.Repeat("a", 64)) || validTokenID(strings.Repeat("A", 64)) || validTokenID("ff_"+strings.Repeat("A", 43)) {
		t.Fatal("public token ID validation is not canonical")
	}
}

func TestWriteJSONRejectsNoProgressAfterShortWrite(t *testing.T) {
	t.Parallel()
	writer := &shortWriter{}
	if err := writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short response write error = %v", err)
	}
	if writer.writes != 2 {
		t.Fatalf("response writes = %d, want 2", writer.writes)
	}
}

func TestFilterGrantsCannotBroaden(t *testing.T) {
	t.Parallel()
	parent := []tokens.Grant{{Service: "github"}, {Service: "slack"}}
	if got := filterGrants(parent, []string{"github"}); len(got) != 1 || got[0].Service != "github" {
		t.Fatalf("got %#v", got)
	}
	if got := filterGrants(parent, []string{"github", "aws"}); got != nil {
		t.Fatalf("unknown service broadened grants: %#v", got)
	}
}

func TestMintRevokesIfBearerDeliveryFails(t *testing.T) {
	t.Parallel()
	temp := t.TempDir()
	compiled, err := config.Compile(config.File{
		Version:     1,
		Server:      config.ServerConfig{Listen: "127.0.0.1:7902", Audience: "test", AdminSocket: filepath.Join(temp, "admin.sock")},
		State:       config.StateConfig{TokenFile: filepath.Join(temp, "tokens.json"), AuditFile: filepath.Join(temp, "audit.jsonl")},
		Secrets:     config.SecretBackendConfig{Type: "env", EnvPrefix: "FF_TEST_"},
		Services:    map[string]config.ServiceConfig{"demo": {Upstream: "https://api.example.com", PathPrefix: "/demo", ClientAuth: config.HeaderAuth{Header: "Authorization"}}},
		Credentials: map[string]config.CredentialConfig{"demo": {Service: "demo", SecretRef: "DEMO", Inject: config.HeaderAuth{Header: "Authorization"}}},
		Policies:    map[string]config.PolicyConfig{"read": {Service: "demo", Rules: []policy.RuleSpec{{ID: "read", Effect: policy.EffectAllow}}}},
		Roles:       map[string]config.RoleConfig{"reader": {Grants: []config.GrantConfig{{Service: "demo", Credential: "demo", Policy: "read"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &issuedStore{}
	var auditBuffer bytes.Buffer
	auditor, _ := audit.New(&auditBuffer, audit.FailClosed)
	server, err := NewServer(compiled, store, auditor)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(MintRequest{Role: "reader", Workload: "ip:127.0.0.1", TTLSeconds: 60})
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/v1/tokens/mint", bytes.NewReader(payload)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	writer := &failingWriter{cancel: cancel}
	server.handler().ServeHTTP(writer, request)
	if store.revocationCtxErr != nil {
		t.Fatalf("compensating revocation inherited canceled request context: %v", store.revocationCtxErr)
	}
	if store.revoked != strings.Repeat("a", 64) {
		t.Fatalf("undelivered token was not revoked: %q", store.revoked)
	}
}
