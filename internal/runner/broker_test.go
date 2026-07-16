package runner

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
)

const brokerTestConfig = `
version: 1
server:
  listen: 127.0.0.1:7902
  audience: forcefield-test
  admin_socket: /tmp/forcefield-runner-test/admin.sock
state:
  token_file: /tmp/forcefield-runner-test/tokens.json
  audit_file: /tmp/forcefield-runner-test/audit.jsonl
secrets:
  type: env
  env_prefix: FF_TEST_
services:
  openai:
    upstream: https://api.openai.example/v1
    path_prefix: /openai
    client_auth: {header: Authorization, prefix: "Bearer "}
    forward_headers: [Content-Type, Idempotency-Key]
  anthropic:
    upstream: https://api.anthropic.example
    path_prefix: /anthropic
    client_auth: {header: x-api-key}
    forward_headers: [Content-Type]
credentials:
  openai-agent:
    service: openai
    secret_ref: OPENAI
    inject: {header: Authorization, prefix: "Bearer "}
  anthropic-agent:
    service: anthropic
    secret_ref: ANTHROPIC
    inject: {header: x-api-key}
policies:
  openai-agent:
    service: openai
    rules: [{id: allow, effect: allow, methods: [POST], paths: [/**]}]
  anthropic-agent:
    service: anthropic
    rules: [{id: allow, effect: allow, methods: [POST], paths: [/**]}]
roles:
  worker:
    grants:
      - {service: openai, credential: openai-agent, policy: openai-agent}
`

type brokerRoundTripFunc func(*http.Request) (*http.Response, error)

func (function brokerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestBrokerInjectsCapabilityAndStripsCallerCredentials(t *testing.T) {
	t.Parallel()
	compiled := brokerCompiled(t)
	bearer := brokerBearer()
	var captured *http.Request
	transport := brokerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured = request.Clone(request.Context())
		captured.Header = request.Header.Clone()
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Set-Cookie":   []string{"session=secret"},
				"Connection":   []string{"X-Internal"},
				"X-Internal":   []string{"remove"},
			},
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	})
	broker, err := NewBroker(compiled, BrokerOptions{
		BaseURL: "https://forcefield.example", Bearer: bearer,
		AllowedServices: []string{"openai"}, Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/openai/v1/responses?stream=true", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer attacker")
	request.Header.Set("X-Api-Key", "attacker")
	request.Header.Set("Cookie", "session=attacker")
	request.Header.Set("Idempotency-Key", "safe-id")
	request.Header.Set("Connection", "X-Smuggle")
	request.Header.Set("X-Smuggle", "remove")
	recorder := httptest.NewRecorder()
	broker.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated || recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if captured == nil {
		t.Fatal("request was not relayed")
	}
	if captured.URL.String() != "https://forcefield.example/openai/v1/responses?stream=true" {
		t.Fatalf("outbound URL = %q", captured.URL)
	}
	if got := captured.Header.Get("Authorization"); got != "Bearer "+bearer {
		t.Fatalf("authorization = %q", got)
	}
	for _, name := range []string{"X-Api-Key", "Cookie", "Connection", "X-Smuggle"} {
		if got := captured.Header.Get(name); got != "" {
			t.Fatalf("%s survived as %q", name, got)
		}
	}
	if got := captured.Header.Get("Idempotency-Key"); got != "safe-id" {
		t.Fatalf("idempotency key = %q", got)
	}
	if recorder.Header().Get("Set-Cookie") != "" || recorder.Header().Get("X-Internal") != "" {
		t.Fatalf("unsafe response headers = %#v", recorder.Header())
	}
}

func TestBrokerRestrictsRoutesToGrantedServices(t *testing.T) {
	t.Parallel()
	called := false
	broker, err := NewBroker(brokerCompiled(t), BrokerOptions{
		BaseURL: "http://127.0.0.1:7902", Bearer: brokerBearer(),
		AllowedServices: []string{"openai"},
		Transport: brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/anthropic/v1/messages", "/unknown", "/openai-other"} {
		recorder := httptest.NewRecorder()
		broker.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
	if called {
		t.Fatal("ungranted route reached the transport")
	}
}

func TestBrokerCapabilityDiscoveryUsesReservedCarrier(t *testing.T) {
	t.Parallel()
	bearer := brokerBearer()
	var authorization string
	broker, err := NewBroker(brokerCompiled(t), BrokerOptions{
		BaseURL: "https://forcefield.example", Bearer: bearer,
		AllowedServices: []string{"openai"},
		Transport: brokerRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			authorization = request.Header.Get("Authorization")
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	broker.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, config.CapabilitiesPath, nil))
	if authorization != "Bearer "+bearer {
		t.Fatalf("authorization = %q", authorization)
	}
}

func TestBrokerFlushesServerSentEventsAsTheyArrive(t *testing.T) {
	t.Parallel()
	reader, upstream := io.Pipe()
	broker, err := NewBroker(brokerCompiled(t), BrokerOptions{
		BaseURL: "https://forcefield.example", Bearer: brokerBearer(), AllowedServices: []string{"openai"},
		Transport: brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream; charset=utf-8"}}, Body: reader,
			}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	writer := newFlushResponseWriter()
	done := make(chan struct{})
	go func() {
		broker.ServeHTTP(writer, httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil))
		close(done)
	}()
	if _, err := upstream.Write([]byte("data: first\n\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-writer.flushes:
		if body != "data: first\n\n" {
			t.Fatalf("first flushed body = %q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("first SSE event was not flushed")
	}
	_ = upstream.Close()
	<-done
}

func TestBrokerRejectsNonOriginAndMalformedBearer(t *testing.T) {
	t.Parallel()
	compiled := brokerCompiled(t)
	for _, base := range []string{"http://example.com", "https://user@example.com", "https://example.com/path", "https://example.com?q=1"} {
		if _, err := NewBroker(compiled, BrokerOptions{BaseURL: base, Bearer: brokerBearer(), AllowedServices: []string{"openai"}, Transport: brokerRoundTripFunc(nil)}); err == nil {
			t.Fatalf("base URL %q was accepted", base)
		}
	}
	if _, err := NewBroker(compiled, BrokerOptions{BaseURL: "https://example.com", Bearer: "ff_bad", AllowedServices: []string{"openai"}, Transport: brokerRoundTripFunc(nil)}); err == nil {
		t.Fatal("malformed bearer was accepted")
	}
}

func TestBrokerDispatchesReservedHiveRouteWithoutForcefieldToken(t *testing.T) {
	t.Parallel()
	forcefieldCalled := false
	hiveAuthorization := ""
	broker, err := NewBroker(brokerCompiled(t), BrokerOptions{
		BaseURL: "https://forcefield.example", Bearer: brokerBearer(), AllowedServices: []string{"openai"},
		Transport: brokerRoundTripFunc(func(*http.Request) (*http.Response, error) {
			forcefieldCalled = true
			return nil, nil
		}),
		Hive: &HiveProxyOptions{
			Config: HiveConfig{URL: "http://127.0.0.1:7777", Network: "dev", AllowTo: []string{"lead@vm1"}, AllowKinds: []string{"msg"}},
			Token:  "personal-hive-token", Actor: "worker@vm1",
			Transport: hiveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				hiveAuthorization = request.Header.Get("Authorization")
				return hiveResponse(http.StatusOK, `{}`), nil
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, HiveBrokerPrefix+"/v1/nets/dev/send", strings.NewReader(`{"to":"lead@vm1","body":"done"}`))
	recorder := httptest.NewRecorder()
	broker.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || forcefieldCalled {
		t.Fatalf("Hive dispatch status=%d forcefield_called=%v", recorder.Code, forcefieldCalled)
	}
	if hiveAuthorization != "Bearer personal-hive-token" {
		t.Fatalf("Hive authorization = %q", hiveAuthorization)
	}
	if strings.Contains(recorder.Body.String(), "personal-hive-token") {
		t.Fatal("Hive token leaked in response")
	}
}

func TestBrokerRejectsForcefieldRouteOverlappingHivePrefix(t *testing.T) {
	t.Parallel()
	compiled := brokerCompiled(t)
	service := compiled.File.Services["openai"]
	service.PathPrefix = "/.forcefield-runner"
	compiled.File.Services["openai"] = service
	_, err := NewBroker(compiled, BrokerOptions{
		BaseURL: "https://forcefield.example", Bearer: brokerBearer(), AllowedServices: []string{"openai"},
		Transport: brokerRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
		Hive: &HiveProxyOptions{
			Config: HiveConfig{URL: "http://127.0.0.1:7777", Network: "dev", AllowKinds: []string{"msg"}},
			Token:  "personal-hive-token", Actor: "worker@vm1", Transport: hiveRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
		},
	})
	if err == nil {
		t.Fatal("overlapping Forcefield and Hive routes were accepted")
	}
}

func brokerCompiled(t *testing.T) *config.Compiled {
	t.Helper()
	compiled, err := config.Decode(strings.NewReader(brokerTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func brokerBearer() string {
	return tokens.BearerPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}

type flushResponseWriter struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	body    bytes.Buffer
	flushes chan string
}

func newFlushResponseWriter() *flushResponseWriter {
	return &flushResponseWriter{header: make(http.Header), flushes: make(chan string, 8)}
}

func (writer *flushResponseWriter) Header() http.Header { return writer.header }

func (writer *flushResponseWriter) WriteHeader(status int) { writer.status = status }

func (writer *flushResponseWriter) Write(contents []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.body.Write(contents)
}

func (writer *flushResponseWriter) Flush() {
	writer.mu.Lock()
	body := writer.body.String()
	writer.mu.Unlock()
	if body == "" {
		return
	}
	writer.flushes <- body
}
