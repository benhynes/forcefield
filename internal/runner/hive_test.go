package runner

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type hiveRoundTripFunc func(*http.Request) (*http.Response, error)

func (function hiveRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHiveProxyPinsOriginAuthorityAndSanitizesHeaders(t *testing.T) {
	t.Parallel()
	token := "host-only-hive-token"
	type capturedRequest struct {
		URL           string
		Host          string
		Authorization string
		Actor         string
		Headers       http.Header
		Body          map[string]string
	}
	var captured capturedRequest
	proxy := newTestHiveProxy(t, HiveConfig{
		URL: "https://hive.example:8443", Network: "dev",
		AllowTo: []string{"lead@debian-dev"}, AllowKinds: []string{"ask"},
	}, token, hiveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		captured.URL = request.URL.String()
		captured.Host = request.Host
		captured.Authorization = request.Header.Get("Authorization")
		captured.Actor = request.Header.Get("X-Hive-Actor")
		captured.Headers = request.Header.Clone()
		if err := json.NewDecoder(request.Body).Decode(&captured.Body); err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header: http.Header{
				"Content-Type":  []string{"application/json"},
				"Authorization": []string{"Bearer " + token},
				"Set-Cookie":    []string{"hive=" + token},
				"Connection":    []string{"X-Hive-Secret"},
				"X-Hive-Secret": []string{token},
			},
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	}))

	request := httptest.NewRequest(http.MethodPost,
		"https://attacker.invalid"+HiveBrokerPrefix+"/v1/nets/dev/send", // absolute targets are never accepted
		strings.NewReader(`{"body":"question","to":"lead@debian-dev","kind":"ask"}`))
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.Host = "attacker.invalid"
	request.Header.Set("Authorization", "Bearer sandbox-token")
	request.Header.Set("Cookie", "sandbox=session")
	request.Header.Set("X-Hive-Actor", "attacker@evil")
	request.Header.Set("Forwarded", "host=evil")
	request.Header.Set("X-Forwarded-Host", "evil")
	request.Header.Set("Connection", "X-Smuggle")
	request.Header.Set("X-Smuggle", "smuggled")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted || recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if captured.URL != "https://hive.example:8443/v1/nets/dev/send" || captured.Host != "hive.example:8443" {
		t.Fatalf("upstream target = %q host %q", captured.URL, captured.Host)
	}
	if captured.Authorization != "Bearer "+token || captured.Actor != "worker@debian-dev" {
		t.Fatalf("trusted authority = %q actor %q", captured.Authorization, captured.Actor)
	}
	for _, header := range []string{"Cookie", "Forwarded", "X-Forwarded-Host", "Connection", "X-Smuggle"} {
		if value := captured.Headers.Get(header); value != "" {
			t.Fatalf("caller header %s survived as %q", header, value)
		}
	}
	if captured.Body["to"] != "lead@debian-dev" || captured.Body["kind"] != "ask" || captured.Body["body"] != "question" {
		t.Fatalf("reconstructed body = %#v", captured.Body)
	}
	for _, header := range []string{"Authorization", "Set-Cookie", "Connection", "X-Hive-Secret"} {
		if value := recorder.Header().Get(header); value != "" {
			t.Fatalf("response exposed %s = %q", header, value)
		}
	}
	if strings.Contains(recorder.Body.String(), token) {
		t.Fatal("host token was returned to the sandbox")
	}
}

func TestHiveProxySendACLIsExact(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	proxy := newTestHiveProxy(t, HiveConfig{
		URL: "http://127.0.0.1:7777", Network: "dev",
		AllowTo:    []string{"lead@debian-dev", "reviewer@mac"},
		AllowKinds: []string{"msg", "answer"},
	}, "hive-token", hiveRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return hiveResponse(http.StatusOK, `{}`), nil
	}))

	tests := []struct {
		name string
		body string
		code int
	}{
		{name: "allowed custom recipient and kind", body: `{"to":"reviewer@mac","kind":"answer","body":"approved","corr_id":"1234"}`, code: http.StatusOK},
		{name: "default msg allowed", body: `{"to":"lead@debian-dev","body":"progress"}`, code: http.StatusOK},
		{name: "recipient is not a prefix match", body: `{"to":"lead@debian-dev.evil","kind":"msg","body":"x"}`, code: http.StatusForbidden},
		{name: "unlisted kind", body: `{"to":"lead@debian-dev","kind":"ask","body":"x"}`, code: http.StatusForbidden},
		{name: "broadcast denied", body: `{"to":"@all","kind":"msg","body":"x"}`, code: http.StatusForbidden},
		{name: "unknown field denied", body: `{"to":"lead@debian-dev","kind":"msg","body":"x","from":"forged@host"}`, code: http.StatusBadRequest},
		{name: "duplicate ACL field denied", body: `{"to":"lead@debian-dev","to":"reviewer@mac","kind":"msg","body":"x"}`, code: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/send", test.body)
			if recorder.Code != test.code {
				t.Fatalf("status = %d body %q, want %d", recorder.Code, recorder.Body.String(), test.code)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("transport calls = %d, want 2", calls.Load())
	}
}

func TestHiveProxyBroadcastRequiresExplicitCapability(t *testing.T) {
	t.Parallel()
	var destination string
	proxy := newTestHiveProxy(t, HiveConfig{
		URL: "http://localhost:7777", Network: "dev",
		AllowKinds: []string{"msg"}, AllowBroadcast: true,
	}, "hive-token", hiveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			To string `json:"to"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		destination = body.To
		return hiveResponse(http.StatusOK, `{}`), nil
	}))
	recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/send", `{"to":"@all","body":"status"}`)
	if recorder.Code != http.StatusOK || destination != "@all" {
		t.Fatalf("response = %d destination %q", recorder.Code, destination)
	}
}

func TestHiveProxyExpandsLocalRecipientAndBoundsBody(t *testing.T) {
	t.Parallel()
	var destination string
	proxy := newTestHiveProxy(t, HiveConfig{
		URL: "http://127.0.0.1:7777", Network: "dev", AllowTo: []string{"reviewer"}, AllowKinds: []string{"msg"},
	}, "hive-token", hiveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			To string `json:"to"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		destination = body.To
		return hiveResponse(http.StatusOK, `{}`), nil
	}))
	if recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/send", `{"to":"reviewer","body":"ok"}`); recorder.Code != http.StatusOK {
		t.Fatalf("local recipient status = %d", recorder.Code)
	}
	if destination != "reviewer@debian-dev" {
		t.Fatalf("destination = %q", destination)
	}
	oversize := `{"to":"reviewer@debian-dev","body":"` + strings.Repeat("x", (8<<10)+1) + `"}`
	if recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/send", oversize); recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d", recorder.Code)
	}
}

func TestHiveProxySynthesizesOnlyLocalHostIdentity(t *testing.T) {
	t.Parallel()
	proxy := newTestHiveProxy(t, testHiveConfig(), "hive-token", hiveRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("synthetic hosts request reached Hive")
		return nil, nil
	}))
	recorder := serveHive(t, proxy, http.MethodGet, "/v1/nets/dev/hosts", "")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("response = %d %#v", recorder.Code, recorder.Header())
	}
	var response struct {
		Self  string            `json:"self"`
		Hosts map[string]string `json:"hosts"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Self != "debian-dev" || len(response.Hosts) != 0 {
		t.Fatalf("synthetic hosts = %#v", response)
	}
}

func TestHiveProxyInboxCannotSelectAnotherAgent(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	proxy := newTestHiveProxy(t, testHiveConfig(), "hive-token", hiveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.RawQuery != "after=0&max=500&stat=1&wait=25" {
			t.Fatalf("canonical query = %q", request.URL.RawQuery)
		}
		return hiveResponse(http.StatusOK, `{"msgs":[]}`), nil
	}))

	allowed := serveHive(t, proxy, http.MethodGet, "/v1/nets/dev/inbox?wait=25&max=500&after=00&stat=1", "")
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed inbox status = %d: %s", allowed.Code, allowed.Body.String())
	}
	for _, query := range []string{"agent=other", "agent=", "after=0&after=1", "unknown=1"} {
		recorder := serveHive(t, proxy, http.MethodGet, "/v1/nets/dev/inbox?"+query, "")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("query %q status = %d", query, recorder.Code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("transport calls = %d, want 1", calls.Load())
	}
}

func TestHiveProxyDeniesControlAndLifecycleRoutes(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	proxy := newTestHiveProxy(t, testHiveConfig(), "hive-token", hiveRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return hiveResponse(http.StatusOK, `{}`), nil
	}))
	routes := []string{
		"/v1/nets/dev/register", "/v1/nets/dev/deregister", "/v1/nets/dev/hosts",
		"/v1/nets/dev/deliver", "/v1/nets/dev/control/rotate", "/v1/nets/dev/spawn",
		"/v1/nets/dev/keys", "/v1/nets/dev/read", "/v1/nets/dev/kill",
		"/v1/nets/other/send", "/v1/health", "/metrics",
	}
	for _, route := range routes {
		recorder := serveHive(t, proxy, http.MethodPost, route, `{}`)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("route %q status = %d", route, recorder.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("denied routes made %d transport calls", calls.Load())
	}
}

func TestHiveProxyDiscoveryAndAckValidation(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	proxy := newTestHiveProxy(t, testHiveConfig(), "hive-token", hiveRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return hiveResponse(http.StatusOK, `{}`), nil
	}))
	for _, route := range []string{"/v1/nets/dev/agents", "/v1/nets/dev/agents?local=0", "/v1/nets/dev/agents?local=1"} {
		if recorder := serveHive(t, proxy, http.MethodGet, route, ""); recorder.Code != http.StatusOK {
			t.Fatalf("route %q status = %d", route, recorder.Code)
		}
	}
	for _, route := range []string{"/v1/nets/dev/agents?local=2", "/v1/nets/dev/agents?host=dev"} {
		if recorder := serveHive(t, proxy, http.MethodGet, route, ""); recorder.Code != http.StatusBadRequest {
			t.Fatalf("route %q status = %d", route, recorder.Code)
		}
	}
	if recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/ack", `{"seq":7}`); recorder.Code != http.StatusOK {
		t.Fatalf("ack status = %d", recorder.Code)
	}
	for _, body := range []string{`{"seq":0}`, `{"seq":-1}`, `{"seq":1.5}`, `{"seq":1,"agent":"other"}`} {
		if recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/ack", body); recorder.Code != http.StatusBadRequest {
			t.Fatalf("ack %q status = %d", body, recorder.Code)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("transport calls = %d, want 4", calls.Load())
	}
}

func TestHiveProxyDefaultTransportHasNoEnvironmentProxyOrRedirectClient(t *testing.T) {
	proxy, err := NewHiveProxy(HiveProxyOptions{
		Config: HiveConfig{
			URL: "http://127.0.0.1:7777", Network: "dev", AllowTo: []string{"lead@host"}, AllowKinds: []string{"msg"},
		},
		Token: "host-token", Actor: "worker@host",
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := proxy.transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("default transport = %#v; environment proxy must be disabled", proxy.transport)
	}

	var roundTrips atomic.Int32
	proxy.transport = hiveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		roundTrips.Add(1)
		if request.Header.Get("Authorization") != "Bearer host-token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://attacker.invalid/steal"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
		}, nil
	})
	recorder := serveHive(t, proxy, http.MethodPost, "/v1/nets/dev/send", `{"to":"lead@host","body":"hello"}`)
	if recorder.Code != http.StatusFound {
		t.Fatalf("redirect response = %d", recorder.Code)
	}
	if roundTrips.Load() != 1 {
		t.Fatalf("Hive proxy made %d RoundTrips for a redirect", roundTrips.Load())
	}
}

func TestNewHiveProxyValidatesOriginTokenAndActor(t *testing.T) {
	t.Parallel()
	valid := testHiveConfig()
	for _, test := range []struct {
		name   string
		config HiveConfig
		token  string
		actor  string
	}{
		{name: "non TLS remote origin", config: withHiveURL(valid, "http://hive.example"), token: "token", actor: "worker@host"},
		{name: "origin path", config: withHiveURL(valid, "https://hive.example/api"), token: "token", actor: "worker@host"},
		{name: "empty token", config: valid, token: "", actor: "worker@host"},
		{name: "whitespace token", config: valid, token: "secret token", actor: "worker@host"},
		{name: "bare actor", config: valid, token: "token", actor: "worker"},
		{name: "broadcast actor", config: valid, token: "token", actor: "@all"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewHiveProxy(HiveProxyOptions{Config: test.config, Token: test.token, Actor: test.actor, Transport: hiveRoundTripFunc(nil)}); err == nil {
				t.Fatal("unsafe Hive proxy options were accepted")
			}
		})
	}
}

func newTestHiveProxy(t *testing.T, config HiveConfig, token string, transport http.RoundTripper) *HiveProxy {
	t.Helper()
	proxy, err := NewHiveProxy(HiveProxyOptions{
		Config: config, Token: token, Actor: "worker@debian-dev", Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func testHiveConfig() HiveConfig {
	return HiveConfig{
		URL: "http://127.0.0.1:7777", Network: "dev", AllowTo: []string{"lead@debian-dev"},
		AllowKinds: []string{"msg"}, AllowDiscovery: true,
	}
}

func withHiveURL(config HiveConfig, value string) HiveConfig {
	config.URL = value
	return config
}

func serveHive(t *testing.T, proxy *HiveProxy, method, route, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, HiveBrokerPrefix+route, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)
	return recorder
}

func hiveResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
