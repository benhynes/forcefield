package runner

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/benhynes/forcefield/internal/headersafety"
)

const (
	// HiveBrokerPrefix is the private route exposed by the runner broker. It is
	// deliberately outside Hive's own API namespace, so the sandbox cannot use
	// the broker as a generic proxy to an arbitrary Hive route.
	HiveBrokerPrefix = "/.forcefield-runner/hive"

	hiveMaximumRequestBytes = 64 << 10
	hiveMaximumTokenBytes   = 4 << 10
)

// HiveProxyOptions contains the Hive authority retained by the trusted
// runner. Token must be a personal MSG token for Actor, never a network or
// CONTROL token. Transport is a test seam; production callers should leave it
// nil to get the direct, environment-proxy-free transport.
type HiveProxyOptions struct {
	Config    HiveConfig
	Token     string
	Actor     string
	Transport http.RoundTripper
}

// HiveProxy is a narrow, deny-by-default reverse proxy to one configured Hive
// origin and network. It does not register agents or expose Hive CONTROL
// routes. The sandbox never receives the bearer retained here.
type HiveProxy struct {
	base      *url.URL
	network   string
	localHost string
	allowTo   map[string]struct{}
	allowKind map[string]struct{}
	broadcast bool
	discovery bool
	transport http.RoundTripper

	credentials sync.RWMutex
	token       string
	actor       string
	cleared     bool
}

// NewHiveProxy validates and freezes an operator-owned Hive policy.
func NewHiveProxy(options HiveProxyOptions) (*HiveProxy, error) {
	config := options.Config
	config.AllowTo = append([]string(nil), config.AllowTo...)
	config.AllowKinds = append([]string(nil), config.AllowKinds...)
	if !config.Enabled() {
		return nil, errors.New("runner Hive proxy requires a configured Hive URL")
	}
	if err := validateHiveConfig(&config); err != nil {
		return nil, fmt.Errorf("runner Hive proxy: %w", err)
	}
	base, err := validateBrokerOrigin(config.URL)
	if err != nil {
		return nil, errors.New("runner Hive proxy requires an HTTPS or loopback HTTP origin")
	}
	if !validHiveProxyToken(options.Token) {
		return nil, errors.New("runner Hive proxy requires a bounded bearer without whitespace")
	}
	if !validHiveActor(options.Actor) {
		return nil, errors.New("runner Hive proxy actor must be a canonical name@host address")
	}

	_, actorHost, _ := strings.Cut(options.Actor, "@")
	allowTo := make(map[string]struct{}, len(config.AllowTo))
	for _, recipient := range config.AllowTo {
		if !strings.Contains(recipient, "@") {
			recipient += "@" + actorHost
		}
		allowTo[recipient] = struct{}{}
	}
	allowKind := make(map[string]struct{}, len(config.AllowKinds))
	for _, kind := range config.AllowKinds {
		allowKind[kind] = struct{}{}
	}
	transport := options.Transport
	if transport == nil {
		transport = newHiveTransport()
	}
	return &HiveProxy{
		base: base, network: config.Network, localHost: actorHost, allowTo: allowTo, allowKind: allowKind,
		broadcast: config.AllowBroadcast, discovery: config.AllowDiscovery,
		transport: transport, token: options.Token, actor: options.Actor,
	}, nil
}

// ServeHTTP accepts only the guest-facing HiveBrokerPrefix routes documented
// below. It never derives an upstream host, network, actor, or credential from
// the caller.
func (proxy *HiveProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if proxy == nil || proxy.transport == nil || request == nil || request.URL == nil ||
		request.URL.IsAbs() || request.URL.Scheme != "" || request.URL.Host != "" || request.URL.Opaque != "" ||
		request.URL.RawPath != "" || request.URL.Path == "" || request.URL.Path[0] != '/' ||
		request.Header.Get("Upgrade") != "" || len(request.Trailer) != 0 {
		http.NotFound(writer, request)
		return
	}

	token, actor, ok := proxy.authority()
	if !ok {
		http.Error(writer, "Hive capability is unavailable", http.StatusServiceUnavailable)
		return
	}

	upstreamPath := strings.TrimPrefix(request.URL.Path, HiveBrokerPrefix)
	expectedPrefix := "/v1/nets/" + proxy.network
	if upstreamPath == request.URL.Path || !strings.HasPrefix(upstreamPath, expectedPrefix+"/") {
		http.NotFound(writer, request)
		return
	}

	var body []byte
	var rawQuery string
	var err error
	switch upstreamPath {
	case expectedPrefix + "/hosts":
		// Hive's MCP client asks /hosts only to expand a bare recipient to
		// name@<local-host> when HIVE_ADDR is explicitly set. Return the one
		// non-authoritative fact already pinned by HIVE_AGENT; never proxy the
		// real host-routing or mutation surface.
		if request.Method != http.MethodGet || request.URL.RawQuery != "" || !emptyHiveRequestBody(request) {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(struct {
			Self  string            `json:"self"`
			Hosts map[string]string `json:"hosts"`
		}{Self: proxy.localHost, Hosts: map[string]string{}})
		return
	case expectedPrefix + "/agents":
		if request.Method != http.MethodGet || !proxy.discovery || !emptyHiveRequestBody(request) {
			hiveRouteDenied(writer, request, proxy.discovery)
			return
		}
		rawQuery, err = validateHiveAgentsQuery(request.URL.RawQuery)
	case expectedPrefix + "/send":
		if request.Method != http.MethodPost || request.URL.RawQuery != "" {
			http.NotFound(writer, request)
			return
		}
		body, err = proxy.validateHiveSend(writer, request)
	case expectedPrefix + "/inbox":
		if request.Method != http.MethodGet || !emptyHiveRequestBody(request) {
			http.NotFound(writer, request)
			return
		}
		rawQuery, err = validateHiveInboxQuery(request.URL.RawQuery)
	case expectedPrefix + "/ack":
		if request.Method != http.MethodPost || request.URL.RawQuery != "" {
			http.NotFound(writer, request)
			return
		}
		body, err = validateHiveAck(writer, request)
	default:
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		if !errors.Is(err, errHiveResponseWritten) {
			http.Error(writer, "invalid Hive request", http.StatusBadRequest)
		}
		return
	}

	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.URL.Scheme = proxy.base.Scheme
	outbound.URL.Host = proxy.base.Host
	outbound.URL.Path = upstreamPath
	outbound.URL.RawPath = ""
	outbound.URL.RawQuery = rawQuery
	outbound.URL.ForceQuery = false
	outbound.Host = proxy.base.Host
	outbound.Header = request.Header.Clone()
	stripBrokerHeaders(outbound.Header)
	outbound.Header.Del("Proxy-Connection")
	outbound.Header.Set("Authorization", "Bearer "+token)
	outbound.Header.Set("X-Hive-Actor", actor)
	outbound.Trailer = nil
	outbound.TransferEncoding = nil
	if body == nil {
		outbound.Body = nil
		outbound.GetBody = nil
		outbound.ContentLength = 0
		outbound.Header.Del("Content-Type")
	} else {
		outbound.Body = io.NopCloser(bytes.NewReader(body))
		outbound.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		outbound.ContentLength = int64(len(body))
		outbound.Header.Set("Content-Type", "application/json")
	}

	response, roundTripErr := proxy.transport.RoundTrip(outbound)
	// Do not retain the host bearer in a request object longer than the actual
	// RoundTrip call. A custom transport must follow the RoundTripper contract
	// and stop using the request before it returns.
	outbound.Header.Del("Authorization")
	outbound.Header.Del("X-Hive-Actor")
	if roundTripErr != nil {
		http.Error(writer, "Hive request failed", http.StatusBadGateway)
		return
	}
	if response == nil || response.Body == nil {
		http.Error(writer, "Hive returned an invalid response", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyBrokerResponseHeaders(writer.Header(), response.Header)
	stripHiveResponseHeaders(writer.Header())
	writer.WriteHeader(response.StatusCode)
	copyBrokerResponseBody(writer, response)
}

// CloseIdleConnections closes connections retained by the proxy transport.
func (proxy *HiveProxy) CloseIdleConnections() {
	if proxy == nil || proxy.transport == nil {
		return
	}
	if closer, ok := proxy.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Clear irreversibly removes the proxy's bearer and actor. New requests are
// rejected, while a RoundTrip already in flight may still complete.
func (proxy *HiveProxy) Clear() {
	if proxy == nil {
		return
	}
	proxy.credentials.Lock()
	proxy.token = ""
	proxy.actor = ""
	proxy.cleared = true
	proxy.credentials.Unlock()
	proxy.CloseIdleConnections()
}

func (proxy *HiveProxy) authority() (token, actor string, ok bool) {
	proxy.credentials.RLock()
	defer proxy.credentials.RUnlock()
	if proxy.cleared || proxy.token == "" || proxy.actor == "" {
		return "", "", false
	}
	return proxy.token, proxy.actor, true
}

func (proxy *HiveProxy) validateHiveSend(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	object, err := readStrictHiveObject(writer, request, "to", "kind", "body", "corr_id")
	if err != nil {
		return nil, err
	}
	to, err := hiveStringField(object, "to", true)
	if err != nil {
		return nil, err
	}
	kind, err := hiveStringField(object, "kind", false)
	if err != nil {
		return nil, err
	}
	if kind == "" {
		kind = "msg"
	}
	body, err := hiveStringField(object, "body", false)
	if err != nil {
		return nil, err
	}
	if len(body) > 8<<10 {
		http.Error(writer, "Hive message body is too large", http.StatusRequestEntityTooLarge)
		return nil, errHiveResponseWritten
	}
	corrID, err := hiveStringField(object, "corr_id", false)
	if err != nil {
		return nil, err
	}

	if to == "@all" {
		if !proxy.broadcast {
			http.Error(writer, "Hive broadcast is not allowed", http.StatusForbidden)
			return nil, errHiveResponseWritten
		}
	} else {
		if !strings.Contains(to, "@") {
			to += "@" + proxy.localHost
		}
		if _, allowed := proxy.allowTo[to]; !allowed {
			http.Error(writer, "Hive recipient is not allowed", http.StatusForbidden)
			return nil, errHiveResponseWritten
		}
	}
	if _, allowed := proxy.allowKind[kind]; !allowed {
		http.Error(writer, "Hive message kind is not allowed", http.StatusForbidden)
		return nil, errHiveResponseWritten
	}

	return json.Marshal(struct {
		To     string `json:"to"`
		Kind   string `json:"kind"`
		Body   string `json:"body"`
		CorrID string `json:"corr_id,omitempty"`
	}{To: to, Kind: kind, Body: body, CorrID: corrID})
}

func validateHiveAck(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	object, err := readStrictHiveObject(writer, request, "seq")
	if err != nil {
		return nil, err
	}
	raw, exists := object["seq"]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, errors.New("missing seq")
	}
	var seq int64
	if err := json.Unmarshal(raw, &seq); err != nil || seq <= 0 {
		return nil, errors.New("seq must be a positive integer")
	}
	return json.Marshal(struct {
		Seq int64 `json:"seq"`
	}{Seq: seq})
}

var errHiveResponseWritten = errors.New("Hive response already written")

func readStrictHiveObject(writer http.ResponseWriter, request *http.Request, allowedFields ...string) (map[string]json.RawMessage, error) {
	if request.Body == nil || request.ContentLength > hiveMaximumRequestBytes {
		if request.ContentLength > hiveMaximumRequestBytes {
			http.Error(writer, "Hive request is too large", http.StatusRequestEntityTooLarge)
			return nil, errHiveResponseWritten
		}
		return nil, errors.New("missing JSON body")
	}
	contents, err := io.ReadAll(io.LimitReader(request.Body, hiveMaximumRequestBytes+1))
	if err != nil {
		return nil, errors.New("read JSON body")
	}
	if len(contents) > hiveMaximumRequestBytes {
		http.Error(writer, "Hive request is too large", http.StatusRequestEntityTooLarge)
		return nil, errHiveResponseWritten
	}
	allowed := make(map[string]struct{}, len(allowedFields))
	for _, field := range allowedFields {
		allowed[field] = struct{}{}
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("JSON body must be an object")
	}
	result := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid JSON object")
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON field")
		}
		if _, known := allowed[name]; !known {
			return nil, errors.New("unknown JSON field")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, errors.New("duplicate JSON field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid JSON value")
		}
		result[name] = append(json.RawMessage(nil), value...)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("trailing JSON value")
	}
	return result, nil
}

func hiveStringField(object map[string]json.RawMessage, name string, required bool) (string, error) {
	raw, exists := object[name]
	if !exists {
		if required {
			return "", errors.New("missing " + name)
		}
		return "", nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", errors.New(name + " must be a string")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || required && value == "" {
		return "", errors.New(name + " must be a string")
	}
	return value, nil
}

func validateHiveAgentsQuery(raw string) (string, error) {
	values, err := parseHiveQuery(raw)
	if err != nil {
		return "", err
	}
	if len(values) == 0 {
		return "", nil
	}
	local, exists := values["local"]
	if !exists || len(values) != 1 || len(local) != 1 || local[0] != "0" && local[0] != "1" {
		return "", errors.New("agents accepts only local=0 or local=1")
	}
	return url.Values{"local": []string{local[0]}}.Encode(), nil
}

func validateHiveInboxQuery(raw string) (string, error) {
	values, err := parseHiveQuery(raw)
	if err != nil {
		return "", err
	}
	canonical := make(url.Values, len(values))
	for key, entries := range values {
		if key == "agent" || len(entries) != 1 {
			return "", errors.New("another agent's inbox is not available")
		}
		value := entries[0]
		switch key {
		case "after":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 {
				return "", errors.New("invalid after cursor")
			}
			value = strconv.FormatInt(parsed, 10)
		case "max":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 1 || parsed > 500 {
				return "", errors.New("invalid inbox maximum")
			}
			value = strconv.Itoa(parsed)
		case "wait":
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 || parsed > 25 {
				return "", errors.New("invalid inbox wait")
			}
			value = strconv.Itoa(parsed)
		case "stat":
			if value != "1" {
				return "", errors.New("invalid inbox stat mode")
			}
		default:
			return "", errors.New("unsupported inbox query")
		}
		canonical[key] = []string{value}
	}
	return canonical.Encode(), nil
}

func parseHiveQuery(raw string) (url.Values, error) {
	if raw == "" {
		return make(url.Values), nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, errors.New("invalid Hive query")
	}
	for _, entries := range values {
		if len(entries) != 1 {
			return nil, errors.New("duplicate Hive query parameter")
		}
	}
	return values, nil
}

func emptyHiveRequestBody(request *http.Request) bool {
	return request.Body == nil || request.ContentLength == 0
}

func hiveRouteDenied(writer http.ResponseWriter, request *http.Request, policyAllows bool) {
	if !policyAllows {
		http.Error(writer, "Hive discovery is not allowed", http.StatusForbidden)
		return
	}
	http.NotFound(writer, request)
}

func validHiveProxyToken(value string) bool {
	if value == "" || len(value) > hiveMaximumTokenBytes {
		return false
	}
	for _, current := range value {
		if unicode.IsSpace(current) || unicode.IsControl(current) {
			return false
		}
	}
	return true
}

func validHiveActor(value string) bool {
	name, host, found := strings.Cut(value, "@")
	return found && !strings.Contains(host, "@") && len(name) <= 32 && len(host) <= 32 &&
		validIdentifier(name) && validIdentifier(host)
}

func stripHiveResponseHeaders(headers http.Header) {
	for name := range headers {
		if headersafety.CredentialBearing(name) || strings.EqualFold(name, "Proxy-Connection") {
			headers.Del(name)
		}
	}
}

func newHiveTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second, KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
	}
}
