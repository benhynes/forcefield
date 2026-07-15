package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/tokens"
)

func TestNormalizeRequestRepresentationRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	for name, header := range map[string]http.Header{
		"duplicate content type":  {"Content-Type": {"application/json", "text/plain"}},
		"case split content type": {"Content-Type": {"application/json"}, "content-type": {"text/plain"}},
		"invalid content type":    {"Content-Type": {"application/json, text/plain"}},
		"encoded body":            {"Content-Encoding": {"gzip"}},
		"duplicate encoding":      {"Content-Encoding": {"identity", "gzip"}},
	} {
		t.Run(name, func(t *testing.T) {
			if normalizeRequestRepresentation(header) {
				t.Fatal("ambiguous representation headers were accepted")
			}
		})
	}
	header := http.Header{"content-type": {" application/json; charset=utf-8 "}, "Content-Encoding": {"identity"}}
	if !normalizeRequestRepresentation(header) || header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("valid representation was not normalized: %#v", header)
	}
}

func TestPrepareRequestBodyEnforcesGlobalAndChunkedLimits(t *testing.T) {
	t.Parallel()
	compiled, err := policy.Compile(policy.Spec{Rules: []policy.RuleSpec{{ID: "allow", Effect: policy.EffectAllow}}}, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]*http.Request{
		"known":   httptest.NewRequest(http.MethodPost, "http://forcefield.test/", strings.NewReader("12345")),
		"chunked": {Method: http.MethodPost, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("12345")), ContentLength: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := prepareRequestBody(request, compiled, tokens.Limits{}, 4); err == nil {
				t.Fatal("body above global limit was accepted")
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "http://forcefield.test/", strings.NewReader("1234"))
	if count, err := prepareRequestBody(request, compiled, tokens.Limits{}, 4); err != nil || count != 4 {
		t.Fatalf("bounded body = (%d, %v)", count, err)
	}
}

type trailerPopulatingBody struct {
	reader  *strings.Reader
	trailer http.Header
}

func (b *trailerPopulatingBody) Read(value []byte) (int, error) {
	n, err := b.reader.Read(value)
	if err == io.EOF {
		b.trailer.Set("X-Undeclared", "bypass")
	}
	return n, err
}
func (*trailerPopulatingBody) Close() error { return nil }

func TestPrepareRequestBodyExposesLateTrailersForRejection(t *testing.T) {
	t.Parallel()
	compiled, err := policy.Compile(policy.Spec{Rules: []policy.RuleSpec{{ID: "allow", Effect: policy.EffectAllow}}}, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: http.MethodPost, Header: make(http.Header), Trailer: make(http.Header), ContentLength: -1}
	request.Body = &trailerPopulatingBody{reader: strings.NewReader("body"), trailer: request.Trailer}
	if _, err := prepareRequestBody(request, compiled, tokens.Limits{}, 1024); err != nil {
		t.Fatal(err)
	}
	if len(request.Trailer) == 0 {
		t.Fatal("late trailer was not surfaced after EOF")
	}
}

func TestForwardPreservesAuthorizedEscapedPath(t *testing.T) {
	t.Parallel()
	upstream := &url.URL{Scheme: "https", Host: "api.example.com", Path: "/v1", RawPath: "/v1"}
	var escapedPath string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		escapedPath = request.URL.EscapedPath()
		return &http.Response{
			StatusCode: http.StatusNoContent, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader("")), Request: request,
		}, nil
	})
	adapter, err := NewHeaderAdapter(HeaderAdapterConfig{ClientHeader: "X-Forcefield-Token", UpstreamHeader: "Authorization", UpstreamPrefix: "Bearer "})
	if err != nil {
		t.Fatal(err)
	}
	service := &runtimeService{upstream: upstream, transport: transport, guard: ResponseGuard{Upstream: upstream, RequireIdentity: true}}
	credential := &runtimeCredential{adapter: adapter}
	incoming := httptest.NewRequest(http.MethodGet, "http://forcefield.test/service", nil)
	recorder := httptest.NewRecorder()
	status, _, err := (&Gateway{}).forward(recorder, incoming, service, credential, &url.URL{Path: "/name,part", RawPath: "/name%2Cpart"}, []byte("secret"))
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("forward = (%d, %v)", status, err)
	}
	if escapedPath != "/v1/name%2Cpart" {
		t.Fatalf("upstream escaped path = %q", escapedPath)
	}
}

func TestForwardRejectsNonFinalUpstreamStatus(t *testing.T) {
	t.Parallel()
	upstream := &url.URL{Scheme: "https", Host: "api.example.com"}
	adapter, err := NewHeaderAdapter(HeaderAdapterConfig{ClientHeader: "X-Forcefield-Token", UpstreamHeader: "Authorization"})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{0, 99, 100, 199, 600, 999} {
		status := status
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
			})
			service := &runtimeService{upstream: upstream, transport: transport, guard: ResponseGuard{Upstream: upstream, RequireIdentity: true}}
			incoming := httptest.NewRequest(http.MethodGet, "http://forcefield.test/service", nil)
			if committed, _, err := (&Gateway{}).forward(httptest.NewRecorder(), incoming, service, &runtimeCredential{adapter: adapter}, &url.URL{Path: "/"}, []byte("secret")); err == nil || committed != 0 {
				t.Fatalf("forward status %d = (%d, %v)", status, committed, err)
			}
		})
	}
}

func TestSecretFilterReleasesNonMatchingStreamPrefixPromptly(t *testing.T) {
	t.Parallel()
	body := newSecretFilteringBody(io.NopCloser(bytes.NewReader([]byte("data: hello\n\n"))), []byte("very-long-upstream-secret"))
	defer body.Close()
	buffer := make([]byte, 64)
	n, err := body.Read(buffer)
	if err != nil || string(buffer[:n]) != "data: hello\n\n" {
		t.Fatalf("first stream read = (%q, %v)", buffer[:n], err)
	}
}
