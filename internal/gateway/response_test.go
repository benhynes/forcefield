package gateway

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSecretFilteringBodyBlocksAcrossReadBoundaries(t *testing.T) {
	t.Parallel()
	secret := []byte("super-secret-value")
	body := newSecretFilteringBody(io.NopCloser(strings.NewReader("safe-prefix-super-secret-value-safe-suffix")), secret)
	defer body.Close()
	buffer := make([]byte, 3)
	var returned strings.Builder
	for {
		n, err := body.Read(buffer)
		returned.Write(buffer[:n])
		if err != nil {
			if !errors.Is(err, ErrSecretReflection) {
				t.Fatalf("unexpected error: %v", err)
			}
			break
		}
	}
	if strings.Contains(returned.String(), string(secret)) {
		t.Fatalf("secret leaked in %q", returned.String())
	}
}

func TestSecretFilteringBodyStreamsSafeContent(t *testing.T) {
	t.Parallel()
	body := newSecretFilteringBody(io.NopCloser(strings.NewReader("ordinary streaming response")), []byte("secret"))
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ordinary streaming response" {
		t.Fatalf("got %q", got)
	}
}

func TestResponseGuardRewritesSameOriginAndRejectsCrossOrigin(t *testing.T) {
	t.Parallel()
	upstream, _ := url.Parse("https://api.example.com/v1")
	guard := ResponseGuard{Upstream: upstream, PublicPathPrefix: "/example", RequireIdentity: true}
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/items", nil)
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}
	resp.Header.Set("Location", "https://api.example.com/v1/next?a=1")
	resp.Header.Set("Set-Cookie", "session=upstream")
	if err := guard.Guard(resp, []byte("real-secret")); err != nil {
		t.Fatal(err)
	}
	if got := resp.Header.Get("Location"); got != "/example/next?a=1" {
		t.Fatalf("Location=%q", got)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Fatal("Set-Cookie was not stripped")
	}

	resp = &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}
	resp.Header.Set("Location", "https://attacker.invalid/steal")
	if err := guard.Guard(resp, []byte("real-secret")); !errors.Is(err, ErrUnsafeRedirect) {
		t.Fatalf("got %v", err)
	}
}

func TestResponseGuardBlocksHeaderReflection(t *testing.T) {
	t.Parallel()
	upstream, _ := url.Parse("https://api.example.com")
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}
	resp.Header.Set("X-Debug", "credential=real-secret")
	err := (ResponseGuard{Upstream: upstream}).Guard(resp, []byte("real-secret"))
	if !errors.Is(err, ErrSecretReflection) {
		t.Fatalf("got %v", err)
	}
}

func TestResponseGuardBlocksSecretHeaderNameAndAmbiguousEncoding(t *testing.T) {
	t.Parallel()
	upstream, _ := url.Parse("https://api.example.com")
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}
	resp.Header["Real-Secret"] = []string{"value"}
	if err := (ResponseGuard{Upstream: upstream}).Guard(resp, []byte("real-secret")); !errors.Is(err, ErrSecretReflection) {
		t.Fatalf("secret header name error = %v", err)
	}

	resp = &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("compressed"))}
	resp.Header["Content-Encoding"] = []string{"identity", "gzip"}
	if err := (ResponseGuard{Upstream: upstream, RequireIdentity: true}).Guard(resp, []byte("real-secret")); !errors.Is(err, ErrEncodedResponse) {
		t.Fatalf("ambiguous encoding error = %v", err)
	}
}

func TestCopyResponseHeadersRemovesDynamicHopHeaders(t *testing.T) {
	t.Parallel()
	source := make(http.Header)
	source.Set("Connection", "X-Internal-Hop")
	source.Set("X-Internal-Hop", "must-not-cross")
	source.Set("Content-Type", "application/json")
	destination := make(http.Header)
	copyResponseHeaders(destination, source)
	if destination.Get("Connection") != "" || destination.Get("X-Internal-Hop") != "" {
		t.Fatalf("dynamic hop headers crossed boundary: %#v", destination)
	}
	if destination.Get("Content-Type") != "application/json" {
		t.Fatal("safe response header was dropped")
	}
}
