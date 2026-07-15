package sshclient

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestDialRejectsEndpointBeforeSendingBearer(t *testing.T) {
	t.Parallel()
	called := false
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("unexpected request")
	})
	for _, endpoint := range []string{
		"http://forcefield.example/ssh/infra",
		"https://user@forcefield.example/ssh/infra",
		"https://forcefield.example/ssh/infra?target=other",
		"https://forcefield.example/ssh/infra#fragment",
	} {
		client, err := Dial(context.Background(), Options{
			Endpoint: endpoint, Bearer: testBearer(), Transport: transport,
			HandshakeTimeout: time.Second,
		})
		if client != nil || !errors.Is(err, ErrConnection) {
			t.Fatalf("endpoint %q => client=%v error=%v", endpoint, client, err)
		}
	}
	if called {
		t.Fatal("invalid endpoint reached the HTTP transport")
	}
}

func TestDialDenialIsGenericAndCancelsStreamingBody(t *testing.T) {
	t.Parallel()
	requestCanceled := make(chan struct{})
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.ContentLength != -1 ||
			request.Header.Get("Authorization") != "Bearer "+testBearer() ||
			request.Header.Get("Content-Type") != "application/octet-stream" ||
			request.Header.Get(config.SSHStreamProtocolHeader) != config.SSHStreamProtocol {
			t.Errorf("unexpected SSH stream request: method=%q length=%d headers=%v", request.Method, request.ContentLength, request.Header)
		}
		go func() {
			<-request.Context().Done()
			close(requestCanceled)
		}()
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("not found\n")),
			Request:    request,
		}, nil
	})
	client, err := Dial(context.Background(), Options{
		Endpoint: "https://forcefield.example/ssh/infra", Bearer: testBearer(), Transport: transport,
		HandshakeTimeout: time.Second,
	})
	if client != nil || !errors.Is(err, ErrConnection) || err.Error() != ErrConnection.Error() {
		t.Fatalf("denial => client=%v error=%v", client, err)
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("denied HTTP stream context was not canceled")
	}
}

func TestDialContextCancellationReleasesBlockedRoundTrip(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	released := make(chan struct{})
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(entered)
		<-request.Context().Done()
		close(released)
		return nil, request.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		client, err := Dial(ctx, Options{
			Endpoint: "https://forcefield.example/ssh/infra", Bearer: testBearer(), Transport: transport,
			HandshakeTimeout: time.Second,
		})
		if client != nil {
			_ = client.Close()
		}
		result <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrConnection) {
			t.Fatalf("canceled dial error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled dial did not return")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("blocked RoundTrip did not observe cancellation")
	}
}

func testBearer() string {
	return tokens.BearerPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}
