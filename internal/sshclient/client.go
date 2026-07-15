// Package sshclient opens the authenticated HTTPS stream used by Forcefield's
// terminating SSH adapter and runs a native SSH client connection inside it.
package sshclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/tokens"
	"golang.org/x/crypto/ssh"
)

var ErrConnection = errors.New("Forcefield SSH connection was not confirmed")

type Options struct {
	Endpoint         string
	Bearer           string
	Transport        http.RoundTripper
	HandshakeTimeout time.Duration
	UserAgent        string
}

func Dial(ctx context.Context, options Options) (*ssh.Client, error) {
	if ctx == nil || options.Transport == nil || !validEndpoint(options.Endpoint) ||
		!validBearer(options.Bearer) {
		return nil, ErrConnection
	}
	timeout := options.HandshakeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout < time.Second || timeout > 30*time.Second {
		return nil, ErrConnection
	}
	requestContext, cancelRequest := context.WithCancel(ctx)
	requestReader, requestWriter := io.Pipe()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, options.Endpoint, requestReader)
	if err != nil {
		cancelRequest()
		_ = requestWriter.Close()
		return nil, ErrConnection
	}
	request.ContentLength = -1
	request.Header.Set("Authorization", "Bearer "+options.Bearer)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set(config.SSHStreamProtocolHeader, config.SSHStreamProtocol)
	if options.UserAgent != "" {
		request.Header.Set("User-Agent", options.UserAgent)
	}
	client := &http.Client{
		Transport: options.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Forcefield SSH redirects are not allowed")
		},
	}
	type roundTripResult struct {
		response *http.Response
		err      error
	}
	roundTrip := make(chan roundTripResult)
	abandoned := make(chan struct{})
	go func() {
		response, err := client.Do(request)
		select {
		case roundTrip <- roundTripResult{response: response, err: err}:
		case <-abandoned:
			if response != nil {
				_ = response.Body.Close()
			}
		}
	}()
	openTimer := time.NewTimer(timeout)
	defer openTimer.Stop()
	var response *http.Response
	select {
	case <-ctx.Done():
		close(abandoned)
		cancelRequest()
		_ = requestReader.CloseWithError(ErrConnection)
		_ = requestWriter.CloseWithError(ErrConnection)
		return nil, ErrConnection
	case <-openTimer.C:
		close(abandoned)
		cancelRequest()
		_ = requestReader.CloseWithError(ErrConnection)
		_ = requestWriter.CloseWithError(ErrConnection)
		return nil, ErrConnection
	case result := <-roundTrip:
		openTimer.Stop()
		response, err = result.response, result.err
	}
	if err != nil {
		cancelRequest()
		_ = requestWriter.CloseWithError(ErrConnection)
		return nil, ErrConnection
	}
	if response.StatusCode != http.StatusOK || response.ContentLength >= 0 ||
		len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/octet-stream" ||
		len(response.Header.Values("Content-Encoding")) != 0 || !hasNoStore(response.Header.Values("Cache-Control")) ||
		len(response.Header.Values(config.SSHStreamProtocolHeader)) != 1 || response.Header.Get(config.SSHStreamProtocolHeader) != config.SSHStreamProtocol ||
		len(response.Header.Values(config.SSHStreamHostKeyHeader)) != 1 || !validFingerprint(response.Header.Get(config.SSHStreamHostKeyHeader)) {
		_ = response.Body.Close()
		cancelRequest()
		_ = requestWriter.CloseWithError(ErrConnection)
		return nil, ErrConnection
	}
	pin := response.Header.Get(config.SSHStreamHostKeyHeader)
	stream := &httpConn{reader: response.Body, writer: requestWriter, cancel: cancelRequest, local: stringAddr("forcefield-client"), remote: stringAddr(options.Endpoint)}
	algorithms := ssh.SupportedAlgorithms()
	sshConfig := &ssh.ClientConfig{
		Config: ssh.Config{Ciphers: algorithms.Ciphers, MACs: algorithms.MACs, KeyExchanges: algorithms.KeyExchanges},
		User:   "forcefield",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != pin {
				return ErrConnection
			}
			return nil
		},
		HostKeyAlgorithms: algorithms.HostKeys,
		ClientVersion:     "SSH-2.0-Forcefield-client",
	}
	handshake := make(chan struct {
		connection ssh.Conn
		channels   <-chan ssh.NewChannel
		requests   <-chan *ssh.Request
		err        error
	}, 1)
	go func() {
		connection, channels, requests, err := ssh.NewClientConn(stream, "forcefield", sshConfig)
		handshake <- struct {
			connection ssh.Conn
			channels   <-chan ssh.NewChannel
			requests   <-chan *ssh.Request
			err        error
		}{connection, channels, requests, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		_ = stream.Close()
		return nil, ErrConnection
	case <-timer.C:
		_ = stream.Close()
		return nil, ErrConnection
	case result := <-handshake:
		if result.err != nil {
			_ = stream.Close()
			return nil, ErrConnection
		}
		return ssh.NewClient(result.connection, result.channels, result.requests), nil
	}
}

func validEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || address != nil && address.IsLoopback()
}

func validBearer(value string) bool {
	if len(value) != tokens.BearerLength || !strings.HasPrefix(value, tokens.BearerPrefix) || strings.TrimSpace(value) != value {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, tokens.BearerPrefix))
	valid := err == nil && len(raw) == sha256.Size
	clear(raw)
	return valid
}

func validFingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "SHA256:")
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	valid := err == nil && len(raw) == sha256.Size && base64.RawStdEncoding.EncodeToString(raw) == encoded
	clear(raw)
	return valid
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

type httpConn struct {
	reader    io.ReadCloser
	writer    *io.PipeWriter
	cancel    context.CancelFunc
	local     net.Addr
	remote    net.Addr
	closeOnce sync.Once
}

func (c *httpConn) Read(value []byte) (int, error)  { return c.reader.Read(value) }
func (c *httpConn) Write(value []byte) (int, error) { return c.writer.Write(value) }
func (c *httpConn) Close() error {
	var result error
	c.closeOnce.Do(func() {
		c.cancel()
		result = errors.Join(c.writer.Close(), c.reader.Close())
	})
	return result
}
func (c *httpConn) LocalAddr() net.Addr              { return c.local }
func (c *httpConn) RemoteAddr() net.Addr             { return c.remote }
func (c *httpConn) SetDeadline(time.Time) error      { return nil }
func (c *httpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpConn) SetWriteDeadline(time.Time) error { return nil }

type stringAddr string

func (a stringAddr) Network() string { return "forcefield" }
func (a stringAddr) String() string  { return string(a) }
