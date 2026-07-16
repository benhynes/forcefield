package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/headersafety"
	"github.com/benhynes/forcefield/internal/tokens"
)

const brokerMaxHeaderBytes = 64 << 10
const brokerMaxConcurrentRequests = 32
const brokerMaxConnections = 64

// BrokerOptions contains authority retained by the trusted host-side runner.
// Bearer and TLS private-key material must never be copied into the sandbox.
type BrokerOptions struct {
	BaseURL         string
	Bearer          string
	AllowedServices []string
	CACertPath      string
	ClientCertPath  string
	ClientKeyPath   string
	Hive            *HiveProxyOptions

	// Transport is a test seam. Production callers should leave it nil so the
	// direct, proxy-free transport below is used.
	Transport http.RoundTripper
}

type brokerRoute struct {
	service string
	prefix  string
	host    string
	header  string
	auth    string
}

// NewBrokerFromManifest builds a runner broker from the authenticated live
// capability projection returned by a remote Forcefield gateway. This keeps
// the gateway configuration and administrative control socket off the runner
// host while retaining the bearer in the trusted supervisor.
func NewBrokerFromManifest(manifest capabilities.Manifest, options BrokerOptions) (*Broker, error) {
	if err := manifest.Validate(); err != nil {
		return nil, errors.New("runner broker requires a valid capability manifest")
	}
	base, err := validateBrokerOrigin(options.BaseURL)
	if err != nil {
		return nil, err
	}
	if len(options.Bearer) != tokens.BearerLength || !tokens.ContainsBearer(options.Bearer) {
		return nil, errors.New("runner broker requires a valid Forcefield bearer")
	}
	routes := make([]brokerRoute, 0, len(manifest.Services))
	maximum := int64(0)
	for _, service := range manifest.Services {
		if options.Hive != nil && service.PathPrefix != "" &&
			(service.PathPrefix == HiveBrokerPrefix || strings.HasPrefix(service.PathPrefix, HiveBrokerPrefix+"/") || strings.HasPrefix(HiveBrokerPrefix, service.PathPrefix+"/")) {
			return nil, fmt.Errorf("runner broker service %q overlaps the reserved Hive route", service.Name)
		}
		routes = append(routes, brokerRoute{
			service: service.Name, prefix: service.PathPrefix, host: strings.ToLower(service.Host),
			header: service.Auth.Header, auth: service.Auth.Prefix + options.Bearer,
		})
		if service.ConfiguredLimits.MaxRequestBytes > 1<<30 {
			return nil, fmt.Errorf("runner broker service %q has an unsafe request limit", service.Name)
		}
		if limit := int64(service.ConfiguredLimits.MaxRequestBytes); limit > maximum {
			maximum = limit
		}
	}
	if len(routes) == 0 {
		return nil, errors.New("runner broker requires at least one granted service")
	}
	if maximum == 0 {
		maximum = 16 << 20
	}
	slices.SortFunc(routes, func(left, right brokerRoute) int {
		if len(left.prefix) != len(right.prefix) {
			return len(right.prefix) - len(left.prefix)
		}
		return strings.Compare(left.service, right.service)
	})
	transport := options.Transport
	if transport == nil {
		transport, err = newBrokerTransport(options)
		if err != nil {
			return nil, err
		}
	}
	var hive *HiveProxy
	if options.Hive != nil {
		hive, err = NewHiveProxy(*options.Hive)
		if err != nil {
			if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
			return nil, err
		}
	}
	brokerContext, cancel := context.WithCancel(context.Background())
	return &Broker{
		base: base, bearer: options.Bearer, transport: transport, routes: routes,
		maximum: maximum, permits: make(chan struct{}, brokerMaxConcurrentRequests),
		context: brokerContext, cancel: cancel, hive: hive,
	}, nil
}

// Broker is a narrow HTTP relay from one sandbox-owned Unix socket to one
// statically configured Forcefield origin. It is not a general forward proxy.
// The socket is the sandbox capability; the actual bearer remains here.
type Broker struct {
	base        *url.URL
	bearer      string
	transport   http.RoundTripper
	routes      []brokerRoute
	maximum     int64
	permits     chan struct{}
	context     context.Context
	cancel      context.CancelFunc
	credentials sync.RWMutex
	cleared     bool
	hive        *HiveProxy
	server      *http.Server
	listener    net.Listener
}

func NewBroker(compiled *config.Compiled, options BrokerOptions) (*Broker, error) {
	if compiled == nil {
		return nil, errors.New("runner broker requires compiled Forcefield configuration")
	}
	base, err := validateBrokerOrigin(options.BaseURL)
	if err != nil {
		return nil, err
	}
	if len(options.Bearer) != tokens.BearerLength || !tokens.ContainsBearer(options.Bearer) {
		return nil, errors.New("runner broker requires a valid Forcefield bearer")
	}
	allowed := make(map[string]struct{}, len(options.AllowedServices))
	for _, service := range options.AllowedServices {
		if _, exists := compiled.File.Services[service]; !exists {
			return nil, fmt.Errorf("runner broker service %q is not configured", service)
		}
		allowed[service] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, errors.New("runner broker requires at least one granted service")
	}
	routes := make([]brokerRoute, 0, len(allowed))
	for service := range allowed {
		serviceConfig := compiled.File.Services[service]
		if options.Hive != nil && serviceConfig.PathPrefix != "" &&
			(serviceConfig.PathPrefix == HiveBrokerPrefix || strings.HasPrefix(serviceConfig.PathPrefix, HiveBrokerPrefix+"/") || strings.HasPrefix(HiveBrokerPrefix, serviceConfig.PathPrefix+"/")) {
			return nil, fmt.Errorf("runner broker service %q overlaps the reserved Hive route", service)
		}
		routes = append(routes, brokerRoute{
			service: service,
			prefix:  serviceConfig.PathPrefix,
			host:    strings.ToLower(serviceConfig.Host),
			header:  serviceConfig.ClientAuth.Header,
			auth:    serviceConfig.ClientAuth.Prefix + options.Bearer,
		})
	}
	slices.SortFunc(routes, func(left, right brokerRoute) int {
		if len(left.prefix) != len(right.prefix) {
			return len(right.prefix) - len(left.prefix)
		}
		return strings.Compare(left.service, right.service)
	})
	transport := options.Transport
	if transport == nil {
		transport, err = newBrokerTransport(options)
		if err != nil {
			return nil, err
		}
	}
	var hive *HiveProxy
	if options.Hive != nil {
		hive, err = NewHiveProxy(*options.Hive)
		if err != nil {
			if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
			return nil, err
		}
	}
	brokerContext, cancel := context.WithCancel(context.Background())
	return &Broker{
		base: base, bearer: options.Bearer, transport: transport, routes: routes,
		maximum: int64(compiled.File.Server.MaxRequestBytes), permits: make(chan struct{}, brokerMaxConcurrentRequests),
		context: brokerContext, cancel: cancel, hive: hive,
	}, nil
}

// ListenUnix binds a new private Unix socket. The parent directory must
// already be an owner-controlled 0700 directory. Call Serve after this method
// returns, so the sandbox cannot race broker readiness.
func (b *Broker) ListenUnix(socketPath string) error {
	if b == nil || b.transport == nil {
		return errors.New("runner broker is not initialized")
	}
	if err := validateBrokerSocketParent(socketPath); err != nil {
		return err
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("runner broker socket path already exists")
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on runner broker socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return errors.New("secure runner broker socket")
	}
	b.listener = newLimitedListener(listener, brokerMaxConnections)
	b.server = &http.Server{
		Handler: b, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: brokerMaxHeaderBytes,
	}
	return nil
}

type limitedListener struct {
	net.Listener
	permits chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newLimitedListener(listener net.Listener, maximum int) net.Listener {
	return &limitedListener{Listener: listener, permits: make(chan struct{}, maximum), closed: make(chan struct{})}
}

func (listener *limitedListener) Accept() (net.Conn, error) {
	select {
	case listener.permits <- struct{}{}:
	case <-listener.closed:
		return nil, net.ErrClosed
	}
	connection, err := listener.Listener.Accept()
	if err != nil {
		<-listener.permits
		return nil, err
	}
	return &limitedConnection{Conn: connection, release: func() { <-listener.permits }}, nil
}

func (listener *limitedListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return listener.Listener.Close()
}

type limitedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (connection *limitedConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func (b *Broker) Serve() error {
	if b == nil || b.server == nil || b.listener == nil {
		return errors.New("runner broker is not listening")
	}
	return b.server.Serve(b.listener)

}

// ServeUnix is the blocking convenience form of ListenUnix followed by Serve.
func (b *Broker) ServeUnix(socketPath string) error {
	if err := b.ListenUnix(socketPath); err != nil {
		return err
	}
	return b.Serve()
}

func (b *Broker) Close(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	var result error
	if b.server != nil {
		result = b.server.Shutdown(ctx)
	} else if b.listener != nil {
		result = b.listener.Close()
	}
	if closer, ok := b.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	if b.hive != nil {
		b.hive.Clear()
	}
	b.credentials.Lock()
	b.bearer = ""
	b.cleared = true
	for index := range b.routes {
		b.routes[index].auth = ""
	}
	b.credentials.Unlock()
	return result
}

func (b *Broker) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect || request.Method == http.MethodTrace || request.URL.IsAbs() || request.URL.Host != "" || request.URL.Scheme != "" ||
		request.URL.Path == "" || request.URL.Path[0] != '/' || request.Header.Get("Upgrade") != "" || len(request.Trailer) != 0 {
		http.NotFound(writer, request)
		return
	}
	select {
	case b.permits <- struct{}{}:
		defer func() { <-b.permits }()
	default:
		http.Error(writer, "Forcefield broker is busy", http.StatusTooManyRequests)
		return
	}
	requestContext, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(b.context, cancel)
	defer func() {
		stop()
		cancel()
	}()
	request = request.Clone(requestContext)
	if request.URL.Path == HiveBrokerPrefix || strings.HasPrefix(request.URL.Path, HiveBrokerPrefix+"/") {
		if b.hive == nil {
			http.NotFound(writer, request)
			return
		}
		b.hive.ServeHTTP(writer, request)
		return
	}
	route, ok := b.route(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	outbound := request.Clone(requestContext)
	if request.Body != nil {
		outbound.Body = http.MaxBytesReader(writer, request.Body, b.maximum)
	}
	outbound.RequestURI = ""
	outbound.URL.Scheme = b.base.Scheme
	outbound.URL.Host = b.base.Host
	outbound.URL.Path = joinBrokerPath(b.base.Path, request.URL.Path)
	outbound.URL.RawPath = ""
	outbound.Host = b.base.Host
	if route.host != "" {
		outbound.Host = route.host
	}
	outbound.Header = request.Header.Clone()
	stripBrokerHeaders(outbound.Header)
	outbound.Header.Set(route.header, route.auth)

	response, err := b.transport.RoundTrip(outbound)
	outbound.Header.Del(route.header)
	if err != nil {
		http.Error(writer, "Forcefield broker request failed", http.StatusBadGateway)
		return
	}
	if response == nil || response.Body == nil {
		http.Error(writer, "Forcefield broker returned an invalid response", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyBrokerResponseHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	copyBrokerResponseBody(writer, response)
}

func copyBrokerResponseBody(writer http.ResponseWriter, response *http.Response) {
	destination := io.Writer(writer)
	if strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		if flusher, ok := writer.(http.Flusher); ok {
			flusher.Flush()
			destination = flushingWriter{writer: writer, flusher: flusher}
		}
	}
	_, _ = io.Copy(destination, response.Body)
}

type flushingWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (writer flushingWriter) Write(contents []byte) (int, error) {
	written, err := writer.writer.Write(contents)
	if written > 0 {
		writer.flusher.Flush()
	}
	return written, err
}

func (b *Broker) route(request *http.Request) (brokerRoute, bool) {
	b.credentials.RLock()
	defer b.credentials.RUnlock()
	if b.cleared {
		return brokerRoute{}, false
	}
	if request.URL.Path == config.CapabilitiesPath {
		return brokerRoute{header: "Authorization", auth: "Bearer " + b.bearer}, true
	}
	host := strings.ToLower(request.Host)
	if parsed, _, err := net.SplitHostPort(request.Host); err == nil {
		host = strings.ToLower(parsed)
	}
	for _, route := range b.routes {
		if route.host != "" && route.host == host {
			return route, true
		}
		if route.prefix != "" && (request.URL.Path == route.prefix || strings.HasPrefix(request.URL.Path, route.prefix+"/")) {
			return route, true
		}
	}
	return brokerRoute{}, false
}

func validateBrokerOrigin(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("runner broker URL must be a Forcefield origin")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && brokerLoopbackHost(parsed.Hostname())) {
		return nil, errors.New("runner broker requires HTTPS or a loopback HTTP origin")
	}
	parsed.Path = ""
	return parsed, nil
}

func brokerLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func validateBrokerSocketParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("runner broker socket path must be absolute and clean")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("runner broker socket parent must be a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("runner broker socket parent must be owned by the runner")
	}
	return nil
}

func newBrokerTransport(options BrokerOptions) (http.RoundTripper, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.CACertPath != "" {
		contents, err := readRunnerFile(options.CACertPath, 1<<20, false)
		if err != nil {
			return nil, errors.New("read runner broker CA certificate")
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(contents) {
			return nil, errors.New("parse runner broker CA certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if (options.ClientCertPath == "") != (options.ClientKeyPath == "") {
		return nil, errors.New("runner broker client certificate and key must be configured together")
	}
	if options.ClientCertPath != "" {
		certificatePEM, err := readRunnerFile(options.ClientCertPath, 1<<20, false)
		if err != nil {
			return nil, errors.New("read runner broker client certificate")
		}
		keyPEM, err := readRunnerFile(options.ClientKeyPath, 1<<20, true)
		if err != nil {
			return nil, errors.New("read runner broker client key")
		}
		defer clear(keyPEM)
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, errors.New("load runner broker client identity")
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
	}, nil
}

func readRunnerFile(path string, maximum int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("runner credential path must be absolute")
	}
	if err := validateTrustedPath(path, true); err != nil {
		return nil, errors.New("unsafe runner credential ancestry")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum || private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("unsafe runner credential file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("runner credential file must be owned by the runner")
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("runner credential file changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		clear(contents)
		return nil, errors.New("read runner credential file")
	}
	return contents, nil
}

func stripBrokerHeaders(headers http.Header) {
	var nominated []string
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				nominated = append(nominated, name)
			}
		}
	}
	for name := range headers {
		if headersafety.CredentialBearing(name) || hopByHopHeader(name) || strings.EqualFold(name, "Forwarded") || strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
			headers.Del(name)
		}
	}
	for _, name := range nominated {
		headers.Del(name)
	}
}

func copyBrokerResponseHeaders(destination, source http.Header) {
	var nominated []string
	for _, value := range source.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				nominated = append(nominated, name)
			}
		}
	}
	for name, values := range source {
		if hopByHopHeader(name) || strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		if slices.ContainsFunc(nominated, func(value string) bool { return strings.EqualFold(value, name) }) {
			continue
		}
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

func hopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func joinBrokerPath(base, request string) string {
	if base == "" || base == "/" {
		return request
	}
	return strings.TrimSuffix(base, "/") + request
}
