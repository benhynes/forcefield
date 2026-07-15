package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/gitadapter"
	"github.com/benhynes/forcefield/internal/policy"
	"github.com/benhynes/forcefield/internal/secrets"
	"github.com/benhynes/forcefield/internal/tokens"
)

type TokenValidator interface {
	Validate(context.Context, string, tokens.ValidationRequest) (tokens.Claims, error)
}

type Auditor interface {
	Record(audit.Record) error
}

type WorkloadResolver func(*http.Request) (string, error)

type Options struct {
	ResolveWorkload WorkloadResolver
	ErrorLog        *log.Logger
	// Transports is a test/integration seam. Production callers should leave it
	// empty so every service receives a hardened resolve-once transport.
	Transports map[string]http.RoundTripper
}

type Gateway struct {
	config           *config.Compiled
	tokens           TokenValidator
	secrets          secrets.Backend
	audit            Auditor
	services         map[string]*runtimeService
	credentials      map[string]*runtimeCredential
	capabilities     *HeaderAdapter
	pathRoutes       []pathRoute
	hostRoutes       map[string]*runtimeService
	limits           *limitManager
	discoveryLimits  *limitManager
	discoveryDenials *limitManager
	workload         WorkloadResolver
	errorLog         *log.Logger
	transports       map[string]http.RoundTripper
	requestSeed      string
	requestSeq       atomic.Uint64
}

type runtimeService struct {
	name              string
	adapter           string
	gitRepositoryCase gitadapter.RepositoryCaseMode
	pathPrefix        string
	host              string
	upstream          *url.URL
	extractor         *HeaderAdapter
	transport         http.RoundTripper
	guard             ResponseGuard
}

type runtimeCredential struct {
	name            string
	service         string
	ref             string
	bindingRevision string
	adapter         *HeaderAdapter
}

type pathRoute struct {
	prefix  string
	service *runtimeService
}

func New(compiled *config.Compiled, validator TokenValidator, backend secrets.Backend, auditor Auditor, opts Options) (*Gateway, error) {
	if compiled == nil || validator == nil || backend == nil || auditor == nil {
		return nil, errors.New("gateway dependencies are required")
	}
	if opts.ResolveWorkload == nil {
		opts.ResolveWorkload = DefaultWorkload
	}
	if opts.ErrorLog == nil {
		opts.ErrorLog = log.New(io.Discard, "", 0)
	}
	g := &Gateway{
		config: compiled, tokens: validator, secrets: backend, audit: auditor,
		services: make(map[string]*runtimeService), credentials: make(map[string]*runtimeCredential),
		hostRoutes: make(map[string]*runtimeService), limits: newLimitManager(),
		discoveryLimits: newLimitManager(), discoveryDenials: newLimitManager(),
		workload: opts.ResolveWorkload, errorLog: opts.ErrorLog,
		transports: opts.Transports,
	}
	capabilityAdapter, err := NewHeaderAdapter(HeaderAdapterConfig{
		ClientHeader: "Authorization", ClientPrefix: "Bearer ",
		UpstreamHeader: "Authorization", UpstreamPrefix: "Bearer ",
	})
	if err != nil {
		return nil, fmt.Errorf("capability adapter: %w", err)
	}
	g.capabilities = capabilityAdapter
	var requestSeed [8]byte
	if _, err := rand.Read(requestSeed[:]); err != nil {
		return nil, errors.New("initialize request correlation IDs")
	}
	g.requestSeed = hex.EncodeToString(requestSeed[:])
	if err := g.compileRuntime(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Gateway) compileRuntime() error {
	for name, serviceConfig := range g.config.File.Services {
		extractor, err := NewHeaderAdapter(HeaderAdapterConfig{
			ClientHeader: serviceConfig.ClientAuth.Header, ClientPrefix: serviceConfig.ClientAuth.Prefix,
			UpstreamHeader: serviceConfig.ClientAuth.Header, UpstreamPrefix: serviceConfig.ClientAuth.Prefix,
		})
		if err != nil {
			return fmt.Errorf("service %s client adapter: %w", name, err)
		}
		transport := g.transports[name]
		if transport == nil {
			transport, err = NewHardenedTransport(TransportOptions{
				AllowedCIDRs: g.config.AllowedPrefixes[name], PinnedSPKISHA256: serviceConfig.PinnedSPKISHA256,
			})
			if err != nil {
				return fmt.Errorf("service %s transport: %w", name, err)
			}
		}
		requireIdentity := true
		if serviceConfig.Response.RequireIdentity != nil {
			requireIdentity = *serviceConfig.Response.RequireIdentity
		}
		service := &runtimeService{
			name: name, adapter: serviceConfig.Adapter, pathPrefix: serviceConfig.PathPrefix, host: strings.ToLower(serviceConfig.Host),
			upstream: g.config.Upstreams[name], extractor: extractor, transport: transport,
			guard: ResponseGuard{
				Upstream: g.config.Upstreams[name], PublicPathPrefix: serviceConfig.PathPrefix,
				StripHeaders: serviceConfig.Response.StripHeaders, RequireIdentity: requireIdentity,
			},
		}
		if serviceConfig.Git != nil {
			service.gitRepositoryCase = serviceConfig.Git.RepositoryCase
		}
		g.services[name] = service
		if service.pathPrefix != "" {
			g.pathRoutes = append(g.pathRoutes, pathRoute{prefix: service.pathPrefix, service: service})
		}
		if service.host != "" {
			g.hostRoutes[service.host] = service
		}
	}
	slices.SortFunc(g.pathRoutes, func(a, b pathRoute) int { return len(b.prefix) - len(a.prefix) })

	for name, credentialConfig := range g.config.File.Credentials {
		serviceConfig := g.config.File.Services[credentialConfig.Service]
		adapter, err := NewHeaderAdapter(HeaderAdapterConfig{
			ClientHeader: serviceConfig.ClientAuth.Header, ClientPrefix: serviceConfig.ClientAuth.Prefix,
			UpstreamHeader: credentialConfig.Inject.Header, UpstreamPrefix: credentialConfig.Inject.Prefix,
			UpstreamBasicUsername: credentialConfig.BasicUsername,
			ForwardHeaders:        serviceConfig.ForwardHeaders, StaticHeaders: serviceConfig.StaticHeaders,
		})
		if err != nil {
			return fmt.Errorf("credential %s adapter: %w", name, err)
		}
		g.credentials[name] = &runtimeCredential{
			name: name, service: credentialConfig.Service, ref: credentialConfig.SecretRef,
			bindingRevision: g.config.BindingRevisions[name], adapter: adapter,
		}
	}
	return nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	metadata := auditMetadata{RequestID: g.nextRequestID()}
	if r != nil {
		metadata.Method = r.Method
	}
	if r == nil || r.URL == nil || len(r.Method) > 32 || r.Method != strings.ToUpper(r.Method) || strings.EqualFold(r.Method, http.MethodConnect) || strings.EqualFold(r.Method, http.MethodTrace) || requestHasUpgrade(r) || len(r.Trailer) != 0 {
		g.deny(w)
		return
	}
	if !normalizeRequestRepresentation(r.Header) {
		g.deny(w)
		return
	}
	canonical, err := CanonicalizeURL(r.URL)
	if err != nil {
		g.deny(w)
		return
	}
	pathDigest := sha256.Sum256([]byte(canonical.Path))
	metadata.PathHash = hex.EncodeToString(pathDigest[:])
	if canonical.Path == config.CapabilitiesPath {
		g.serveCapabilities(w, r, canonical, started, metadata)
		return
	}
	service, relativePath := g.route(r.Host, canonical.Path)
	if service == nil {
		g.deny(w)
		return
	}
	if service.adapter == config.AdapterGitSmartHTTP {
		g.serveGit(w, r, canonical, service, relativePath, started, metadata)
		return
	}

	token, err := service.extractor.ExtractToken(r)
	if err != nil {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	workload, err := g.workload(r)
	if err != nil {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	claims, err := g.tokens.Validate(r.Context(), token, tokens.ValidationRequest{Workload: workload, Audience: g.config.File.Server.Audience})
	if err != nil {
		g.recordDeny(started, metadata, service.name, workload, "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	requestContext, cancel := context.WithDeadline(r.Context(), claims.ExpiresAt)
	defer cancel()
	r = r.WithContext(requestContext)
	metadata.TokenID = claims.TokenID
	metadata.RootTokenID = claims.RootTokenID
	grant, ok := oneGrantForService(claims.Grants, service.name)
	if !ok {
		g.recordDeny(started, metadata, service.name, workload, "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	grantID := config.GrantID(grant)
	credential := g.credentials[grant.CredentialRef]
	compiledPolicy, policyOK := g.config.ResolveGrant(grant)
	if credential == nil || credential.service != service.name || credential.bindingRevision == "" ||
		grant.BindingRevision != credential.bindingRevision || !policyOK || service.adapter != config.AdapterHTTP ||
		compiledPolicy.Adapter != config.AdapterHTTP || compiledPolicy.Policy == nil {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	limitScopes, ok := claimLimitScopes(claims, grant)
	if !ok {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	if !g.limits.allowRequest(limitScopes) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusTooManyRequests, 0)
		g.writeGeneric(w, http.StatusTooManyRequests)
		return
	}

	relativeURL := &url.URL{Path: relativePath, RawQuery: canonical.RawQuery}
	requestBytes, err := prepareRequestBody(r, compiledPolicy.Policy, grant.Limits, g.config.File.Server.MaxRequestBytes)
	if err != nil || len(r.Trailer) != 0 || !g.limits.allowBytes(limitScopes, uint64(requestBytes)) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, requestBytes)
		g.deny(w)
		return
	}
	decision := compiledPolicy.Policy.Evaluate(r.Context(), policy.Request{
		Method: r.Method, EscapedPath: relativeURL.EscapedPath(), RawQuery: relativeURL.RawQuery,
		ContentType: r.Header.Get("Content-Type"), Body: bodyBytes(r, compiledPolicy.Policy.NeedsBody()),
	})
	if !decision.Allowed() {
		g.recordDecision(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, decision, http.StatusNotFound, requestBytes, 0)
		g.deny(w)
		return
	}
	if err := applyPolicyTarget(relativeURL, decision); err != nil {
		g.recordDecision(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, decision, http.StatusNotFound, requestBytes, 0)
		g.deny(w)
		return
	}

	// Fail-closed auditing happens before the secret is fetched or any upstream
	// authority is exercised.
	if err := g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: compiledPolicy.Revision, RuleID: strings.Join(decision.MatchedRuleIDs, ","),
		Reason:     string(decision.Reason),
		WorkloadID: workload, GrantID: grantID, Service: service.name, Decision: audit.DecisionAllow,
		Status: 0, Latency: time.Since(started), BytesIn: requestBytes,
	}); err != nil {
		g.writeGeneric(w, http.StatusServiceUnavailable)
		return
	}
	if !g.tokenStillValid(r.Context(), token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, requestBytes)
		g.deny(w)
		return
	}

	lease, err := g.secrets.Get(r.Context(), credential.ref)
	if err != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, requestBytes)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	defer lease.Release()
	secret, err := lease.Clone()
	if err != nil || len(secret) == 0 {
		zeroBytes(secret)
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, requestBytes)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	defer zeroBytes(secret)
	if !g.tokenStillValid(r.Context(), token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, requestBytes)
		g.deny(w)
		return
	}

	status, bytesOut, err := g.forward(w, r, service, credential, relativeURL, secret)
	responseCommitted := status != 0
	if err != nil {
		g.errorLog.Printf("service=%s request failed", service.name)
		if status == 0 {
			status = http.StatusBadGateway
			g.writeGeneric(w, status)
		}
	}
	decisionType := audit.DecisionAllow
	if err != nil {
		decisionType = audit.DecisionError
	}
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: compiledPolicy.Revision, RuleID: strings.Join(decision.MatchedRuleIDs, ","),
		Reason:     string(decision.Reason),
		WorkloadID: workload, GrantID: grantID, Service: service.name, Decision: decisionType,
		Status: status, Latency: time.Since(started), BytesIn: requestBytes, BytesOut: bytesOut,
	})
	if err != nil && responseCommitted {
		panic(http.ErrAbortHandler)
	}
}

func (g *Gateway) forward(w http.ResponseWriter, in *http.Request, service *runtimeService, credential *runtimeCredential, relative *url.URL, secret []byte) (int, int64, error) {
	target := *service.upstream
	base := strings.TrimSuffix(target.Path, "/")
	target.Path = base + relative.Path
	escapedBase := strings.TrimSuffix(service.upstream.EscapedPath(), "/")
	target.RawPath = escapedBase + relative.EscapedPath()
	target.RawQuery = relative.RawQuery
	target.Fragment = ""

	out := in.Clone(in.Context())
	out.URL = &target
	out.RequestURI = ""
	out.Host = target.Host
	out.Close = false
	out.Trailer = nil
	out.TransferEncoding = nil
	if err := credential.adapter.RewriteHeaders(in.Header, out.Header, secret); err != nil {
		return 0, 0, err
	}
	leakPatterns, err := credential.adapter.LeakPatterns(secret)
	if err != nil {
		return 0, 0, err
	}
	defer zeroCredentialPatterns(leakPatterns)
	out.Header.Set("Accept-Encoding", "identity")
	response, err := service.transport.RoundTrip(out)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 599 {
		return 0, 0, errors.New("upstream returned an invalid final status")
	}
	if err := service.guard.GuardPatterns(response, leakPatterns); err != nil {
		return 0, 0, responseGuardError(err)
	}
	prefixBuffer := make([]byte, 32<<10)
	prefixBytes, readErr := response.Body.Read(prefixBuffer)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return 0, 0, readErr
	}
	prefix := prefixBuffer[:prefixBytes]
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("Expires")
	w.Header().Del("Pragma")
	w.WriteHeader(response.StatusCode)
	writtenPrefix := 0
	if len(prefix) != 0 {
		var prefixErr error
		writtenPrefix, prefixErr = w.Write(prefix)
		if prefixErr != nil {
			return response.StatusCode, int64(writtenPrefix), prefixErr
		}
	}
	destination := io.Writer(w)
	if isEventStream(response.Header.Get("Content-Type")) {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
			destination = flushingWriter{writer: w, flusher: flusher}
		}
	}
	n, copyErr := io.Copy(destination, response.Body)
	return response.StatusCode, int64(writtenPrefix) + n, copyErr
}

type flushingWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w flushingWriter) Write(value []byte) (int, error) {
	n, err := w.writer.Write(value)
	if n > 0 {
		w.flusher.Flush()
	}
	return n, err
}

func isEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "text/event-stream"
}

func (g *Gateway) route(rawHost, path string) (*runtimeService, string) {
	host := strings.ToLower(rawHost)
	if parsedHost, _, err := net.SplitHostPort(rawHost); err == nil {
		host = strings.ToLower(parsedHost)
	}
	if service := g.hostRoutes[host]; service != nil {
		return service, path
	}
	for _, route := range g.pathRoutes {
		if path == route.prefix {
			return route.service, "/"
		}
		if strings.HasPrefix(path, route.prefix+"/") {
			return route.service, strings.TrimPrefix(path, route.prefix)
		}
	}
	return nil, ""
}

func prepareRequestBody(r *http.Request, compiledPolicy *policy.Policy, limits tokens.Limits, globalMax uint64) (int64, error) {
	if globalMax == 0 || globalMax > 1<<30 {
		return 0, errors.New("invalid global request body limit")
	}
	capBytes := int64(globalMax)
	if compiledPolicy.NeedsBody() && compiledPolicy.MaxBodyBytes() < capBytes {
		capBytes = compiledPolicy.MaxBodyBytes()
	}
	if limits.MaxRequestBytes != 0 && limits.MaxRequestBytes < uint64(capBytes) {
		capBytes = int64(limits.MaxRequestBytes)
	}
	if r.ContentLength > capBytes {
		return 0, errors.New("request body exceeds grant limit")
	}
	if r.Body == nil {
		return 0, nil
	}
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return 0, errors.New("encoded request bodies are unsupported")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, capBytes+1))
	closeErr := r.Body.Close()
	if err != nil || closeErr != nil || int64(len(data)) > capBytes {
		zeroBytes(data)
		return 0, errors.New("request body could not be bounded")
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	return int64(len(data)), nil
}

func bodyBytes(r *http.Request, needed bool) []byte {
	if !needed || r.GetBody == nil {
		return nil
	}
	body, err := r.GetBody()
	if err != nil {
		return nil
	}
	defer body.Close()
	data, _ := io.ReadAll(body)
	return data
}

func applyPolicyTarget(target *url.URL, decision policy.Decision) error {
	decoded, err := url.PathUnescape(decision.CanonicalPath)
	if err != nil || decoded == "" {
		return errors.New("invalid canonical policy target")
	}
	target.Path = decoded
	target.RawPath = decision.CanonicalPath
	target.RawQuery = decision.CanonicalQuery
	return nil
}

func oneGrantForService(grants []tokens.Grant, service string) (tokens.Grant, bool) {
	var found tokens.Grant
	count := 0
	for _, grant := range grants {
		if grant.Service == service {
			found = grant
			count++
		}
	}
	return found, count == 1
}

func (g *Gateway) tokenStillValid(ctx context.Context, bearer, workload string, previous tokens.Claims, grant tokens.Grant) bool {
	fresh, err := g.tokens.Validate(ctx, bearer, tokens.ValidationRequest{Workload: workload, Audience: g.config.File.Server.Audience})
	if err != nil || fresh.TokenID != previous.TokenID || fresh.RootTokenID != previous.RootTokenID || !fresh.ExpiresAt.Equal(previous.ExpiresAt) {
		return false
	}
	freshGrant, ok := oneGrantForService(fresh.Grants, grant.Service)
	if !ok || freshGrant != grant {
		return false
	}
	_, ok = claimLimitScopes(fresh, freshGrant)
	return ok
}

func claimLimitScopes(claims tokens.Claims, current tokens.Grant) ([]limitScope, bool) {
	if len(claims.LimitChain) != claims.Depth+1 || len(claims.LimitChain) == 0 ||
		claims.LimitChain[0].TokenID != claims.RootTokenID ||
		claims.LimitChain[len(claims.LimitChain)-1].TokenID != claims.TokenID {
		return nil, false
	}
	scopes := make([]limitScope, 0, len(claims.LimitChain))
	var previous tokens.Grant
	for index, chain := range claims.LimitChain {
		grant, ok := oneGrantForService(chain.Grants, current.Service)
		if !ok || grant.Service != current.Service || grant.CredentialRef != current.CredentialRef ||
			grant.PolicyRevision != current.PolicyRevision || grant.BindingRevision != current.BindingRevision {
			return nil, false
		}
		if index > 0 && (!grantLimitsNoBroader(grant.Limits, previous.Limits) || chain.ExpiresAt.After(claims.LimitChain[index-1].ExpiresAt)) {
			return nil, false
		}
		previous = grant
		scopes = append(scopes, limitScope{
			key:    chain.TokenID + "\x00" + current.Service + "\x00" + current.CredentialRef + "\x00" + current.PolicyRevision + "\x00" + current.BindingRevision,
			limits: grant.Limits, expiresAt: chain.ExpiresAt,
		})
	}
	last := claims.LimitChain[len(claims.LimitChain)-1]
	lastGrant, _ := oneGrantForService(last.Grants, current.Service)
	if lastGrant != current || !last.ExpiresAt.Equal(claims.ExpiresAt) {
		return nil, false
	}
	return scopes, true
}

func grantLimitsNoBroader(child, parent tokens.Limits) bool {
	return limitNoBroader(child.RequestsPerSecond, parent.RequestsPerSecond) &&
		burstNoBroader(child, parent) &&
		limitNoBroader(child.RequestBudget, parent.RequestBudget) &&
		limitNoBroader(child.ByteBudget, parent.ByteBudget) &&
		limitNoBroader(child.MaxRequestBytes, parent.MaxRequestBytes)
}

func burstNoBroader(child, parent tokens.Limits) bool {
	if parent.RequestsPerSecond == 0 {
		return true
	}
	parentBurst := parent.Burst
	if parentBurst == 0 {
		parentBurst = 1
	}
	childBurst := child.Burst
	if childBurst == 0 {
		childBurst = 1
	}
	return childBurst <= parentBurst
}

func limitNoBroader(child, parent uint64) bool {
	return parent == 0 || child != 0 && child <= parent
}

func DefaultWorkload(r *http.Request) (string, error) {
	if r == nil {
		return "", errors.New("missing request")
	}
	if r.TLS != nil && len(r.TLS.VerifiedChains) != 0 && len(r.TLS.VerifiedChains[0]) != 0 {
		leaf := r.TLS.VerifiedChains[0][0]
		digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		return "mtls-spki:" + hex.EncodeToString(digest[:]), nil
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("invalid remote address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("invalid remote address")
	}
	return "ip:" + ip.String(), nil
}

func requestHasUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func normalizeRequestRepresentation(header http.Header) bool {
	contentType, ok := singletonHeader(header, "Content-Type")
	if !ok {
		return false
	}
	if contentType != "" {
		if _, _, err := mime.ParseMediaType(contentType); err != nil {
			return false
		}
	}
	encoding, ok := singletonHeader(header, "Content-Encoding")
	if !ok {
		return false
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	// Generic HTTP policies still reject encoded bodies in prepareRequestBody.
	// Git smart HTTP additionally accepts the two encodings emitted by Git's
	// remote-curl client and decodes them before policy or upstream forwarding.
	return encoding == "" || encoding == "identity" || encoding == "gzip" || encoding == "x-gzip"
}

func singletonHeader(header http.Header, name string) (string, bool) {
	var values []string
	for key, current := range header {
		if strings.EqualFold(key, name) {
			values = append(values, current...)
		}
	}
	if len(values) > 1 || len(values) == 1 && containsHeaderControl(values[0]) {
		return "", false
	}
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
	if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", true
	}
	value := strings.TrimSpace(values[0])
	header.Set(name, value)
	return value, true
}

func copyResponseHeaders(destination, source http.Header) {
	dynamicHop := make(map[string]struct{})
	for name, values := range source {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range values {
			for _, token := range strings.Split(value, ",") {
				if canonical := http.CanonicalHeaderKey(strings.TrimSpace(token)); validHeaderName(canonical) {
					dynamicHop[canonical] = struct{}{}
				}
			}
		}
	}
	for name, values := range source {
		if _, blocked := dynamicHop[http.CanonicalHeaderKey(name)]; blocked || isHopByHopHeader(name) || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Trailer") {
			continue
		}
		for _, value := range values {
			destination.Add(name, value)
		}
	}
}

func (g *Gateway) deny(w http.ResponseWriter) { g.writeGeneric(w, http.StatusNotFound) }

func (g *Gateway) writeGeneric(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len("{\"error\":\"request denied\"}\n")))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "{\"error\":\"request denied\"}\n")
}

type auditMetadata struct {
	RequestID, TokenID, RootTokenID string
	Method, PathHash                string
}

func (g *Gateway) nextRequestID() string {
	return g.requestSeed + fmt.Sprintf("%016x", g.requestSeq.Add(1))
}

func (g *Gateway) recordDeny(started time.Time, metadata auditMetadata, service, workload, grant string, status int, bytesIn int64) {
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		Service: service, WorkloadID: workload, GrantID: grant, Decision: audit.DecisionDeny,
		Status: status, Latency: time.Since(started), BytesIn: bytesIn,
	})
}

func (g *Gateway) recordDecision(started time.Time, metadata auditMetadata, service, workload, grant, revision string, decision policy.Decision, status int, bytesIn, bytesOut int64) {
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: revision, RuleID: strings.Join(decision.MatchedRuleIDs, ","), WorkloadID: workload,
		Reason:  string(decision.Reason),
		GrantID: grant, Service: service, Decision: audit.DecisionDeny, Status: status,
		Latency: time.Since(started), BytesIn: bytesIn, BytesOut: bytesOut,
	})
}

func (g *Gateway) recordError(started time.Time, metadata auditMetadata, service, workload, grant, revision string, status int, bytesIn int64) {
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: revision, WorkloadID: workload, GrantID: grant, Service: service,
		Decision: audit.DecisionError, Status: status, Latency: time.Since(started), BytesIn: bytesIn,
	})
}
