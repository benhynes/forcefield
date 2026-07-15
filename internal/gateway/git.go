package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/config"
	"github.com/benhynes/forcefield/internal/gitadapter"
	"github.com/benhynes/forcefield/internal/tokens"
)

const gitClientUsername = "forcefield"

type preparedGitRoute struct {
	gitadapter.Route
	ProtocolVersion int
	ProtocolHeader  string
	ResponseType    string
}

func (g *Gateway) serveGit(w http.ResponseWriter, r *http.Request, canonical CanonicalURL, service *runtimeService, relativePath string, started time.Time, metadata auditMetadata) {
	preparedRoute, err := classifyGitRequest(r, relativePath, canonical.RawQuery)
	if err != nil {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	preparedRoute.Repository, err = gitadapter.NormalizeRepository(preparedRoute.Repository, service.gitRepositoryCase)
	if err != nil {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusNotFound, 0)
		g.deny(w)
		return
	}
	token, challenge, err := extractGitToken(service, r)
	if challenge {
		g.recordDeny(started, metadata, service.name, "", "", http.StatusUnauthorized, 0)
		writeGitChallenge(g, w)
		return
	}
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
		grant.BindingRevision != credential.bindingRevision || !policyOK || compiledPolicy.Adapter != config.AdapterGitSmartHTTP || compiledPolicy.GitPolicy == nil {
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

	maximum := g.config.File.Server.MaxRequestBytes
	if grant.Limits.MaxRequestBytes != 0 && grant.Limits.MaxRequestBytes < maximum {
		maximum = grant.Limits.MaxRequestBytes
	}
	decision, requestBody, err := g.authorizeGitRequest(r, preparedRoute, compiledPolicy.GitPolicy, maximum, limitScopes)
	if requestBody != nil {
		defer requestBody.Close()
	}
	bytesIn := int64(0)
	if requestBody != nil {
		bytesIn = requestBody.BytesRead()
	}
	if err != nil || !decision.Allowed {
		if decision.Reason == "" {
			decision.Reason = gitadapter.ReasonInvalidInput
		}
		g.recordGitDecision(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, decision, http.StatusNotFound, bytesIn, 0)
		g.deny(w)
		return
	}

	relativeURL := &url.URL{Path: relativePath, RawQuery: canonical.RawQuery}
	if err := g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: compiledPolicy.Revision, RuleID: strings.Join(decision.MatchedRuleIDs, ","),
		Reason: string(decision.Reason), WorkloadID: workload, GrantID: grantID,
		Service: service.name, Decision: audit.DecisionAllow, Status: 0,
		Latency: time.Since(started), BytesIn: bytesIn,
	}); err != nil {
		g.writeGeneric(w, http.StatusServiceUnavailable)
		return
	}
	if !g.tokenStillValid(r.Context(), token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, bytesIn)
		g.deny(w)
		return
	}

	lease, err := g.secrets.Get(r.Context(), credential.ref)
	if err != nil {
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, bytesIn)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	defer lease.Release()
	secret, err := lease.Clone()
	if err != nil || len(secret) == 0 {
		zeroBytes(secret)
		g.recordError(started, metadata, service.name, workload, grantID, compiledPolicy.Revision, http.StatusBadGateway, bytesIn)
		g.writeGeneric(w, http.StatusBadGateway)
		return
	}
	defer zeroBytes(secret)
	if !g.tokenStillValid(r.Context(), token, workload, claims, grant) {
		g.recordDeny(started, metadata, service.name, workload, grantID, http.StatusNotFound, bytesIn)
		g.deny(w)
		return
	}

	status, bytesOut, forwardErr := g.forwardGit(w, r, service, credential, relativeURL, secret, preparedRoute)
	bytesIn = 0
	if requestBody != nil {
		bytesIn = requestBody.BytesRead()
	}
	responseCommitted := status != 0
	if forwardErr != nil {
		g.errorLog.Printf("service=%s git request failed", service.name)
		if status == 0 {
			if errors.Is(forwardErr, errGitBodyLimit) || errors.Is(forwardErr, errGitByteBudget) || errors.Is(forwardErr, errGitBodyTrailer) || errors.Is(forwardErr, errGitGzip) {
				status = http.StatusNotFound
				g.deny(w)
			} else {
				status = http.StatusBadGateway
				g.writeGeneric(w, status)
			}
		}
	}
	decisionType := audit.DecisionAllow
	if forwardErr != nil {
		decisionType = audit.DecisionError
	}
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: compiledPolicy.Revision, RuleID: strings.Join(decision.MatchedRuleIDs, ","),
		Reason: string(decision.Reason), WorkloadID: workload, GrantID: grantID,
		Service: service.name, Decision: decisionType, Status: status,
		Latency: time.Since(started), BytesIn: bytesIn, BytesOut: bytesOut,
	})
	if forwardErr != nil && responseCommitted {
		panic(http.ErrAbortHandler)
	}
}

func classifyGitRequest(r *http.Request, relativePath, rawQuery string) (preparedGitRoute, error) {
	if r == nil || r.URL == nil || r.URL.ForceQuery {
		return preparedGitRoute{}, gitadapter.ErrInvalidRoute
	}
	route, err := gitadapter.ClassifyRoute(gitadapter.RouteRequest{
		Method: r.Method, Path: relativePath, RawQuery: rawQuery, ContentType: r.Header.Get("Content-Type"),
	})
	if err != nil {
		return preparedGitRoute{}, err
	}
	if route.Phase == gitadapter.RouteDiscovery {
		encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || encoding != "" && encoding != "identity" {
			return preparedGitRoute{}, gitadapter.ErrInvalidRoute
		}
	}
	protocol, ok := singletonHeader(r.Header, "Git-Protocol")
	if !ok || len(protocol) > 64 {
		return preparedGitRoute{}, gitadapter.ErrInvalidRoute
	}
	version := 0
	switch protocol {
	case "":
	case "version=1":
		version = 1
	case "version=2":
		version = 2
	default:
		return preparedGitRoute{}, gitadapter.ErrInvalidRoute
	}
	forwardProtocol := protocol
	if route.Service == gitadapter.ServiceReceivePack {
		if route.Phase == gitadapter.RouteRPC && version == 2 {
			return preparedGitRoute{}, gitadapter.ErrUnsupported
		}
		// Git currently has no protocol-v2 push. Clients commonly advertise v2
		// during discovery and fall back to v0 when the server does not answer in
		// v2, so strip that header instead of treating it as push semantics.
		if version == 2 {
			version = 0
			forwardProtocol = ""
		}
	}
	responseType, err := gitadapter.ExpectedResponseContentType(route)
	if err != nil {
		return preparedGitRoute{}, err
	}
	return preparedGitRoute{Route: route, ProtocolVersion: version, ProtocolHeader: forwardProtocol, ResponseType: responseType}, nil
}

func extractGitToken(service *runtimeService, r *http.Request) (token string, challenge bool, err error) {
	if service == nil || r == nil {
		return "", false, ErrInvalidBrokerCredential
	}
	authorization, ok := singletonHeader(r.Header, "Authorization")
	if !ok {
		return "", false, ErrInvalidBrokerCredential
	}
	if authorization == "" {
		return "", true, nil
	}
	if !strings.HasPrefix(authorization, "Basic ") {
		token, err = service.extractor.ExtractToken(r)
		return token, false, err
	}
	encoded := strings.TrimPrefix(authorization, "Basic ")
	decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
	if decodeErr != nil || len(decoded) > 1024 {
		zeroBytes(decoded)
		return "", false, ErrInvalidBrokerCredential
	}
	defer zeroBytes(decoded)
	username, password, found := strings.Cut(string(decoded), ":")
	if !found || username != gitClientUsername || !validBrokerBearer(password) {
		return "", false, ErrInvalidBrokerCredential
	}
	return password, false, nil
}

func validBrokerBearer(value string) bool {
	return strings.HasPrefix(value, tokens.BearerPrefix) && len(value) >= 16 && strings.TrimSpace(value) == value
}

func writeGitChallenge(g *Gateway, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="forcefield-git", charset="UTF-8"`)
	g.writeGeneric(w, http.StatusUnauthorized)
}

func (g *Gateway) authorizeGitRequest(r *http.Request, route preparedGitRoute, compiled *gitadapter.Policy, maximum uint64, scopes []limitScope) (gitadapter.Decision, *gitRequestBody, error) {
	operation := gitadapter.OperationFetch
	if route.Service == gitadapter.ServiceReceivePack {
		operation = gitadapter.OperationPush
	}
	if route.Phase == gitadapter.RouteDiscovery {
		decision := compiled.CanAccessRepository(gitadapter.RepositoryAccessRequest{
			Repository: route.Repository, Service: route.Service, Operation: operation, ProtocolVersion: route.ProtocolVersion,
		})
		return decision, nil, decision.Err
	}
	if route.Service == gitadapter.ServiceUploadPack {
		decision := compiled.Evaluate(gitadapter.PolicyRequest{
			Repository: route.Repository, Service: route.Service,
			Operation: gitadapter.OperationFetch, ProtocolVersion: route.ProtocolVersion,
		})
		if !decision.Allowed {
			return decision, nil, decision.Err
		}
		body, err := prepareGitRequestBody(r, maximum, func(count uint64) bool { return g.limits.allowBytes(scopes, count) })
		if err != nil {
			return decision, body, err
		}
		r.Body = body
		r.GetBody = nil
		return decision, body, nil
	}

	body, err := prepareGitRequestBody(r, maximum, func(count uint64) bool { return g.limits.allowBytes(scopes, count) })
	if err != nil {
		return gitadapter.Decision{}, body, err
	}
	parsed, err := gitadapter.ParseReceivePackPrefix(body, gitadapter.ParseOptions{AllowPushCertificates: false})
	if err != nil {
		return gitadapter.Decision{}, body, err
	}
	r.Body = &replayedGitBody{Reader: parsed.Body(), source: body}
	r.GetBody = nil
	if parsed.Request.Kind == gitadapter.ReceivePackPush {
		decision := compiled.Evaluate(gitadapter.PolicyRequest{
			Repository: route.Repository, Service: route.Service, Operation: gitadapter.OperationPush,
			ProtocolVersion: route.ProtocolVersion, ReceivePack: &parsed.Request,
		})
		return decision, body, decision.Err
	}
	decision := compiled.CanAccessRepository(gitadapter.RepositoryAccessRequest{
		Repository: route.Repository, Service: route.Service, Operation: gitadapter.OperationPush,
		ProtocolVersion: route.ProtocolVersion,
	})
	return decision, body, decision.Err
}

func (g *Gateway) forwardGit(w http.ResponseWriter, in *http.Request, service *runtimeService, credential *runtimeCredential, relative *url.URL, secret []byte, route preparedGitRoute) (int, int64, error) {
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
	out.GetBody = nil
	if err := credential.adapter.RewriteHeaders(in.Header, out.Header, secret); err != nil {
		return 0, 0, err
	}
	// These fields are derived from the classified request and may never retain
	// an operator-forwarded or client-selected value.
	out.Header.Del("Git-Protocol")
	out.Header.Del("Content-Type")
	out.Header.Del("Content-Encoding")
	leakPatterns, err := credential.adapter.LeakPatterns(secret)
	if err != nil {
		return 0, 0, err
	}
	defer zeroCredentialPatterns(leakPatterns)
	if route.Phase == gitadapter.RouteRPC {
		out.Header.Set("Content-Type", route.ContentType)
	}
	if route.ProtocolHeader != "" {
		out.Header.Set("Git-Protocol", route.ProtocolHeader)
	}
	out.Header.Set("Accept-Encoding", "identity")
	response, err := service.transport.RoundTrip(out)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 599 {
		return 0, 0, errors.New("upstream returned an invalid final status")
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		values := headerValues(response.Header, "Content-Type")
		if response.StatusCode != http.StatusOK || len(values) != 1 || strings.TrimSpace(values[0]) != route.ResponseType {
			return 0, 0, errors.New("upstream returned an invalid Git response type")
		}
	}
	if err := service.guard.GuardPatterns(response, leakPatterns); err != nil {
		return 0, 0, responseGuardError(err)
	}
	response.Header.Del("WWW-Authenticate")
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
	n, copyErr := io.Copy(w, response.Body)
	return response.StatusCode, int64(writtenPrefix) + n, copyErr
}

func (g *Gateway) recordGitDecision(started time.Time, metadata auditMetadata, service, workload, grant, revision string, decision gitadapter.Decision, status int, bytesIn, bytesOut int64) {
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash,
		PolicyRevision: revision, RuleID: strings.Join(decision.MatchedRuleIDs, ","),
		WorkloadID: workload, Reason: string(decision.Reason), GrantID: grant,
		Service: service, Decision: audit.DecisionDeny, Status: status,
		Latency: time.Since(started), BytesIn: bytesIn, BytesOut: bytesOut,
	})
}
