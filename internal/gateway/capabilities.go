package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/benhynes/forcefield/internal/audit"
	"github.com/benhynes/forcefield/internal/capabilities"
	"github.com/benhynes/forcefield/internal/tokens"
)

const capabilityAuditService = "forcefield-capabilities"

const (
	capabilityRequestsPerSecond = 2
	capabilityBurst             = 16
)

func (g *Gateway) serveCapabilities(w http.ResponseWriter, r *http.Request, canonical CanonicalURL, started time.Time, metadata auditMetadata) {
	workload, err := g.workload(r)
	if err != nil {
		g.recordCapabilityDeny(started, metadata, "")
		g.deny(w)
		return
	}
	if r.Method != http.MethodGet || canonical.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		g.recordCapabilityDeny(started, metadata, workload)
		g.deny(w)
		return
	}
	bearer, err := g.capabilities.ExtractToken(r)
	if err != nil {
		g.recordCapabilityDeny(started, metadata, workload)
		g.deny(w)
		return
	}
	claims, err := g.tokens.Validate(r.Context(), bearer, tokens.ValidationRequest{
		Workload: workload, Audience: g.config.File.Server.Audience,
	})
	if err != nil {
		g.recordCapabilityDeny(started, metadata, workload)
		g.deny(w)
		return
	}
	metadata.TokenID = claims.TokenID
	metadata.RootTokenID = claims.RootTokenID
	rateWindow := started.UTC().Truncate(time.Hour)
	if !g.discoveryLimits.allowRequest([]limitScope{{
		key: "forcefield-capabilities-workload\x00" + workload + "\x00" + strconv.FormatInt(rateWindow.Unix(), 10),
		limits: tokens.Limits{
			RequestsPerSecond: capabilityRequestsPerSecond,
			Burst:             capabilityBurst,
		},
		expiresAt: rateWindow.Add(2 * time.Hour),
	}}) {
		// Throttled requests are deliberately not audited one-for-one, which
		// prevents an authenticated caller from amplifying audit storage.
		g.writeGeneric(w, http.StatusTooManyRequests)
		return
	}

	usable := make([]tokens.Grant, 0, len(claims.Grants))
	seen := make(map[string]struct{}, len(claims.Grants))
	for _, grant := range claims.Grants {
		if _, duplicate := seen[grant.Service]; duplicate {
			g.recordCapabilityDeny(started, metadata, workload)
			g.deny(w)
			return
		}
		seen[grant.Service] = struct{}{}
		if _, current := g.config.ResolveGrant(grant); !current {
			continue
		}
		if _, validChain := claimLimitScopes(claims, grant); !validChain {
			continue
		}
		usable = append(usable, grant)
	}
	generatedAt := time.Now().UTC()
	if !generatedAt.Before(claims.ExpiresAt) {
		g.recordCapabilityDeny(started, metadata, workload)
		g.deny(w)
		return
	}
	manifest, err := capabilities.Build(g.config, generatedAt, claims.ExpiresAt, usable)
	if err != nil {
		g.recordError(started, metadata, capabilityAuditService, workload, "", "", http.StatusInternalServerError, 0)
		g.writeGeneric(w, http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded)+1 > capabilities.MaxManifestSize {
		g.recordError(started, metadata, capabilityAuditService, workload, "", "", http.StatusInternalServerError, 0)
		g.writeGeneric(w, http.StatusInternalServerError)
		return
	}
	encoded = append(encoded, '\n')
	// Record authorization before exposing the manifest so fail-closed audit
	// mode cannot silently authorize a response the sink did not accept.
	if err := g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash, RuleID: "capabilities", Reason: "authorized",
		WorkloadID: workload, Service: capabilityAuditService, Decision: audit.DecisionAllow,
		Status: 0, Latency: time.Since(started),
	}); err != nil {
		g.writeGeneric(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(http.StatusOK)
	written, writeErr := w.Write(encoded)
	auditedBytes := written
	if written < 0 {
		auditedBytes = 0
	} else if written > len(encoded) {
		auditedBytes = len(encoded)
	}
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	decision := audit.DecisionAllow
	reason := "authorized"
	if writeErr != nil {
		decision = audit.DecisionError
		reason = "response_write"
	}
	_ = g.audit.Record(audit.Record{
		RequestID: metadata.RequestID, TokenID: metadata.TokenID, RootTokenID: metadata.RootTokenID,
		Method: metadata.Method, PathHash: metadata.PathHash, RuleID: "capabilities", Reason: reason,
		WorkloadID: workload, Service: capabilityAuditService, Decision: decision,
		Status: http.StatusOK, Latency: time.Since(started), BytesOut: int64(auditedBytes),
	})
	if writeErr != nil {
		panic(http.ErrAbortHandler)
	}
}

// recordCapabilityDeny globally samples unauthenticated and malformed
// discovery denials. Authentication is attempted before the independent
// per-workload success limiter, so an invalid caller cannot starve a valid
// token or allocate unbounded limiter state; sampling only bounds audit growth
// and does not change the deliberately generic 404.
func (g *Gateway) recordCapabilityDeny(started time.Time, metadata auditMetadata, workload string) {
	rateWindow := started.UTC().Truncate(time.Hour)
	if !g.discoveryDenials.allowRequest([]limitScope{{
		key: "forcefield-capabilities-deny-audit\x00" + strconv.FormatInt(rateWindow.Unix(), 10),
		limits: tokens.Limits{
			RequestsPerSecond: capabilityRequestsPerSecond,
			Burst:             capabilityBurst,
		},
		expiresAt: rateWindow.Add(2 * time.Hour),
	}}) {
		return
	}
	g.recordDeny(started, metadata, capabilityAuditService, workload, "", http.StatusNotFound, 0)
}
