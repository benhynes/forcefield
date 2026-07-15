package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
)

type matchState uint8

const (
	stateNoMatch matchState = iota
	stateMatch
	stateError
)

// Evaluate evaluates a request without mutating it. If Body is supplied it is
// always subject to MaxBodyBytes, even when this policy does not need a body.
func (p *Policy) Evaluate(ctx context.Context, request Request) Decision {
	if p == nil {
		return Decision{Effect: EffectDeny, Reason: ReasonEvaluationError, Err: errors.New("policy is nil")}
	}
	if int64(len(request.Body)) > p.opts.BodyLimit {
		return Decision{Effect: EffectDeny, Reason: ReasonBodyTooLarge, Err: ErrBodyTooLarge}
	}
	canonical, err := canonicalizeRequest(request)
	if err != nil {
		return Decision{Effect: EffectDeny, Reason: ReasonInvalidRequest, Err: err}
	}
	base := Decision{
		Effect:         EffectDeny,
		CanonicalPath:  canonical.path,
		CanonicalQuery: canonical.canonicalQuery,
	}

	var matchedAllows []string
	var matchedDenies []string
	var evalErrors []error
	for i := range p.rules {
		rule := &p.rules[i]
		state, err := rule.matches(ctx, canonical)
		switch state {
		case stateMatch:
			if rule.effect == EffectDeny {
				matchedDenies = append(matchedDenies, rule.id)
			} else {
				matchedAllows = append(matchedAllows, rule.id)
			}
		case stateError:
			if err == nil {
				err = errors.New("unspecified matcher error")
			}
			evalErrors = append(evalErrors, fmt.Errorf("rule %q: %w", rule.id, err))
		}
	}
	matched := append(append(make([]string, 0, len(matchedAllows)+len(matchedDenies)), matchedAllows...), matchedDenies...)
	sort.Strings(matched)
	base.MatchedRuleIDs = matched
	// An indeterminate condition is never converted into an allow, even if a
	// different rule matched. This is the policy engine's fail-closed boundary.
	if len(evalErrors) != 0 {
		base.Reason = ReasonEvaluationError
		base.Err = errors.Join(evalErrors...)
		return base
	}
	if len(matchedDenies) != 0 {
		base.Reason = ReasonExplicitDeny
		return base
	}
	if len(matchedAllows) != 0 {
		base.Effect = EffectAllow
		base.Reason = ReasonAllowed
		return base
	}
	base.Reason = ReasonNoMatch
	return base
}

func (r *compiledRule) matches(ctx context.Context, request *canonicalRequest) (matchState, error) {
	if r.methods != nil {
		if _, ok := r.methods[request.method]; !ok {
			return stateNoMatch, nil
		}
	}
	if len(r.paths) != 0 {
		matched := false
		for _, path := range r.paths {
			if path.matches(request.pathSegments) {
				matched = true
				break
			}
		}
		if !matched {
			return stateNoMatch, nil
		}
	}
	for _, matcher := range r.query {
		if !matcher.matches(request.query) {
			return stateNoMatch, nil
		}
	}
	if len(r.json) != 0 {
		document, err := request.parseJSON()
		if err != nil {
			return stateError, fmt.Errorf("parse JSON body: %w", err)
		}
		for _, matcher := range r.json {
			if !matcher.matches(document) {
				return stateNoMatch, nil
			}
		}
	}
	if r.graphql != nil {
		graphql, err := request.parseGraphQL()
		if err != nil {
			return stateError, err
		}
		if !r.graphql.matches(graphql) {
			return stateNoMatch, nil
		}
	}
	if r.cel != nil {
		matched, err := r.cel.matches(ctx, request)
		if err != nil {
			return stateError, err
		}
		if !matched {
			return stateNoMatch, nil
		}
	}
	return stateMatch, nil
}

// EvaluateHTTP reads and restores r.Body only when NeedsBody is true, then
// evaluates it. When canonicalization succeeds it rewrites the request URL and
// RequestURI to the exact canonical path/query which was authorized. A reverse
// proxy can therefore forward the same representation the policy inspected.
func (p *Policy) EvaluateHTTP(ctx context.Context, r *http.Request) Decision {
	if p == nil {
		return Decision{Effect: EffectDeny, Reason: ReasonEvaluationError, Err: errors.New("policy is nil")}
	}
	if r == nil || r.URL == nil {
		return Decision{Effect: EffectDeny, Reason: ReasonInvalidRequest, Err: fmt.Errorf("%w: nil HTTP request or URL", ErrInvalidRequest)}
	}
	if r.URL.RawPath != "" && r.URL.EscapedPath() != r.URL.RawPath {
		return Decision{Effect: EffectDeny, Reason: ReasonInvalidRequest, Err: fmt.Errorf("%w: inconsistent URL Path and RawPath", ErrInvalidRequest)}
	}

	var body []byte
	if p.needsBody {
		if r.ContentLength > p.opts.BodyLimit {
			return Decision{Effect: EffectDeny, Reason: ReasonBodyTooLarge, Err: ErrBodyTooLarge}
		}
		if r.Body != nil {
			original := r.Body
			limited := io.LimitReader(original, p.opts.BodyLimit+1)
			var err error
			body, err = io.ReadAll(limited)
			closeErr := original.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			if err != nil {
				return Decision{Effect: EffectDeny, Reason: ReasonEvaluationError, Err: fmt.Errorf("read request body: %w", err)}
			}
			if closeErr != nil {
				return Decision{Effect: EffectDeny, Reason: ReasonEvaluationError, Err: fmt.Errorf("close request body: %w", closeErr)}
			}
			if int64(len(body)) > p.opts.BodyLimit {
				return Decision{Effect: EffectDeny, Reason: ReasonBodyTooLarge, Err: ErrBodyTooLarge}
			}
		}
	}

	decision := p.Evaluate(ctx, Request{
		Method:      r.Method,
		EscapedPath: r.URL.EscapedPath(),
		RawQuery:    r.URL.RawQuery,
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
	})
	if decision.CanonicalPath != "" {
		decoded, err := url.PathUnescape(decision.CanonicalPath)
		if err != nil {
			// CanonicalPath was produced by this package; reaching this branch is
			// an internal error and must still fail closed.
			decision.Effect = EffectDeny
			decision.Reason = ReasonEvaluationError
			decision.Err = fmt.Errorf("decode canonical path: %w", err)
			return decision
		}
		r.URL.Path = decoded
		r.URL.RawPath = decision.CanonicalPath
		r.URL.RawQuery = decision.CanonicalQuery
		r.RequestURI = decision.CanonicalPath
		if decision.CanonicalQuery != "" {
			r.RequestURI += "?" + decision.CanonicalQuery
		}
	}
	return decision
}
