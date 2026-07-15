package gitadapter

import (
	"fmt"
	"sort"
)

type Operation string

const (
	OperationDiscover Operation = "discover"
	OperationFetch    Operation = "fetch"
	OperationPush     Operation = "push"
	OperationProbe    Operation = "probe"
	OperationNoop     Operation = "noop"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// StringMatcher matches either one exact value or all values with Prefix.
// Exactly one field must be set. Prefix comparison is byte-for-byte and does
// not perform path, Unicode, or case normalization.
type StringMatcher struct {
	Exact  string `json:"exact,omitempty" yaml:"exact,omitempty"`
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
}

func (m StringMatcher) matches(value string) bool {
	if m.Exact != "" {
		return value == m.Exact
	}
	return len(value) >= len(m.Prefix) && value[:len(m.Prefix)] == m.Prefix
}

func (m StringMatcher) valid() bool { return (m.Exact == "") != (m.Prefix == "") }

// Rule fields are conjunctions; each slice is an OR set. Ref and UpdateKinds
// scope a rule to individual updates. A rule without either applies to the
// entire request and, for a push, to every update.
type Rule struct {
	ID               string          `json:"id" yaml:"id"`
	Effect           Effect          `json:"effect" yaml:"effect"`
	Repositories     []StringMatcher `json:"repositories,omitempty" yaml:"repositories,omitempty"`
	Services         []Service       `json:"services,omitempty" yaml:"services,omitempty"`
	Operations       []Operation     `json:"operations,omitempty" yaml:"operations,omitempty"`
	ProtocolVersions []int           `json:"protocol_versions,omitempty" yaml:"protocol_versions,omitempty"`
	ObjectFormats    []ObjectFormat  `json:"object_formats,omitempty" yaml:"object_formats,omitempty"`
	Refs             []StringMatcher `json:"refs,omitempty" yaml:"refs,omitempty"`
	UpdateKinds      []UpdateKind    `json:"update_kinds,omitempty" yaml:"update_kinds,omitempty"`
	Signed           *bool           `json:"signed,omitempty" yaml:"signed,omitempty"`
	Atomic           *bool           `json:"atomic,omitempty" yaml:"atomic,omitempty"`
	HasPushOptions   *bool           `json:"has_push_options,omitempty" yaml:"has_push_options,omitempty"`
}

type PolicyRequest struct {
	Repository      string
	Service         Service
	Operation       Operation
	ProtocolVersion int
	ReceivePack     *ReceivePackRequest
}

// RepositoryAccessRequest asks whether a repository has any usable fetch or
// push authority before request-specific facts (such as destination refs) are
// available. Operation must be OperationFetch or OperationPush.
type RepositoryAccessRequest struct {
	Repository      string
	Service         Service
	Operation       Operation
	ProtocolVersion int
}

type DecisionReason string

const (
	ReasonAllowed      DecisionReason = "allowed"
	ReasonExplicitDeny DecisionReason = "explicit_deny"
	ReasonNoMatch      DecisionReason = "no_match"
	ReasonInvalidInput DecisionReason = "invalid_input"
)

type Decision struct {
	Allowed        bool
	Reason         DecisionReason
	MatchedRuleIDs []string
	DeniedUpdate   int
	Err            error
}

type Policy struct{ rules []Rule }

const (
	maxPolicyRules        = 256
	maxPolicyMatchers     = 1024
	maxPolicyMatcherBytes = 64 << 10
)

func NewPolicy(rules []Rule) (*Policy, error) {
	if len(rules) > maxPolicyRules {
		return nil, fmt.Errorf("%w: policy cannot contain more than %d rules", ErrInvalidPolicy, maxPolicyRules)
	}
	seenIDs := make(map[string]struct{}, len(rules))
	compiled := make([]Rule, len(rules))
	matcherCount := 0
	matcherBytes := 0
	for i, rule := range rules {
		if rule.ID == "" || (rule.Effect != EffectAllow && rule.Effect != EffectDeny) {
			return nil, fmt.Errorf("%w: rule %d has invalid id or effect", ErrInvalidPolicy, i)
		}
		if _, duplicate := seenIDs[rule.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate rule id", ErrInvalidPolicy)
		}
		seenIDs[rule.ID] = struct{}{}
		matchers := append(append([]StringMatcher(nil), rule.Repositories...), rule.Refs...)
		if len(matchers) > maxPolicyMatchers-matcherCount {
			return nil, fmt.Errorf("%w: matcher complexity exceeds its bound", ErrInvalidPolicy)
		}
		matcherCount += len(matchers)
		for _, matcher := range matchers {
			if !matcher.valid() {
				return nil, fmt.Errorf("%w: rule %q has invalid string matcher", ErrInvalidPolicy, rule.ID)
			}
			size := len(matcher.Exact) + len(matcher.Prefix)
			if size > maxPolicyMatcherBytes-matcherBytes {
				return nil, fmt.Errorf("%w: matcher complexity exceeds its bound", ErrInvalidPolicy)
			}
			matcherBytes += size
		}
		if !validRuleEnums(rule) {
			return nil, fmt.Errorf("%w: rule %q has invalid selector", ErrInvalidPolicy, rule.ID)
		}
		compiled[i] = cloneRule(rule)
	}
	return &Policy{rules: compiled}, nil
}

func cloneRule(rule Rule) Rule {
	rule.Repositories = append([]StringMatcher(nil), rule.Repositories...)
	rule.Services = append([]Service(nil), rule.Services...)
	rule.Operations = append([]Operation(nil), rule.Operations...)
	rule.ProtocolVersions = append([]int(nil), rule.ProtocolVersions...)
	rule.ObjectFormats = append([]ObjectFormat(nil), rule.ObjectFormats...)
	rule.Refs = append([]StringMatcher(nil), rule.Refs...)
	rule.UpdateKinds = append([]UpdateKind(nil), rule.UpdateKinds...)
	if rule.Signed != nil {
		value := *rule.Signed
		rule.Signed = &value
	}
	if rule.Atomic != nil {
		value := *rule.Atomic
		rule.Atomic = &value
	}
	if rule.HasPushOptions != nil {
		value := *rule.HasPushOptions
		rule.HasPushOptions = &value
	}
	return rule
}

func Bool(value bool) *bool { return &value }

// Evaluate is immutable and safe for concurrent use. An explicit deny or an
// invalid request always denies the entire operation. For pushes, every update
// must independently match an allow and none may match a deny.
func (p *Policy) Evaluate(request PolicyRequest) Decision {
	decision := Decision{Reason: ReasonNoMatch, DeniedUpdate: -1}
	if p == nil {
		decision.Reason = ReasonInvalidInput
		decision.Err = fmt.Errorf("%w: nil policy", ErrInvalidPolicy)
		return decision
	}
	if err := validatePolicyRequest(request); err != nil {
		decision.Reason = ReasonInvalidInput
		decision.Err = err
		return decision
	}

	var matched []string
	if request.Operation == OperationPush {
		deniedUpdate := -1
		unmatchedUpdate := -1
		for index := range request.ReceivePack.Updates {
			allowed := false
			for _, rule := range p.rules {
				if !rule.matches(request, &request.ReceivePack.Updates[index]) {
					continue
				}
				matched = append(matched, rule.ID)
				if rule.Effect == EffectDeny {
					if deniedUpdate < 0 {
						deniedUpdate = index
					}
					continue
				}
				allowed = true
			}
			if !allowed && unmatchedUpdate < 0 {
				unmatchedUpdate = index
			}
		}
		decision.MatchedRuleIDs = sortedDeduplicated(matched)
		if deniedUpdate >= 0 {
			decision.Reason = ReasonExplicitDeny
			decision.DeniedUpdate = deniedUpdate
			return decision
		}
		if unmatchedUpdate >= 0 {
			decision.DeniedUpdate = unmatchedUpdate
			return decision
		}
		decision.Allowed = true
		decision.Reason = ReasonAllowed
		return decision
	}

	allowed := false
	denied := false
	for _, rule := range p.rules {
		if !rule.matches(request, nil) {
			continue
		}
		matched = append(matched, rule.ID)
		if rule.Effect == EffectDeny {
			denied = true
			continue
		}
		allowed = true
	}
	decision.MatchedRuleIDs = sortedDeduplicated(matched)
	if denied {
		decision.Reason = ReasonExplicitDeny
		return decision
	}
	if allowed {
		decision.Allowed = true
		decision.Reason = ReasonAllowed
	}
	return decision
}

// CanAccessRepository evaluates preflight access without inventing a ref or
// update kind. A scoped allow proves that some operation may be possible, but
// only a request-wide deny can veto repository access at this stage. Concrete
// pushes must still be passed to Evaluate, where scoped denies are enforced.
func (p *Policy) CanAccessRepository(request RepositoryAccessRequest) Decision {
	decision := Decision{Reason: ReasonNoMatch, DeniedUpdate: -1}
	if p == nil {
		decision.Reason = ReasonInvalidInput
		decision.Err = fmt.Errorf("%w: nil policy", ErrInvalidPolicy)
		return decision
	}
	if err := validateRepositoryAccessRequest(request); err != nil {
		decision.Reason = ReasonInvalidInput
		decision.Err = err
		return decision
	}

	allowed := false
	denied := false
	var matched []string
	for _, rule := range p.rules {
		if !rule.matchesRepositoryAccess(request) {
			continue
		}
		if rule.Effect == EffectAllow {
			allowed = true
			matched = append(matched, rule.ID)
			continue
		}
		if rule.requestWide() {
			denied = true
			matched = append(matched, rule.ID)
		}
	}
	decision.MatchedRuleIDs = sortedDeduplicated(matched)
	if denied {
		decision.Reason = ReasonExplicitDeny
		return decision
	}
	if allowed {
		decision.Allowed = true
		decision.Reason = ReasonAllowed
	}
	return decision
}

func validateRepositoryAccessRequest(request RepositoryAccessRequest) error {
	if request.Repository == "" || request.ProtocolVersion < 0 || request.ProtocolVersion > 2 {
		return fmt.Errorf("%w: invalid repository access identity", ErrInvalidPolicy)
	}
	switch request.Operation {
	case OperationFetch:
		if request.Service != ServiceUploadPack {
			return fmt.Errorf("%w: fetch requires upload-pack", ErrInvalidPolicy)
		}
	case OperationPush:
		if request.Service != ServiceReceivePack || request.ProtocolVersion == 2 {
			return fmt.Errorf("%w: push requires receive-pack v0/v1", ErrInvalidPolicy)
		}
	default:
		return fmt.Errorf("%w: repository access operation", ErrInvalidPolicy)
	}
	return nil
}

func (rule Rule) matchesRepositoryAccess(request RepositoryAccessRequest) bool {
	return matchStrings(rule.Repositories, request.Repository) &&
		containsService(rule.Services, request.Service) &&
		containsOperation(rule.Operations, request.Operation) &&
		containsInt(rule.ProtocolVersions, request.ProtocolVersion)
}

func (rule Rule) requestWide() bool {
	return len(rule.Refs) == 0 && len(rule.UpdateKinds) == 0 &&
		len(rule.ObjectFormats) == 0 && rule.Signed == nil &&
		rule.Atomic == nil && rule.HasPushOptions == nil
}

func (rule Rule) matches(request PolicyRequest, update *Update) bool {
	if !matchStrings(rule.Repositories, request.Repository) || !containsService(rule.Services, request.Service) || !containsOperation(rule.Operations, request.Operation) || !containsInt(rule.ProtocolVersions, request.ProtocolVersion) {
		return false
	}
	if len(rule.Refs) != 0 || len(rule.UpdateKinds) != 0 {
		if update == nil || !matchStrings(rule.Refs, update.Ref) || !containsUpdateKind(rule.UpdateKinds, update.Kind) {
			return false
		}
	}
	if len(rule.ObjectFormats) != 0 || rule.Signed != nil || rule.Atomic != nil || rule.HasPushOptions != nil {
		if request.ReceivePack == nil || !containsObjectFormat(rule.ObjectFormats, request.ReceivePack.ObjectFormat) {
			return false
		}
		if rule.Signed != nil && *rule.Signed != request.ReceivePack.Signed {
			return false
		}
		if rule.Atomic != nil && *rule.Atomic != request.ReceivePack.Atomic {
			return false
		}
		if rule.HasPushOptions != nil && *rule.HasPushOptions != request.ReceivePack.PushOptionsNegotiated {
			return false
		}
	}
	return true
}

func validatePolicyRequest(request PolicyRequest) error {
	if request.Repository == "" || (request.Service != ServiceUploadPack && request.Service != ServiceReceivePack) || request.ProtocolVersion < 0 || request.ProtocolVersion > 2 {
		return fmt.Errorf("%w: invalid request identity", ErrInvalidPolicy)
	}
	switch request.Operation {
	case OperationDiscover:
		if request.ReceivePack != nil {
			return fmt.Errorf("%w: discovery cannot have receive-pack data", ErrInvalidPolicy)
		}
	case OperationFetch:
		if request.Service != ServiceUploadPack || request.ReceivePack != nil {
			return fmt.Errorf("%w: invalid fetch request", ErrInvalidPolicy)
		}
	case OperationPush:
		if request.Service != ServiceReceivePack || request.ReceivePack == nil || request.ReceivePack.Kind != ReceivePackPush || len(request.ReceivePack.Updates) == 0 {
			return fmt.Errorf("%w: invalid push request", ErrInvalidPolicy)
		}
		if request.ProtocolVersion == 2 {
			return fmt.Errorf("%w: protocol v2 push", ErrUnsupported)
		}
		if err := validateReceiveForPolicy(*request.ReceivePack); err != nil {
			return err
		}
	case OperationProbe, OperationNoop:
		if request.Service != ServiceReceivePack || request.ReceivePack == nil || len(request.ReceivePack.Updates) != 0 {
			return fmt.Errorf("%w: invalid receive-pack no-op", ErrInvalidPolicy)
		}
		expected := ReceivePackProbe
		if request.Operation == OperationNoop {
			expected = ReceivePackNoop
		}
		if request.ReceivePack.Kind != expected {
			return fmt.Errorf("%w: receive-pack kind mismatch", ErrInvalidPolicy)
		}
	default:
		return fmt.Errorf("%w: unknown operation", ErrInvalidPolicy)
	}
	return nil
}

func validateReceiveForPolicy(request ReceivePackRequest) error {
	if request.ObjectFormat.oidHexLength() == 0 {
		return fmt.Errorf("%w: object format", ErrInvalidPolicy)
	}
	if request.PushOptionsNegotiated != hasCapability(request.Capabilities, "push-options") || len(request.PushOptions) != 0 && !request.PushOptionsNegotiated {
		return fmt.Errorf("%w: inconsistent push-options state", ErrInvalidPolicy)
	}
	seen := make(map[string]struct{}, len(request.Updates))
	for _, update := range request.Updates {
		if err := ValidateRefName(update.Ref); err != nil {
			return fmt.Errorf("%w: update ref", ErrInvalidPolicy)
		}
		oldOID, oldErr := parseOID(update.OldOID, request.ObjectFormat)
		newOID, newErr := parseOID(update.NewOID, request.ObjectFormat)
		if oldErr != nil || newErr != nil || oldOID != update.OldOID || newOID != update.NewOID {
			return fmt.Errorf("%w: non-canonical update object id", ErrInvalidPolicy)
		}
		expected := UpdateModify
		if allZero(oldOID) {
			expected = UpdateCreate
		}
		if allZero(newOID) {
			expected = UpdateDelete
		}
		if allZero(oldOID) && allZero(newOID) || update.Kind != expected {
			return fmt.Errorf("%w: update kind", ErrInvalidPolicy)
		}
		if _, duplicate := seen[update.Ref]; duplicate {
			return fmt.Errorf("%w: duplicate ref", ErrInvalidPolicy)
		}
		seen[update.Ref] = struct{}{}
	}
	return nil
}

func validRuleEnums(rule Rule) bool {
	for _, service := range rule.Services {
		if service != ServiceUploadPack && service != ServiceReceivePack {
			return false
		}
	}
	for _, operation := range rule.Operations {
		switch operation {
		case OperationDiscover, OperationFetch, OperationPush, OperationProbe, OperationNoop:
		default:
			return false
		}
	}
	for _, version := range rule.ProtocolVersions {
		if version < 0 || version > 2 {
			return false
		}
	}
	for _, format := range rule.ObjectFormats {
		if format.oidHexLength() == 0 {
			return false
		}
	}
	for _, kind := range rule.UpdateKinds {
		if kind != UpdateCreate && kind != UpdateModify && kind != UpdateDelete {
			return false
		}
	}
	return true
}

func matchStrings(matchers []StringMatcher, value string) bool {
	if len(matchers) == 0 {
		return true
	}
	for _, matcher := range matchers {
		if matcher.matches(value) {
			return true
		}
	}
	return false
}

func containsService(values []Service, target Service) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsOperation(values []Operation, target Operation) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsInt(values []int, target int) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsObjectFormat(values []ObjectFormat, target ObjectFormat) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsUpdateKind(values []UpdateKind, target UpdateKind) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedDeduplicated(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
