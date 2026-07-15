package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Effect is the outcome attached to a matching rule.
type Effect string

const (
	// EngineRevision changes whenever canonicalization, matcher, or effective
	// default semantics change. Persisted capability tokens bind to it through
	// their policy revision.
	EngineRevision = "forcefield-policy-engine/v1"

	EffectDeny  Effect = "deny"
	EffectAllow Effect = "allow"
)

// Reason explains why an evaluation reached its outcome.
type Reason string

const (
	ReasonAllowed         Reason = "allowed"
	ReasonExplicitDeny    Reason = "explicit_deny"
	ReasonNoMatch         Reason = "no_match"
	ReasonInvalidRequest  Reason = "invalid_request"
	ReasonBodyTooLarge    Reason = "body_too_large"
	ReasonEvaluationError Reason = "evaluation_error"
)

var (
	// ErrBodyTooLarge is returned when a request body exceeds Options.BodyLimit.
	ErrBodyTooLarge = errors.New("policy: request body exceeds limit")
	// ErrInvalidRequest marks an input which could not be canonicalized.
	ErrInvalidRequest = errors.New("policy: invalid request")
)

// Options controls resource bounds. Zero values select conservative defaults.
type Options struct {
	BodyLimit                  int64
	CELCostLimit               uint64
	CELTimeout                 time.Duration
	CELInterruptCheckFrequency uint
}

const (
	defaultBodyLimit                  = int64(1 << 20)
	defaultCELCostLimit               = uint64(10_000)
	defaultCELTimeout                 = 10 * time.Millisecond
	defaultCELInterruptCheckFrequency = uint(100)
)

func normalizeOptions(opts Options) (Options, error) {
	if opts.BodyLimit < 0 {
		return Options{}, fmt.Errorf("body limit must not be negative")
	}
	if opts.CELTimeout < 0 {
		return Options{}, fmt.Errorf("CEL timeout must not be negative")
	}
	if opts.BodyLimit == 0 {
		opts.BodyLimit = defaultBodyLimit
	}
	if opts.CELCostLimit == 0 {
		opts.CELCostLimit = defaultCELCostLimit
	}
	if opts.CELTimeout == 0 {
		opts.CELTimeout = defaultCELTimeout
	}
	if opts.CELInterruptCheckFrequency == 0 {
		opts.CELInterruptCheckFrequency = defaultCELInterruptCheckFrequency
	}
	return opts, nil
}

// Spec is the serializable form of a policy.
type Spec struct {
	Rules []RuleSpec `json:"rules" yaml:"rules"`
}

// RuleSpec is a conjunction of matcher groups. Methods and Paths are OR lists;
// Query and JSON entries are AND lists. An empty matcher set matches all
// canonical requests.
type RuleSpec struct {
	ID      string             `json:"id" yaml:"id"`
	Effect  Effect             `json:"effect" yaml:"effect"`
	Methods []string           `json:"methods,omitempty" yaml:"methods,omitempty"`
	Paths   []string           `json:"paths,omitempty" yaml:"paths,omitempty"`
	Query   []QueryMatcherSpec `json:"query,omitempty" yaml:"query,omitempty"`
	JSON    []JSONMatcherSpec  `json:"json,omitempty" yaml:"json,omitempty"`
	GraphQL *GraphQLSpec       `json:"graphql,omitempty" yaml:"graphql,omitempty"`
	CEL     *CELSpec           `json:"cel,omitempty" yaml:"cel,omitempty"`
}

// QueryOp defines a query-parameter predicate.
type QueryOp string

const (
	QueryPresent QueryOp = "present"
	QueryAbsent  QueryOp = "absent"
	// QueryEqual requires exactly one occurrence with the configured value.
	QueryEqual QueryOp = "eq"
	// QueryIn requires at least one occurrence and requires every occurrence to
	// be in Values. This prevents duplicate-parameter smuggling.
	QueryIn QueryOp = "in"
)

type QueryMatcherSpec struct {
	Key    string   `json:"key" yaml:"key"`
	Op     QueryOp  `json:"op" yaml:"op"`
	Value  string   `json:"value,omitempty" yaml:"value,omitempty"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`
}

// JSONOp defines an RFC 6901 JSON-pointer predicate.
type JSONOp string

const (
	JSONEqual JSONOp = "eq"
	JSONIn    JSONOp = "in"
)

// JSONMatcherSpec compares the value at Pointer with JSON values. Value and
// Values must each hold exactly one JSON value; duplicate object keys are
// rejected both here and in request bodies. Its YAML decoder accepts only the
// JSON data model and converts values to these lossless RawMessage fields.
type JSONMatcherSpec struct {
	Pointer string            `json:"pointer" yaml:"pointer"`
	Op      JSONOp            `json:"op" yaml:"op"`
	Value   json.RawMessage   `json:"value,omitempty" yaml:"value,omitempty"`
	Values  []json.RawMessage `json:"values,omitempty" yaml:"values,omitempty"`
}

type GraphQLSpec struct {
	OperationType string   `json:"operation_type,omitempty" yaml:"operation_type,omitempty"`
	OperationName string   `json:"operation_name,omitempty" yaml:"operation_name,omitempty"`
	RootFields    []string `json:"root_fields,omitempty" yaml:"root_fields,omitempty"`
}

type CELSpec struct {
	Expression string `json:"expression" yaml:"expression"`
}

// Request is the raw input to Evaluate. EscapedPath is an RFC 3986 escaped
// absolute path, not a decoded path. RawQuery omits the leading question mark.
// ContentType is used to select the JSON or GraphQL body decoder.
type Request struct {
	Method      string
	EscapedPath string
	RawQuery    string
	ContentType string
	Body        []byte
}

// Decision is always EffectAllow or EffectDeny. Err is diagnostic; any non-nil
// error necessarily has EffectDeny. MatchedRuleIDs is sorted for deterministic,
// order-independent auditing.
type Decision struct {
	Effect         Effect
	Reason         Reason
	MatchedRuleIDs []string
	Err            error
	CanonicalPath  string
	CanonicalQuery string
}

func (d Decision) Allowed() bool { return d.Effect == EffectAllow && d.Err == nil }
