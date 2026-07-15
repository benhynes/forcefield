package policy

import (
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/google/cel-go/cel"
)

// Policy is an immutable compiled policy, safe for concurrent evaluation.
// Its fields are deliberately private so callers cannot mutate matchers after
// validation.
type Policy struct {
	rules     []compiledRule
	opts      Options
	needsBody bool
}

type compiledRule struct {
	id      string
	effect  Effect
	methods map[string]struct{}
	paths   []pathGlob
	query   []queryMatcher
	json    []jsonMatcher
	graphql *graphqlMatcher
	cel     *celMatcher
}

type queryMatcher struct {
	key    string
	op     QueryOp
	value  string
	values map[string]struct{}
}

// Compile validates and deep-copies spec. Subsequent mutation of spec cannot
// affect the returned Policy.
func Compile(spec Spec, opts Options) (*Policy, error) {
	opts, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	needsCEL := false
	for _, rule := range spec.Rules {
		needsCEL = needsCEL || rule.CEL != nil
	}
	var celEnv *cel.Env
	if needsCEL {
		env, err := newCELEnv()
		if err != nil {
			return nil, fmt.Errorf("create CEL environment: %w", err)
		}
		celEnv = env
	}

	compiled := make([]compiledRule, 0, len(spec.Rules))
	ids := make(map[string]struct{}, len(spec.Rules))
	auditIDBytes := 0
	needsBody := false
	for i, ruleSpec := range spec.Rules {
		if ruleSpec.ID == "" || len(ruleSpec.ID) > 256 || !utf8.ValidString(ruleSpec.ID) || containsControl(ruleSpec.ID) {
			return nil, fmt.Errorf("rule %d: ID must be valid metadata", i)
		}
		auditIDBytes += len(ruleSpec.ID)
		if i > 0 {
			auditIDBytes++
		}
		if auditIDBytes > 1024 {
			return nil, fmt.Errorf("rule IDs exceed audit metadata limit")
		}
		if _, duplicate := ids[ruleSpec.ID]; duplicate {
			return nil, fmt.Errorf("rule %q: duplicate ID", ruleSpec.ID)
		}
		ids[ruleSpec.ID] = struct{}{}
		rule, err := compileRule(ruleSpec, celEnv, opts)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", ruleSpec.ID, err)
		}
		needsBody = needsBody || len(rule.json) != 0 || rule.graphql != nil || rule.cel != nil
		compiled = append(compiled, rule)
	}
	// Rule order has no policy meaning. Stable ID order also makes audit output
	// identical for semantically identical specs with different source order.
	sort.Slice(compiled, func(i, j int) bool { return compiled[i].id < compiled[j].id })
	return &Policy{rules: compiled, opts: opts, needsBody: needsBody}, nil
}

func compileRule(spec RuleSpec, env *cel.Env, opts Options) (compiledRule, error) {
	rule := compiledRule{id: spec.ID, effect: spec.Effect}
	if rule.effect != EffectAllow && rule.effect != EffectDeny {
		return compiledRule{}, fmt.Errorf("effect must be allow or deny")
	}
	if len(spec.Methods) != 0 {
		rule.methods = make(map[string]struct{}, len(spec.Methods))
		for _, method := range spec.Methods {
			if !validMethod(method) {
				return compiledRule{}, fmt.Errorf("invalid method %q", method)
			}
			if _, duplicate := rule.methods[method]; duplicate {
				return compiledRule{}, fmt.Errorf("duplicate method %q", method)
			}
			rule.methods[method] = struct{}{}
		}
	}
	if len(spec.Paths) != 0 {
		rule.paths = make([]pathGlob, len(spec.Paths))
		seen := make(map[string]struct{}, len(spec.Paths))
		for i, pattern := range spec.Paths {
			if _, duplicate := seen[pattern]; duplicate {
				return compiledRule{}, fmt.Errorf("duplicate path pattern %q", pattern)
			}
			seen[pattern] = struct{}{}
			glob, err := compilePathGlob(pattern)
			if err != nil {
				return compiledRule{}, fmt.Errorf("path %q: %w", pattern, err)
			}
			rule.paths[i] = glob
		}
	}
	if len(spec.Query) != 0 {
		rule.query = make([]queryMatcher, len(spec.Query))
		seen := make(map[string]struct{}, len(spec.Query))
		for i, matcherSpec := range spec.Query {
			key := matcherSpec.Key + "\x00" + string(matcherSpec.Op)
			if _, duplicate := seen[key]; duplicate {
				return compiledRule{}, fmt.Errorf("duplicate query matcher for %q/%s", matcherSpec.Key, matcherSpec.Op)
			}
			seen[key] = struct{}{}
			matcher, err := compileQueryMatcher(matcherSpec)
			if err != nil {
				return compiledRule{}, fmt.Errorf("query matcher %d: %w", i, err)
			}
			rule.query[i] = matcher
		}
	}
	if len(spec.JSON) != 0 {
		rule.json = make([]jsonMatcher, len(spec.JSON))
		for i, matcherSpec := range spec.JSON {
			matcher, err := compileJSONMatcher(matcherSpec)
			if err != nil {
				return compiledRule{}, fmt.Errorf("JSON matcher %d: %w", i, err)
			}
			rule.json[i] = matcher
		}
	}
	if spec.GraphQL != nil {
		matcher, err := compileGraphQLMatcher(*spec.GraphQL)
		if err != nil {
			return compiledRule{}, fmt.Errorf("GraphQL: %w", err)
		}
		rule.graphql = &matcher
	}
	if spec.CEL != nil {
		if env == nil {
			return compiledRule{}, fmt.Errorf("internal CEL environment is unavailable")
		}
		matcher, err := compileCELMatcher(env, *spec.CEL, opts)
		if err != nil {
			return compiledRule{}, err
		}
		rule.cel = matcher
	}
	return rule, nil
}

func compileQueryMatcher(spec QueryMatcherSpec) (queryMatcher, error) {
	if !validQueryComponent(spec.Key) {
		return queryMatcher{}, fmt.Errorf("invalid key")
	}
	matcher := queryMatcher{key: spec.Key, op: spec.Op, value: spec.Value}
	switch spec.Op {
	case QueryPresent, QueryAbsent:
		if spec.Value != "" || len(spec.Values) != 0 {
			return queryMatcher{}, fmt.Errorf("%s forbids value and values", spec.Op)
		}
	case QueryEqual:
		if len(spec.Values) != 0 || !validQueryComponent(spec.Value) {
			return queryMatcher{}, fmt.Errorf("eq requires one valid value and forbids values")
		}
	case QueryIn:
		if spec.Value != "" || len(spec.Values) == 0 {
			return queryMatcher{}, fmt.Errorf("in requires non-empty values and forbids value")
		}
		matcher.values = make(map[string]struct{}, len(spec.Values))
		for _, value := range spec.Values {
			if !validQueryComponent(value) {
				return queryMatcher{}, fmt.Errorf("invalid in value")
			}
			if _, duplicate := matcher.values[value]; duplicate {
				return queryMatcher{}, fmt.Errorf("duplicate in value %q", value)
			}
			matcher.values[value] = struct{}{}
		}
	default:
		return queryMatcher{}, fmt.Errorf("unsupported operation %q", spec.Op)
	}
	return matcher, nil
}

func validQueryComponent(value string) bool {
	return utf8.ValidString(value) && !containsControl(value)
}

func (m queryMatcher) matches(query map[string][]string) bool {
	values, present := query[m.key]
	switch m.op {
	case QueryPresent:
		return present
	case QueryAbsent:
		return !present
	case QueryEqual:
		return len(values) == 1 && values[0] == m.value
	case QueryIn:
		if len(values) == 0 {
			return false
		}
		for _, value := range values {
			if _, allowed := m.values[value]; !allowed {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// NeedsBody reports whether any compiled matcher can inspect a request body.
func (p *Policy) NeedsBody() bool { return p != nil && p.needsBody }

// MaxBodyBytes is the maximum body size accepted when NeedsBody is true.
func (p *Policy) MaxBodyBytes() int64 {
	if p == nil {
		return 0
	}
	return p.opts.BodyLimit
}

// EffectiveOptions returns the normalized resource bounds actually used by
// the compiled policy. Callers use this when deriving immutable revisions.
func (p *Policy) EffectiveOptions() Options {
	if p == nil {
		return Options{}
	}
	return p.opts
}
