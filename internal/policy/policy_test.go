package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func mustCompile(t *testing.T, spec Spec, opts ...Options) *Policy {
	t.Helper()
	var option Options
	if len(opts) != 0 {
		option = opts[0]
	}
	policy, err := Compile(spec, option)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return policy
}

func allowRule(id string) RuleSpec { return RuleSpec{ID: id, Effect: EffectAllow} }

func request(method, path string) Request {
	return Request{Method: method, EscapedPath: path}
}

func TestDefaultDenyAndExactMethod(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "read", Effect: EffectAllow, Methods: []string{"GET"}, Paths: []string{"/items"},
	}}})

	if decision := policy.Evaluate(t.Context(), request("GET", "/items")); !decision.Allowed() {
		t.Fatalf("GET /items = %#v, want allow", decision)
	}
	if decision := policy.Evaluate(t.Context(), request("get", "/items")); decision.Allowed() || decision.Reason != ReasonInvalidRequest {
		t.Errorf("lowercase method = %#v, want invalid-request deny", decision)
	}
	for _, method := range []string{"GETTING", "POST"} {
		if decision := policy.Evaluate(t.Context(), request(method, "/items")); decision.Allowed() || decision.Reason != ReasonNoMatch {
			t.Errorf("%s /items = %#v, want no-match deny", method, decision)
		}
	}
	if decision := policy.Evaluate(t.Context(), request("GET", "/other")); decision.Allowed() {
		t.Fatalf("unmatched request = %#v, want deny", decision)
	}
}

func TestDenyPrecedenceIsOrderIndependent(t *testing.T) {
	allow := RuleSpec{ID: "z-allow", Effect: EffectAllow, Methods: []string{"POST"}, Paths: []string{"/items/**"}}
	deny := RuleSpec{ID: "a-deny", Effect: EffectDeny, Methods: []string{"POST"}, Paths: []string{"/items/admin"}}
	for _, rules := range [][]RuleSpec{{allow, deny}, {deny, allow}} {
		policy := mustCompile(t, Spec{Rules: rules})
		decision := policy.Evaluate(t.Context(), request("POST", "/items/admin"))
		if decision.Effect != EffectDeny || decision.Reason != ReasonExplicitDeny || decision.Err != nil {
			t.Fatalf("decision = %#v, want explicit deny", decision)
		}
		if want := []string{"a-deny", "z-allow"}; !reflect.DeepEqual(decision.MatchedRuleIDs, want) {
			t.Fatalf("matched = %v, want %v", decision.MatchedRuleIDs, want)
		}
	}
}

func TestCompiledPolicyIsIndependentOfSpecMutation(t *testing.T) {
	spec := Spec{Rules: []RuleSpec{{
		ID: "read", Effect: EffectAllow, Methods: []string{"GET"}, Paths: []string{"/safe"},
	}}}
	policy := mustCompile(t, spec)
	spec.Rules[0].Effect = EffectDeny
	spec.Rules[0].Methods[0] = "POST"
	spec.Rules[0].Paths[0] = "/unsafe"

	if decision := policy.Evaluate(t.Context(), request("GET", "/safe")); !decision.Allowed() {
		t.Fatalf("mutating source spec changed compiled policy: %#v", decision)
	}
}

func TestPathGlobsAreSegmentAwareAndCanonical(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		allow   bool
	}{
		{"/v1/*", "/v1/a", true},
		{"/v1/*", "/v1/a/b", false},
		{"/v1/*", "/v1/", false},
		{"/v1/**", "/v1", true},
		{"/v1/**", "/v1/a/b", true},
		{"/v1/**/end", "/v1/end", true},
		{"/v1/**/end", "/v1/a/b/end", true},
		{"/v1/item", "/v1/items", false},
		{"/caf%C3%A9", "/caf%C3%A9", true},
		{"/caf%C3%A9", "/caf%c3%a9", true},
	}
	for _, test := range tests {
		t.Run(test.pattern+"_"+test.path, func(t *testing.T) {
			policy := mustCompile(t, Spec{Rules: []RuleSpec{{ID: "path", Effect: EffectAllow, Paths: []string{test.pattern}}}})
			got := policy.Evaluate(t.Context(), request("GET", test.path)).Allowed()
			if got != test.allow {
				t.Fatalf("match(%q, %q) = %v, want %v", test.pattern, test.path, got, test.allow)
			}
		})
	}

	for _, invalid := range []string{
		"relative", "/v1//x", "/v1/%2F/x", "/v1/%5c/x", "/v1/%2e%2e/x", "/v1/%zz",
		"/v1/%252fadmin", "/v1/%252e%252e/admin", "/v1/%2541", "/safe/..%3Bignored/admin", "/matrix;param/x",
	} {
		if _, err := CanonicalPath(invalid); err == nil {
			t.Errorf("CanonicalPath(%q) unexpectedly succeeded", invalid)
		}
	}
	if canonical, err := CanonicalPath("/v1/100%25done"); err != nil || canonical != "/v1/100%25done" {
		t.Fatalf("literal percent path = %q, %v; want allowed", canonical, err)
	}
	if canonical, err := CanonicalQuery("message=hello%20world"); err != nil || canonical != "message=hello%20world" {
		t.Fatalf("space query = %q, %v", canonical, err)
	}
	for _, invalid := range []string{"message=hello+world", "next=%2526admin%253Dtrue", "key%252Ename=value"} {
		if _, err := CanonicalQuery(invalid); err == nil {
			t.Errorf("CanonicalQuery(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestCanonicalQueryAndPollutionSafeMatchers(t *testing.T) {
	canonical, err := CanonicalQuery("b=2&a=3&a=1")
	if err != nil || canonical != "a=1&a=3&b=2" {
		t.Fatalf("CanonicalQuery = %q, %v", canonical, err)
	}
	eqPolicy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "eq", Effect: EffectAllow,
		Query: []QueryMatcherSpec{{Key: "mode", Op: QueryEqual, Value: "safe"}},
	}}})
	if got := eqPolicy.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/", RawQuery: "mode=safe"}); !got.Allowed() {
		t.Fatalf("single eq = %#v, want allow", got)
	}
	if got := eqPolicy.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/", RawQuery: "mode=safe&mode=unsafe"}); got.Allowed() {
		t.Fatalf("duplicate eq = %#v, want deny", got)
	}

	inPolicy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "in", Effect: EffectAllow,
		Query: []QueryMatcherSpec{{Key: "label", Op: QueryIn, Values: []string{"one", "two"}}},
	}}})
	if got := inPolicy.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/", RawQuery: "label=two&label=one"}); !got.Allowed() {
		t.Fatalf("allowed repeated values = %#v", got)
	}
	if got := inPolicy.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/", RawQuery: "label=one&label=evil"}); got.Allowed() {
		t.Fatalf("mixed repeated values = %#v, want deny", got)
	}
	if got := eqPolicy.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/", RawQuery: "mode=%zz"}); got.Reason != ReasonInvalidRequest {
		t.Fatalf("malformed query = %#v, want invalid request", got)
	}
}

func TestJSONPointerEqualityInAndDuplicateRejection(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "json", Effect: EffectAllow, Methods: []string{"POST"},
		JSON: []JSONMatcherSpec{
			{Pointer: "/a~1b/~0key/0", Op: JSONEqual, Value: json.RawMessage(`1.0`)},
			{Pointer: "/state", Op: JSONIn, Values: []json.RawMessage{json.RawMessage(`"open"`), json.RawMessage(`"closed"`)}},
		},
	}}})
	good := Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: []byte(`{"a/b":{"~key":[1]},"state":"open"}`)}
	if decision := policy.Evaluate(t.Context(), good); !decision.Allowed() {
		t.Fatalf("valid JSON = %#v, want allow", decision)
	}

	for name, body := range map[string]string{
		"missing":       `{"a/b":{"~key":[1]}}`,
		"wrong":         `{"a/b":{"~key":[2]},"state":"open"}`,
		"duplicate-key": `{"a/b":{"~key":[1]},"state":"open","state":"closed"}`,
		"malformed":     `{"a/b":`,
		"huge-exponent": `{"a/b":{"~key":[1e9999999]},"state":"open"}`,
	} {
		t.Run(name, func(t *testing.T) {
			input := good
			input.Body = []byte(body)
			decision := policy.Evaluate(t.Context(), input)
			if decision.Allowed() {
				t.Fatalf("body %s unexpectedly allowed", body)
			}
			if (name == "duplicate-key" || name == "malformed" || name == "huge-exponent") && decision.Reason != ReasonEvaluationError {
				t.Fatalf("body %s reason = %s, want evaluation error", body, decision.Reason)
			}
		})
	}
}

func TestJSONMatchersRequireUnambiguousUTF8MediaType(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "json", Effect: EffectAllow,
		JSON: []JSONMatcherSpec{{Pointer: "/ok", Op: JSONEqual, Value: json.RawMessage(`true`)}},
	}}})
	for _, contentType := range []string{"text/plain", "application/json; charset=iso-8859-1", "application/json; profile=unsafe"} {
		decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: contentType, Body: []byte(`{"ok":true}`)})
		if decision.Allowed() || decision.Reason != ReasonEvaluationError {
			t.Errorf("content type %q = %#v, want fail-closed", contentType, decision)
		}
	}
	if decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/problem+json; charset=UTF-8", Body: []byte(`{"ok":true}`)}); !decision.Allowed() {
		t.Fatalf("UTF-8 +json was rejected: %#v", decision)
	}
}

func TestJSONRejectsUnpairedSurrogates(t *testing.T) {
	for _, body := range []string{`{"value":"\uD800"}`, `{"value":"\uDC00"}`, `{"\uD800":"value"}`} {
		if _, err := decodeUniqueJSON([]byte(body)); err == nil {
			t.Errorf("decodeUniqueJSON(%s) accepted an unpaired surrogate", body)
		}
	}
	if _, err := decodeUniqueJSON([]byte(`{"value":"\uD83D\uDE00"}`)); err != nil {
		t.Fatalf("valid surrogate pair was rejected: %v", err)
	}
}

func TestInvalidJSONMatcherRejectedAtCompile(t *testing.T) {
	_, err := Compile(Spec{Rules: []RuleSpec{{
		ID: "bad", Effect: EffectAllow,
		JSON: []JSONMatcherSpec{{Pointer: "/x", Op: JSONEqual, Value: json.RawMessage(`{"x":1,"x":2}`)}},
	}}}, Options{})
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("Compile() error = %v, want duplicate key", err)
	}
}

func TestJSONMatcherYAMLPreservesJSONValues(t *testing.T) {
	var matcher JSONMatcherSpec
	err := yaml.Unmarshal([]byte(`
pointer: /payload
op: eq
value:
  enabled: true
  count: 0x10
  ratio: .5
  tags: [one, null]
`), &matcher)
	if err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{ID: "yaml", Effect: EffectAllow, JSON: []JSONMatcherSpec{matcher}}}})
	input := Request{
		Method: "POST", EscapedPath: "/", ContentType: "application/json",
		Body: []byte(`{"payload":{"enabled":true,"count":16,"ratio":0.5,"tags":["one",null]}}`),
	}
	if decision := policy.Evaluate(t.Context(), input); !decision.Allowed() {
		t.Fatalf("YAML-derived JSON matcher = %#v, raw value %s", decision, matcher.Value)
	}

	if err := yaml.Unmarshal([]byte("pointer: /state\nop: in\nvalues: [open, closed]\n"), &matcher); err != nil {
		t.Fatalf("yaml.Unmarshal(in) error = %v", err)
	}
	policy = mustCompile(t, Spec{Rules: []RuleSpec{{ID: "yaml-in", Effect: EffectAllow, JSON: []JSONMatcherSpec{matcher}}}})
	input.Body = []byte(`{"state":"open"}`)
	if decision := policy.Evaluate(t.Context(), input); !decision.Allowed() {
		t.Fatalf("YAML-derived in matcher = %#v", decision)
	}
}

func TestJSONMatcherYAMLRejectsNonJSONOrAmbiguousValues(t *testing.T) {
	tests := map[string]string{
		"duplicate nested key": "pointer: /x\nop: eq\nvalue: {a: 1, a: 2}\n",
		"anchor":               "pointer: /x\nop: eq\nvalue: &base {a: 1}\n",
		"non-string key":       "pointer: /x\nop: eq\nvalue: {1: value}\n",
		"non-finite":           "pointer: /x\nop: eq\nvalue: .nan\n",
		"timestamp":            "pointer: /x\nop: eq\nvalue: 2026-07-15T00:00:00Z\n",
		"custom map tag":       "pointer: /x\nop: eq\nvalue: !thing {a: 1}\n",
		"binary":               "pointer: /x\nop: eq\nvalue: !!binary SGVsbG8=\n",
		"unknown field":        "pointer: /x\nop: eq\nvalue: 1\nextra: true\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var matcher JSONMatcherSpec
			if err := yaml.Unmarshal([]byte(input), &matcher); err == nil {
				t.Fatalf("yaml.Unmarshal(%q) unexpectedly succeeded: %#v", input, matcher)
			}
		})
	}
}

func TestJSONMatcherJSONDecodingRemainsLossless(t *testing.T) {
	var matcher JSONMatcherSpec
	if err := json.Unmarshal([]byte(`{"pointer":"/x","op":"eq","value":{"n":9007199254740993}}`), &matcher); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := string(matcher.Value); got != `{"n":9007199254740993}` {
		t.Fatalf("raw JSON value = %s", got)
	}
}

func TestBodyCapAndNeedsBody(t *testing.T) {
	noBody := mustCompile(t, Spec{Rules: []RuleSpec{allowRule("all")}}, Options{BodyLimit: 4})
	if noBody.NeedsBody() {
		t.Fatal("method/path-only policy unexpectedly needs body")
	}
	if noBody.MaxBodyBytes() != 4 {
		t.Fatalf("MaxBodyBytes = %d, want 4", noBody.MaxBodyBytes())
	}
	if decision := noBody.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/", Body: []byte("12345")}); !errors.Is(decision.Err, ErrBodyTooLarge) {
		t.Fatalf("oversized Evaluate = %#v", decision)
	}

	withBody := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "json", Effect: EffectAllow,
		JSON: []JSONMatcherSpec{{Pointer: "", Op: JSONEqual, Value: json.RawMessage(`1`)}},
	}}}, Options{BodyLimit: 4})
	if !withBody.NeedsBody() {
		t.Fatal("JSON policy should need body")
	}
	req := httptest.NewRequest("POST", "http://forcefield/", strings.NewReader("12345"))
	if decision := withBody.EvaluateHTTP(t.Context(), req); !errors.Is(decision.Err, ErrBodyTooLarge) || decision.Reason != ReasonBodyTooLarge {
		t.Fatalf("oversized EvaluateHTTP = %#v", decision)
	}
}

func TestMalformedBodyRuleFailsClosedButOnlyAfterCheapMatchers(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{
		allowRule("baseline"),
		{ID: "post-json", Effect: EffectAllow, Methods: []string{"POST"}, JSON: []JSONMatcherSpec{{Pointer: "/x", Op: JSONEqual, Value: json.RawMessage(`1`)}}},
	}})
	malformed := Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: []byte(`{`)}
	if decision := policy.Evaluate(t.Context(), malformed); decision.Allowed() || decision.Reason != ReasonEvaluationError {
		t.Fatalf("POST malformed body = %#v, want fail-closed", decision)
	}
	malformed.Method = "GET"
	if decision := policy.Evaluate(t.Context(), malformed); !decision.Allowed() {
		t.Fatalf("unrelated GET body matcher should not parse: %#v", decision)
	}
}

func TestGraphQLTypeRootFieldsFragmentsAndAliases(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "graphql", Effect: EffectAllow, Methods: []string{"POST"},
		GraphQL: &GraphQLSpec{OperationType: "query", RootFields: []string{"viewer", "repository"}},
	}}})
	makeRequest := func(query string) Request {
		envelope, _ := json.Marshal(map[string]any{"query": query})
		return Request{Method: "POST", EscapedPath: "/graphql", ContentType: "application/json", Body: envelope}
	}
	good := `query Q { me: viewer { id } ...Repo } fragment Repo on Query { repository(owner:"o", name:"r") { id } }`
	if decision := policy.Evaluate(t.Context(), makeRequest(good)); !decision.Allowed() {
		t.Fatalf("valid GraphQL = %#v", decision)
	}
	for name, query := range map[string]string{
		"extra-root": `query { viewer { id } deleteUser(id:"1") { id } }`,
		"mutation":   `mutation { viewer { id } }`,
	} {
		t.Run(name, func(t *testing.T) {
			if decision := policy.Evaluate(t.Context(), makeRequest(query)); decision.Allowed() {
				t.Fatalf("GraphQL %s unexpectedly allowed: %#v", query, decision)
			}
		})
	}
	if decision := policy.Evaluate(t.Context(), makeRequest(`query {`)); decision.Reason != ReasonEvaluationError {
		t.Fatalf("malformed GraphQL = %#v, want evaluation error", decision)
	}
}

func TestGraphQLOperationSelectionAndDuplicateEnvelope(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "named", Effect: EffectAllow,
		GraphQL: &GraphQLSpec{OperationType: "query", OperationName: "Safe", RootFields: []string{"viewer"}},
	}}})
	document := `query Safe { viewer { id } } query Unsafe { admin { id } }`
	withoutName := []byte(`{"query":"query Safe { viewer { id } } query Unsafe { admin { id } }"}`)
	if decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: withoutName}); decision.Reason != ReasonEvaluationError {
		t.Fatalf("ambiguous operation = %#v", decision)
	}
	envelope, _ := json.Marshal(map[string]any{"query": document, "operationName": "Safe"})
	if decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: envelope}); !decision.Allowed() {
		t.Fatalf("selected operation = %#v", decision)
	}
	duplicate := []byte(`{"query":"query Safe { viewer { id } }","query":"query Safe { admin { id } }","operationName":"Safe"}`)
	if decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: duplicate}); decision.Reason != ReasonEvaluationError {
		t.Fatalf("duplicate envelope = %#v", decision)
	}
}

func TestGraphQLFragmentExpansionIsBounded(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "graphql", Effect: EffectAllow,
		GraphQL: &GraphQLSpec{OperationType: "query", RootFields: []string{"viewer"}},
	}}})
	var document strings.Builder
	document.WriteString("query { ...F0 }")
	for i := 0; i <= maxGraphQLExpansionDepth; i++ {
		if i == maxGraphQLExpansionDepth {
			document.WriteString(" fragment F" + strconv.Itoa(i) + " on Query { viewer { id } }")
		} else {
			document.WriteString(" fragment F" + strconv.Itoa(i) + " on Query { ...F" + strconv.Itoa(i+1) + " }")
		}
	}
	envelope, _ := json.Marshal(map[string]any{"query": document.String()})
	decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: envelope})
	if decision.Allowed() || decision.Reason != ReasonEvaluationError {
		t.Fatalf("deep fragment expansion = %#v, want evaluation error", decision)
	}
}

func TestGraphQLRejectsParserDepthAndTokenBombs(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{ID: "graphql", Effect: EffectAllow, GraphQL: &GraphQLSpec{OperationType: "query"}}}})
	deep := "query { viewer " + strings.Repeat("{ child ", maxGraphQLSyntaxDepth+1) + strings.Repeat("}", maxGraphQLSyntaxDepth+2)
	for name, document := range map[string]string{
		"depth":  deep,
		"tokens": "query { " + strings.Repeat("viewer ", maxGraphQLTokens+1) + "}",
	} {
		envelope, _ := json.Marshal(map[string]any{"query": document})
		decision := policy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: envelope})
		if decision.Allowed() || decision.Reason != ReasonEvaluationError {
			t.Errorf("GraphQL %s bomb = %#v", name, decision)
		}
	}
}

func TestGraphQLGETUsesCanonicalQuery(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "get", Effect: EffectAllow, Methods: []string{"GET"},
		GraphQL: &GraphQLSpec{OperationType: "query", RootFields: []string{"viewer"}},
	}}})
	query := strings.ReplaceAll(url.Values{"query": {`query { viewer { id } }`}}.Encode(), "+", "%20")
	if decision := policy.Evaluate(t.Context(), Request{Method: "GET", EscapedPath: "/graphql", RawQuery: query}); !decision.Allowed() {
		t.Fatalf("GraphQL GET = %#v", decision)
	}
}

func TestGraphQLRejectsAmbiguousCarriers(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "graphql", Effect: EffectAllow,
		GraphQL: &GraphQLSpec{OperationType: "query", RootFields: []string{"viewer"}},
	}}})
	allowed := `query { viewer { id } }`
	postBody, _ := json.Marshal(map[string]any{"query": allowed})
	tests := []Request{
		{Method: "GET", EscapedPath: "/graphql", RawQuery: "query=query%20%7B%20viewer%20%7B%20id%20%7D%20%7D", Body: []byte(`query { admin { id } }`)},
		{Method: "POST", EscapedPath: "/graphql", RawQuery: "query=query%20%7B%20admin%20%7D", ContentType: "application/json", Body: postBody},
		{Method: "PUT", EscapedPath: "/graphql", ContentType: "application/json", Body: postBody},
	}
	for _, request := range tests {
		if decision := policy.Evaluate(t.Context(), request); decision.Allowed() || decision.Reason != ReasonEvaluationError {
			t.Errorf("ambiguous GraphQL request = %#v", decision)
		}
	}
}

func TestCELClosedVariablesBoolOutputAndEvaluation(t *testing.T) {
	for name, expression := range map[string]string{
		"unknown-variable": `secret == "x"`,
		"non-bool":         `method`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Compile(Spec{Rules: []RuleSpec{{ID: "cel", Effect: EffectAllow, CEL: &CELSpec{Expression: expression}}}}, Options{})
			if err == nil {
				t.Fatalf("Compile(%q) unexpectedly succeeded", expression)
			}
		})
	}

	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "cel", Effect: EffectAllow,
		CEL: &CELSpec{Expression: `method == "POST" && query["mode"] == ["safe"] && body.amount <= 10`},
	}}}, Options{CELTimeout: time.Second})
	input := Request{Method: "POST", EscapedPath: "/", RawQuery: "mode=safe", ContentType: "application/json", Body: []byte(`{"amount":10}`)}
	if decision := policy.Evaluate(t.Context(), input); !decision.Allowed() {
		t.Fatalf("CEL valid request = %#v", decision)
	}
	input.Body = []byte(`{"amount":11}`)
	if decision := policy.Evaluate(t.Context(), input); decision.Allowed() {
		t.Fatalf("CEL false request = %#v", decision)
	}
	input.Body = []byte(`{"amount":10,"amount":1}`)
	if decision := policy.Evaluate(t.Context(), input); decision.Reason != ReasonEvaluationError {
		t.Fatalf("CEL duplicate JSON = %#v", decision)
	}
	input.ContentType = "text/plain"
	input.Body = []byte("opaque")
	if decision := policy.Evaluate(t.Context(), input); decision.Reason != ReasonEvaluationError {
		t.Fatalf("CEL opaque body = %#v, want fail-closed error", decision)
	}
}

func TestCELLazilyRejectsOnlyInspectedLossyDecimals(t *testing.T) {
	integerPolicy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "integer", Effect: EffectAllow, CEL: &CELSpec{Expression: `body.max_output_tokens <= 100`},
	}}})
	body := []byte(`{"max_output_tokens":50,"temperature":0.7}`)
	if decision := integerPolicy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: body}); !decision.Allowed() {
		t.Fatalf("unrelated decimal broke integer CEL policy: %#v", decision)
	}
	decimalPolicy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "decimal", Effect: EffectAllow, CEL: &CELSpec{Expression: `body.amount <= 100.0`},
	}}})
	body = []byte(`{"amount":100.00000000000000001}`)
	if decision := decimalPolicy.Evaluate(t.Context(), Request{Method: "POST", EscapedPath: "/", ContentType: "application/json", Body: body}); decision.Allowed() || decision.Reason != ReasonEvaluationError {
		t.Fatalf("lossy inspected decimal = %#v, want evaluation error", decision)
	}
}

func TestCELCostLimitFailsClosed(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "cel", Effect: EffectAllow,
		CEL: &CELSpec{Expression: `query["x"].exists(v, v == "needle")`},
	}}}, Options{CELCostLimit: 1, CELTimeout: time.Second})
	input := Request{Method: "GET", EscapedPath: "/", RawQuery: "x=a&x=b&x=c&x=needle"}
	decision := policy.Evaluate(context.Background(), input)
	if decision.Allowed() || decision.Reason != ReasonEvaluationError || decision.Err == nil {
		t.Fatalf("cost-limited CEL = %#v, want fail-closed evaluation error", decision)
	}
}

func TestEvaluateHTTPRestoresBodyAndCanonicalizesURL(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "json", Effect: EffectAllow,
		JSON: []JSONMatcherSpec{{Pointer: "/ok", Op: JSONEqual, Value: json.RawMessage(`true`)}},
	}}})
	req := httptest.NewRequest("POST", "http://forcefield/caf%c3%a9?z=2&a=3&a=1", strings.NewReader(`{"ok":true}`))
	req.Header.Set("Content-Type", "application/json")
	decision := policy.EvaluateHTTP(t.Context(), req)
	if !decision.Allowed() {
		t.Fatalf("EvaluateHTTP = %#v", decision)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || string(body) != `{"ok":true}` {
		t.Fatalf("restored body = %q, %v", body, err)
	}
	if req.URL.EscapedPath() != "/caf%C3%A9" || req.URL.RawQuery != "a=1&a=3&z=2" || req.RequestURI != "/caf%C3%A9?a=1&a=3&z=2" {
		t.Fatalf("canonical URL = path %q query %q RequestURI %q", req.URL.EscapedPath(), req.URL.RawQuery, req.RequestURI)
	}
}

type failReader struct{ read bool }

func (r *failReader) Read([]byte) (int, error) {
	r.read = true
	return 0, errors.New("should not read")
}
func (*failReader) Close() error { return nil }

func TestEvaluateHTTPDoesNotBufferWhenBodyIsUnneeded(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{allowRule("all")}})
	reader := &failReader{}
	req := httptest.NewRequest("POST", "http://forcefield/", nil)
	req.Body = reader
	req.ContentLength = -1
	if decision := policy.EvaluateHTTP(t.Context(), req); !decision.Allowed() {
		t.Fatalf("EvaluateHTTP = %#v", decision)
	}
	if reader.read {
		t.Fatal("EvaluateHTTP read body for a body-independent policy")
	}
}

func TestConcurrentEvaluation(t *testing.T) {
	policy := mustCompile(t, Spec{Rules: []RuleSpec{{
		ID: "read", Effect: EffectAllow, Methods: []string{"GET"}, Paths: []string{"/v1/**"},
	}}})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if decision := policy.Evaluate(context.Background(), request("GET", "/v1/items")); !decision.Allowed() {
					t.Errorf("concurrent decision = %#v", decision)
					return
				}
			}
		}()
	}
	wg.Wait()
}
