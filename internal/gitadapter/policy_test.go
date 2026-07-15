package gitadapter

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestNewPolicyRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rules []Rule
	}{
		{name: "missing id", rules: []Rule{{Effect: EffectAllow}}},
		{name: "invalid effect", rules: []Rule{{ID: "x", Effect: Effect("audit")}}},
		{name: "duplicate id", rules: []Rule{{ID: "x", Effect: EffectAllow}, {ID: "x", Effect: EffectDeny}}},
		{name: "empty matcher", rules: []Rule{{ID: "x", Effect: EffectAllow, Repositories: []StringMatcher{{}}}}},
		{name: "ambiguous matcher", rules: []Rule{{ID: "x", Effect: EffectAllow, Repositories: []StringMatcher{{Exact: "a", Prefix: "b"}}}}},
		{name: "invalid service", rules: []Rule{{ID: "x", Effect: EffectAllow, Services: []Service{"git-archive"}}}},
		{name: "invalid operation", rules: []Rule{{ID: "x", Effect: EffectAllow, Operations: []Operation{"delete"}}}},
		{name: "invalid protocol", rules: []Rule{{ID: "x", Effect: EffectAllow, ProtocolVersions: []int{3}}}},
		{name: "invalid object format", rules: []Rule{{ID: "x", Effect: EffectAllow, ObjectFormats: []ObjectFormat{"md5"}}}},
		{name: "invalid update kind", rules: []Rule{{ID: "x", Effect: EffectAllow, UpdateKinds: []UpdateKind{"force"}}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewPolicy(test.rules); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("NewPolicy() error = %v, want ErrInvalidPolicy", err)
			}
		})
	}
}

func TestPolicyIsDefaultDeny(t *testing.T) {
	t.Parallel()
	policy := mustPolicy(t, nil)
	decision := policy.Evaluate(fetchRequest("space/repository.git"))
	if decision.Allowed || decision.Reason != ReasonNoMatch || decision.DeniedUpdate != -1 || decision.Err != nil {
		t.Fatalf("decision = %#v, want default deny", decision)
	}
}

func TestPolicyDenyWinsIndependentOfRuleOrder(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{ID: "z-allow", Effect: EffectAllow, Repositories: exact("space/repository.git"), Services: []Service{ServiceUploadPack}, Operations: []Operation{OperationFetch}},
		{ID: "a-deny", Effect: EffectDeny, Repositories: exact("space/repository.git"), Services: []Service{ServiceUploadPack}, Operations: []Operation{OperationFetch}},
	}
	wantMatched := []string{"a-deny", "z-allow"}
	for _, ordered := range [][]Rule{rules, {rules[1], rules[0]}} {
		decision := mustPolicy(t, ordered).Evaluate(fetchRequest("space/repository.git"))
		if decision.Allowed || decision.Reason != ReasonExplicitDeny {
			t.Fatalf("decision = %#v, want explicit deny", decision)
		}
		if !reflect.DeepEqual(decision.MatchedRuleIDs, wantMatched) {
			t.Errorf("matched IDs = %#v, want %#v", decision.MatchedRuleIDs, wantMatched)
		}
	}
}

func TestPolicyEveryPushedRefRequiresAllow(t *testing.T) {
	t.Parallel()
	policy := mustPolicy(t, []Rule{{
		ID:           "scoped",
		Effect:       EffectAllow,
		Repositories: exact("space/repository.git"),
		Services:     []Service{ServiceReceivePack},
		Operations:   []Operation{OperationPush},
		Refs:         []StringMatcher{{Prefix: "refs/heads/change/"}},
	}})
	request := pushRequest(
		modifyUpdate("refs/heads/change/one"),
		modifyUpdate("refs/heads/elsewhere"),
	)
	decision := policy.Evaluate(request)
	if decision.Allowed || decision.Reason != ReasonNoMatch || decision.DeniedUpdate != 1 {
		t.Fatalf("decision = %#v, want unmatched update 1", decision)
	}
}

func TestPolicyScopedDenyVetoesWholeMultiRefPush(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{
			ID:           "allow-all-refs",
			Effect:       EffectAllow,
			Repositories: exact("space/repository.git"),
			Operations:   []Operation{OperationPush},
		},
		{
			ID:           "deny-one-ref",
			Effect:       EffectDeny,
			Repositories: exact("space/repository.git"),
			Operations:   []Operation{OperationPush},
			Refs:         exact("refs/heads/restricted"),
		},
	}
	request := pushRequest(
		modifyUpdate("refs/heads/change"),
		modifyUpdate("refs/heads/restricted"),
		modifyUpdate("refs/heads/another"),
	)
	wantMatched := []string{"allow-all-refs", "deny-one-ref"}
	for _, ordered := range [][]Rule{rules, {rules[1], rules[0]}} {
		decision := mustPolicy(t, ordered).Evaluate(request)
		if decision.Allowed || decision.Reason != ReasonExplicitDeny || decision.DeniedUpdate != 1 {
			t.Fatalf("decision = %#v, want explicit deny on update 1", decision)
		}
		if !reflect.DeepEqual(decision.MatchedRuleIDs, wantMatched) {
			t.Errorf("matched IDs = %#v, want %#v", decision.MatchedRuleIDs, wantMatched)
		}
	}
}

func TestPolicyUpdateKindsAndRequestSelectors(t *testing.T) {
	t.Parallel()
	policy := mustPolicy(t, []Rule{{
		ID:             "specific",
		Effect:         EffectAllow,
		Repositories:   []StringMatcher{{Prefix: "space/"}},
		Services:       []Service{ServiceReceivePack},
		Operations:     []Operation{OperationPush},
		ObjectFormats:  []ObjectFormat{ObjectFormatSHA1},
		Refs:           []StringMatcher{{Prefix: "refs/tags/"}},
		UpdateKinds:    []UpdateKind{UpdateDelete},
		Signed:         Bool(false),
		Atomic:         Bool(true),
		HasPushOptions: Bool(true),
	}})
	request := pushRequest(deleteUpdate("refs/tags/old"))
	request.ReceivePack.Atomic = true
	request.ReceivePack.PushOptions = []string{"reason=cleanup"}
	request.ReceivePack.PushOptionsNegotiated = true
	request.ReceivePack.Capabilities = []string{"push-options"}
	decision := policy.Evaluate(request)
	if !decision.Allowed || decision.Reason != ReasonAllowed {
		t.Fatalf("decision = %#v, want allowed", decision)
	}

	request.ReceivePack.Signed = true
	decision = policy.Evaluate(request)
	if decision.Allowed || decision.Reason != ReasonNoMatch {
		t.Fatalf("signed decision = %#v, want no match", decision)
	}
}

func TestPolicyRejectsExcessiveMatcherComplexity(t *testing.T) {
	t.Parallel()
	matchers := make([]StringMatcher, maxPolicyMatchers+1)
	for index := range matchers {
		matchers[index] = StringMatcher{Exact: fmt.Sprintf("owner/repository-%04d.git", index)}
	}
	if _, err := NewPolicy([]Rule{{
		ID: "too-many", Effect: EffectAllow, Repositories: matchers,
		Operations: []Operation{OperationFetch},
	}}); err == nil {
		t.Fatal("policy accepted attacker-amplifiable matcher complexity")
	}
}

func TestCanAccessRepositoryUsesScopedAllowsButOnlyGlobalDenies(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{
			ID:           "scoped-allow",
			Effect:       EffectAllow,
			Repositories: exact("space/repository.git"),
			Operations:   []Operation{OperationPush},
			Refs:         []StringMatcher{{Prefix: "refs/heads/change/"}},
			UpdateKinds:  []UpdateKind{UpdateCreate, UpdateModify},
		},
		{
			ID:           "scoped-deny",
			Effect:       EffectDeny,
			Repositories: exact("space/repository.git"),
			Operations:   []Operation{OperationPush},
			Refs:         exact("refs/heads/change/restricted"),
		},
		{
			ID:            "format-specific-deny",
			Effect:        EffectDeny,
			Repositories:  exact("space/repository.git"),
			Operations:    []Operation{OperationPush},
			ObjectFormats: []ObjectFormat{ObjectFormatSHA256},
		},
	}
	policy := mustPolicy(t, rules)
	access := policy.CanAccessRepository(RepositoryAccessRequest{
		Repository:      "space/repository.git",
		Service:         ServiceReceivePack,
		Operation:       OperationPush,
		ProtocolVersion: 0,
	})
	if !access.Allowed || access.Reason != ReasonAllowed {
		t.Fatalf("repository access = %#v, want allowed", access)
	}
	if !reflect.DeepEqual(access.MatchedRuleIDs, []string{"scoped-allow"}) {
		t.Fatalf("repository access matched IDs = %#v", access.MatchedRuleIDs)
	}

	concrete := pushRequest(modifyUpdate("refs/heads/change/restricted"))
	decision := policy.Evaluate(concrete)
	if decision.Allowed || decision.Reason != ReasonExplicitDeny {
		t.Fatalf("concrete push = %#v, want scoped deny", decision)
	}
}

func TestCanAccessRepositoryRequestWideDenyWins(t *testing.T) {
	t.Parallel()
	policy := mustPolicy(t, []Rule{
		{ID: "scoped-allow", Effect: EffectAllow, Repositories: exact("space/repository.git"), Operations: []Operation{OperationPush}, Refs: []StringMatcher{{Prefix: "refs/heads/change/"}}},
		{ID: "global-deny", Effect: EffectDeny, Repositories: exact("space/repository.git"), Operations: []Operation{OperationPush}},
	})
	decision := policy.CanAccessRepository(RepositoryAccessRequest{
		Repository:      "space/repository.git",
		Service:         ServiceReceivePack,
		Operation:       OperationPush,
		ProtocolVersion: 1,
	})
	if decision.Allowed || decision.Reason != ReasonExplicitDeny {
		t.Fatalf("decision = %#v, want explicit deny", decision)
	}
	want := []string{"global-deny", "scoped-allow"}
	if !reflect.DeepEqual(decision.MatchedRuleIDs, want) {
		t.Fatalf("matched IDs = %#v, want %#v", decision.MatchedRuleIDs, want)
	}
}

func TestCanAccessRepositoryValidatesOperationServicePair(t *testing.T) {
	t.Parallel()
	policy := mustPolicy(t, []Rule{{ID: "all", Effect: EffectAllow}})
	tests := []RepositoryAccessRequest{
		{Repository: "space/repository.git", Service: ServiceUploadPack, Operation: OperationPush, ProtocolVersion: 0},
		{Repository: "space/repository.git", Service: ServiceReceivePack, Operation: OperationFetch, ProtocolVersion: 0},
		{Repository: "space/repository.git", Service: ServiceReceivePack, Operation: OperationPush, ProtocolVersion: 2},
		{Repository: "space/repository.git", Service: ServiceUploadPack, Operation: OperationDiscover, ProtocolVersion: 0},
	}
	for _, request := range tests {
		decision := policy.CanAccessRepository(request)
		if decision.Allowed || decision.Reason != ReasonInvalidInput || decision.Err == nil {
			t.Errorf("request %#v decision = %#v, want invalid input", request, decision)
		}
	}
}

func TestPolicyRejectsInconsistentConstructedPushes(t *testing.T) {
	t.Parallel()
	policy := mustPolicy(t, []Rule{{ID: "all", Effect: EffectAllow, Operations: []Operation{OperationPush}}})

	tests := []struct {
		name   string
		mutate func(*PolicyRequest)
	}{
		{name: "protocol v2", mutate: func(r *PolicyRequest) { r.ProtocolVersion = 2 }},
		{name: "wrong service", mutate: func(r *PolicyRequest) { r.Service = ServiceUploadPack }},
		{name: "uppercase oid", mutate: func(r *PolicyRequest) {
			r.ReceivePack.Updates[0].OldOID = strings.ToUpper(r.ReceivePack.Updates[0].OldOID)
		}},
		{name: "wrong kind", mutate: func(r *PolicyRequest) { r.ReceivePack.Updates[0].Kind = UpdateDelete }},
		{name: "duplicate ref", mutate: func(r *PolicyRequest) {
			r.ReceivePack.Updates = append(r.ReceivePack.Updates, r.ReceivePack.Updates[0])
		}},
		{name: "invalid ref", mutate: func(r *PolicyRequest) { r.ReceivePack.Updates[0].Ref = "HEAD" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := pushRequest(modifyUpdate("refs/heads/change"))
			test.mutate(&request)
			decision := policy.Evaluate(request)
			if decision.Allowed || decision.Reason != ReasonInvalidInput || decision.Err == nil {
				t.Fatalf("decision = %#v, want invalid input", decision)
			}
		})
	}
}

func TestNewPolicyDefensivelyCopiesRulesAndIsConcurrentSafe(t *testing.T) {
	t.Parallel()
	signed := false
	rules := []Rule{{
		ID:           "allow",
		Effect:       EffectAllow,
		Repositories: exact("space/repository.git"),
		Operations:   []Operation{OperationPush},
		Signed:       &signed,
	}}
	policy := mustPolicy(t, rules)
	rules[0].Repositories[0].Exact = "changed/repository.git"
	rules[0].Operations[0] = OperationFetch
	signed = true

	request := pushRequest(modifyUpdate("refs/heads/change"))
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			decision := policy.Evaluate(request)
			if !decision.Allowed {
				t.Errorf("concurrent decision = %#v, want allowed", decision)
			}
		}()
	}
	wait.Wait()
}

func mustPolicy(t *testing.T, rules []Rule) *Policy {
	t.Helper()
	policy, err := NewPolicy(rules)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func exact(value string) []StringMatcher {
	return []StringMatcher{{Exact: value}}
}

func fetchRequest(repository string) PolicyRequest {
	return PolicyRequest{
		Repository:      repository,
		Service:         ServiceUploadPack,
		Operation:       OperationFetch,
		ProtocolVersion: 2,
	}
}

func pushRequest(updates ...Update) PolicyRequest {
	needsPack := false
	for _, update := range updates {
		if update.Kind != UpdateDelete {
			needsPack = true
		}
	}
	return PolicyRequest{
		Repository:      "space/repository.git",
		Service:         ServiceReceivePack,
		Operation:       OperationPush,
		ProtocolVersion: 0,
		ReceivePack: &ReceivePackRequest{
			Kind:         ReceivePackPush,
			ObjectFormat: ObjectFormatSHA1,
			Updates:      updates,
			HasPack:      needsPack,
		},
	}
}

func modifyUpdate(ref string) Update {
	return Update{OldOID: oidASHA1, NewOID: oidBSHA1, Ref: ref, Kind: UpdateModify}
}

func deleteUpdate(ref string) Update {
	return Update{OldOID: oidASHA1, NewOID: zeroSHA1, Ref: ref, Kind: UpdateDelete}
}
