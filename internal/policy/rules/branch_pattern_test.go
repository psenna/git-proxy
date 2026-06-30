package rules

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/policy/ruletest"
	"github.com/psenna/git-proxy/internal/port"
)

// newBranchPattern builds a branch_pattern rule with the given allowed-ref
// patterns, exercising the factory's params decoding the same way Resolve
// would.
func newBranchPattern(allow ...string) port.Rule {
	return newBranchPatternRule(policy.RuleConfig{
		Params: map[string]any{"allow": allow},
	})
}

func TestBranchPattern(t *testing.T) {
	rule := newBranchPattern("refs/heads/main", "refs/heads/feat/*", "refs/heads/fix/*")

	cases := []ruletest.PushCase{
		{
			Name: "push to main allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "push to feat/x allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/feat/x", Old: "a", New: "b"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "push to fix/y allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/fix/y", Old: "a", New: "b"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "push to weird/branch denied",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/weird/branch", Old: "a", New: "b"},
			}},
			Want:       port.VerdictDeny,
			WantReason: "push to ref \"refs/heads/weird/branch\" is not allowed by any allow pattern",
		},
		{
			Name: "push to unknown top-level denied",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/secret", Old: "a", New: "b"},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "any ref in a multi-ref push must match (one bad denies)",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b"},
				{Ref: "refs/heads/weird/branch", Old: "a", New: "b"},
			}},
			Want:       port.VerdictDeny,
			WantReason: "push to ref \"refs/heads/weird/branch\" is not allowed by any allow pattern",
		},
		{
			Name: "no ref updates allowed",
			Req:  port.PushRequest{},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestBranchPattern_EmptyAllowDeniesAll(t *testing.T) {
	// Empty allow = deny all pushes (fail-closed for "nothing permitted").
	// This is intentionally different from history_protect's empty = allow-all;
	// both are documented config-semantic choices.
	rule := newBranchPattern()
	cases := []ruletest.PushCase{
		{
			Name: "push to main denied when allow empty",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b"},
			}},
			Want:       port.VerdictDeny,
			WantReason: "no branches are allowed (allow list is empty)",
		},
		{
			Name: "push to feat/x denied when allow empty",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/feat/x", Old: "a", New: "b"},
			}},
			Want: port.VerdictDeny,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestBranchPattern_FetchAlwaysAllows(t *testing.T) {
	rule := newBranchPattern("refs/heads/main")
	ruletest.RunFetch(t, rule, []ruletest.FetchCase{
		{Name: "fetch allowed", Req: port.FetchRequest{Agent: "x", Repo: "r"}, Want: port.VerdictAllow},
	})
}

func TestBranchPattern_RegisteredName(t *testing.T) {
	if got := newBranchPattern("refs/heads/main").Name(); got != "branch_pattern" {
		t.Fatalf("Name() = %q, want branch_pattern", got)
	}
}

func TestBranchPattern_FactoryRegistered(t *testing.T) {
	f, ok := policy.LookupRule("branch_pattern")
	if !ok {
		t.Fatal("branch_pattern not registered in default registry")
	}
	r := f(policy.RuleConfig{Params: map[string]any{"allow": []string{"refs/heads/main"}}})
	if r.Name() != "branch_pattern" {
		t.Fatalf("factory produced %q, want branch_pattern", r.Name())
	}
}