package rules

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/policy/ruletest"
	"github.com/psenna/git-proxy/internal/port"
)

// newHistoryProtect builds a history_protect rule with the given protected-ref
// patterns, exercising the factory's params decoding the same way Resolve would.
func newHistoryProtect(refs ...string) port.Rule {
	return newHistoryProtectRule(policy.RuleConfig{
		Params: map[string]any{"refs": refs},
	})
}

func TestHistoryProtect(t *testing.T) {
	rule := newHistoryProtect("refs/heads/main", "refs/heads/release/*")

	cases := []ruletest.PushCase{
		{
			Name: "force-push to protected main denied",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b", Force: true},
			}},
			Want:       port.VerdictDeny,
			WantReason: "force-push to protected ref \"refs/heads/main\" is not allowed",
		},
		{
			Name: "delete of protected main denied",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: ""},
			}},
			Want:       port.VerdictDeny,
			WantReason: "ref deletion on protected ref \"refs/heads/main\" is not allowed",
		},
		{
			Name: "delete of protected release glob denied",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/release/v1", Old: "a", New: ""},
			}},
			Want:       port.VerdictDeny,
			WantReason: "ref deletion on protected ref \"refs/heads/release/v1\" is not allowed",
		},
		{
			Name: "fast-forward to protected main allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b", Force: false},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "create of protected main allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "", New: "b", Force: false},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "force-push to non-protected ref allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/feature/x", Old: "a", New: "b", Force: true},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "delete of non-protected ref allowed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/feature/x", Old: "a", New: ""},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "no ref updates allowed",
			Req:  port.PushRequest{},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestHistoryProtect_EmptyRefsAllowsAll(t *testing.T) {
	// Empty refs config = no refs protected → allow everything (including
	// force-push and delete). This is the documented allow-all semantic for
	// "nothing configured"; fail-closed applies to errors, not to empty config.
	rule := newHistoryProtect()
	cases := []ruletest.PushCase{
		{
			Name: "force-push allowed when no refs protected",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b", Force: true},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "delete allowed when no refs protected",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: ""},
			}},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestHistoryProtect_GlobIsSingleSegment(t *testing.T) {
	// path.Match `*` does not cross `/`, so refs/heads/release/* protects
	// refs/heads/release/v1 but NOT refs/heads/release/v1/x. A regression to a
	// matcher whose `*` crosses `/` would silently over-protect (or, for
	// branch_pattern, over-allow); this row pins the single-segment boundary.
	rule := newHistoryProtect("refs/heads/release/*")
	cases := []ruletest.PushCase{
		{
			Name: "force-push to release/v1 denied (glob matches one segment)",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/release/v1", Old: "a", New: "b", Force: true},
			}},
			Want:       port.VerdictDeny,
			WantReason: "force-push to protected ref \"refs/heads/release/v1\" is not allowed",
		},
		{
			Name: "force-push to release/v1/x allowed (glob does not cross slash)",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/release/v1/x", Old: "a", New: "b", Force: true},
			}},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestHistoryProtect_MalformedPatternNeverMatches(t *testing.T) {
	// A malformed pattern (path.Match returns ErrBadPattern) must fail safe:
	// it never matches, so the ref is treated as not protected. It must not
	// panic and must not accidentally protect an unrelated ref.
	rule := newHistoryProtect("refs/heads/[")
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "force-push allowed when protected pattern is malformed",
			Req: port.PushRequest{RefUpdates: []port.RefUpdate{
				{Ref: "refs/heads/main", Old: "a", New: "b", Force: true},
			}},
			Want: port.VerdictAllow,
		},
	})
}

func TestHistoryProtect_FetchAlwaysAllows(t *testing.T) {
	rule := newHistoryProtect("refs/heads/main")
	ruletest.RunFetch(t, rule, []ruletest.FetchCase{
		{Name: "fetch allowed", Req: port.FetchRequest{Agent: "x", Repo: "r"}, Want: port.VerdictAllow},
	})
}

func TestHistoryProtect_RegisteredName(t *testing.T) {
	if got := newHistoryProtect("refs/heads/main").Name(); got != "history_protect" {
		t.Fatalf("Name() = %q, want history_protect", got)
	}
}

func TestHistoryProtect_FactoryRegistered(t *testing.T) {
	// The rule must self-register via init() so Resolve can find it by name.
	f, ok := policy.LookupRule("history_protect")
	if !ok {
		t.Fatal("history_protect not registered in default registry")
	}
	r := f(policy.RuleConfig{Params: map[string]any{"refs": []string{"refs/heads/main"}}})
	if r.Name() != "history_protect" {
		t.Fatalf("factory produced %q, want history_protect", r.Name())
	}
}
