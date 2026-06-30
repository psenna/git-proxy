package policy

import (
	"errors"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// stubRule is a test-only Rule. It returns a canned Decision for push/fetch and
// records that it was evaluated. Real rules live in internal/policy/rules and
// register via init(); stubs are used here to exercise the engine in isolation.
type stubRule struct {
	name        string
	pushDec     port.Decision
	pushErr     error
	fetchDec    port.Decision
	fetchErr    error
	pushCalls   int
	fetchCalls  int
}

func (s *stubRule) Name() string { return s.name }

func (s *stubRule) EvaluatePush(port.PushRequest) (port.Decision, error) {
	s.pushCalls++
	return s.pushDec, s.pushErr
}

func (s *stubRule) EvaluateFetch(port.FetchRequest) (port.Decision, error) {
	s.fetchCalls++
	return s.fetchDec, s.fetchErr
}

func allow(name string) *stubRule {
	return &stubRule{name: name, pushDec: port.Decision{Verdict: port.VerdictAllow}, fetchDec: port.Decision{Verdict: port.VerdictAllow}}
}

func deny(name, msg string) *stubRule {
	return &stubRule{
		name:     name,
		pushDec:  port.Decision{Verdict: port.VerdictDeny, Reasons: []port.Reason{{Rule: name, Message: msg}}},
		fetchDec: port.Decision{Verdict: port.VerdictDeny, Reasons: []port.Reason{{Rule: name, Message: msg}}},
	}
}

func TestEngine_AllowWhenAllAllow(t *testing.T) {
	e := NewEngine(FirstDeny, allow("a"), allow("b"))
	got := e.EvaluatePush(port.PushRequest{Agent: "x", Repo: "r"})
	if got.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow", got.Verdict)
	}
	if len(got.Reasons) != 0 {
		t.Fatalf("reasons = %v, want empty", got.Reasons)
	}
}

func TestEngine_DenyWinsOverAllow(t *testing.T) {
	e := NewEngine(FirstDeny, allow("a"), deny("b", "blocked"))
	got := e.EvaluatePush(port.PushRequest{Agent: "x", Repo: "r"})
	if got.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", got.Verdict)
	}
	if len(got.Reasons) != 1 || got.Reasons[0].Rule != "b" {
		t.Fatalf("reasons = %+v, want single from b", got.Reasons)
	}
}

func TestEngine_FailClosedOnError(t *testing.T) {
	r := &stubRule{
		name:    "err_rule",
		pushErr: errors.New("boom"),
	}
	e := NewEngine(FirstDeny, r)
	got := e.EvaluatePush(port.PushRequest{Agent: "x", Repo: "r"})
	if got.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny (fail-closed)", got.Verdict)
	}
	if len(got.Reasons) != 1 {
		t.Fatalf("reasons = %+v, want one", got.Reasons)
	}
	if got.Reasons[0].Rule != "err_rule" {
		t.Fatalf("reason rule = %q, want err_rule", got.Reasons[0].Rule)
	}
}

func TestEngine_FirstDenyShortCircuits(t *testing.T) {
	d := deny("deny_first", "nope")
	a := allow("allow_second")
	e := NewEngine(FirstDeny, d, a)
	got := e.EvaluatePush(port.PushRequest{Agent: "x", Repo: "r"})
	if got.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", got.Verdict)
	}
	if a.pushCalls != 0 {
		t.Fatalf("second rule evaluated %d times, want 0 (short-circuit)", a.pushCalls)
	}
	if len(got.Reasons) != 1 {
		t.Fatalf("reasons = %+v, want only the first deny", got.Reasons)
	}
}

func TestEngine_CollectAllAggregates(t *testing.T) {
	d1 := deny("deny_one", "one")
	d2 := deny("deny_two", "two")
	a := allow("allow_three")
	e := NewEngine(CollectAll, d1, d2, a)
	got := e.EvaluatePush(port.PushRequest{Agent: "x", Repo: "r"})
	if got.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", got.Verdict)
	}
	if a.pushCalls != 1 {
		t.Fatalf("allow rule evaluated %d times, want 1 (no short-circuit)", a.pushCalls)
	}
	if len(got.Reasons) != 2 {
		t.Fatalf("reasons = %+v, want two aggregated", got.Reasons)
	}
}

func TestEngine_FetchPath(t *testing.T) {
	e := NewEngine(FirstDeny, deny("b", "blocked"))
	got := e.EvaluateFetch(port.FetchRequest{Agent: "x", Repo: "r"})
	if got.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", got.Verdict)
	}
}

func TestRegistry_RegisterAndLookup(t *testing.T) {
	// Use an isolated registry to avoid cross-test pollution with the global
	// registry used by Resolve.
	reg := NewRegistry()
	reg.Register("stub", func() port.Rule { return allow("stub") })
	f, ok := reg.Lookup("stub")
	if !ok {
		t.Fatal("Lookup stub: not found")
	}
	if r := f(); r.Name() != "stub" {
		t.Fatalf("factory produced %q, want stub", r.Name())
	}
	if _, ok := reg.Lookup("nope"); ok {
		t.Fatal("Lookup nope: want not found")
	}
}

func TestResolve_UnknownRuleFailClosed(t *testing.T) {
	// Config references a rule that is not registered: Resolve must fail closed
	// (return an error rather than silently skipping the rule).
	reg := NewRegistry()
	_, err := Resolve(PolicyConfig{Mode: FirstDeny, Rules: map[string]RuleConfig{
		"ghost": {Enabled: true},
	}}, reg)
	if err == nil {
		t.Fatal("Resolve unknown rule: want error, got nil")
	}
}

func TestResolve_AppliesAgentRepoFilter(t *testing.T) {
	reg := NewRegistry()
	reg.Register("deny_all", func() port.Rule { return deny("deny_all", "blocked") })

	// deny_all enabled only for agent "agent-1"; agent "agent-2" should be
	// exempt → request allowed.
	e, err := Resolve(PolicyConfig{Mode: FirstDeny, Rules: map[string]RuleConfig{
		"deny_all": {Enabled: true, Agents: []string{"agent-1"}},
	}}, reg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := e.EvaluatePush(port.PushRequest{Agent: "agent-2", Repo: "r"})
	if got.Verdict != port.VerdictAllow {
		t.Fatalf("agent-2 verdict = %v, want Allow (rule does not apply)", got.Verdict)
	}
	got = e.EvaluatePush(port.PushRequest{Agent: "agent-1", Repo: "r"})
	if got.Verdict != port.VerdictDeny {
		t.Fatalf("agent-1 verdict = %v, want Deny", got.Verdict)
	}
}