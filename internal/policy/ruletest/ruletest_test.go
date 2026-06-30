package ruletest_test

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy/ruletest"
	"github.com/psenna/git-proxy/internal/port"
)

// echoRule echoes a fixed verdict for push/fetch; test stand-in for a real rule.
type echoRule struct {
	name   string
	push   port.Verdict
	fetch  port.Verdict
	reason string
}

func (e echoRule) Name() string { return e.name }

func (e echoRule) EvaluatePush(port.PushRequest) (port.Decision, error) {
	if e.push == port.VerdictDeny {
		return port.Decision{Verdict: port.VerdictDeny, Reasons: []port.Reason{{Rule: e.name, Message: e.reason}}}, nil
	}
	return port.Decision{Verdict: port.VerdictAllow}, nil
}

func (e echoRule) EvaluateFetch(port.FetchRequest) (port.Decision, error) {
	if e.fetch == port.VerdictDeny {
		return port.Decision{Verdict: port.VerdictDeny, Reasons: []port.Reason{{Rule: e.name, Message: e.reason}}}, nil
	}
	return port.Decision{Verdict: port.VerdictAllow}, nil
}

func TestRunPush(t *testing.T) {
	r := echoRule{name: "echo", push: port.VerdictDeny, fetch: port.VerdictAllow, reason: "blocked"}
	ruletest.RunPush(t, r, []ruletest.PushCase{
		{Name: "deny_a", Req: port.PushRequest{Agent: "a", Repo: "r"}, Want: port.VerdictDeny, WantReason: "blocked"},
		{Name: "deny_b", Req: port.PushRequest{Agent: "b", Repo: "r"}, Want: port.VerdictDeny},
	})
}

func TestRunFetch(t *testing.T) {
	r := echoRule{name: "echo", push: port.VerdictAllow, fetch: port.VerdictDeny, reason: "no read"}
	ruletest.RunFetch(t, r, []ruletest.FetchCase{
		{Name: "deny_read", Req: port.FetchRequest{Agent: "a", Repo: "r"}, Want: port.VerdictDeny, WantReason: "no read"},
	})
}

func TestRunPushAllow(t *testing.T) {
	r := echoRule{name: "echo", push: port.VerdictAllow, fetch: port.VerdictAllow}
	ruletest.RunPush(t, r, []ruletest.PushCase{
		{Name: "allow", Req: port.PushRequest{Agent: "a", Repo: "r"}, Want: port.VerdictAllow},
	})
}