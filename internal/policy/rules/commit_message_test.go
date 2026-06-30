package rules

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/policy/ruletest"
	"github.com/psenna/git-proxy/internal/port"
)

func newCommitMessage(params map[string]any) port.Rule {
	return newCommitMessageRule(policy.RuleConfig{Params: params})
}

func TestCommitMessage_RequirePrefix(t *testing.T) {
	rule := newCommitMessage(map[string]any{
		"require_prefix": []string{"feat:", "fix:", "chore:"},
	})
	cases := []ruletest.PushCase{
		{
			Name: "subject with allowed prefix allowed",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "feat: add thing"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "subject without prefix denied",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "add thing"},
			}},
			Want:       port.VerdictDeny,
			WantReason: `commit s1 subject "add thing" does not start with any required prefix`,
		},
		{
			Name: "second commit without prefix denied",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "fix: ok"},
				{SHA: "s2", Message: "bad subject"},
			}},
			Want:       port.VerdictDeny,
			WantReason: `commit s2 subject "bad subject" does not start with any required prefix`,
		},
		{
			Name: "subject is first line only",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "chore: subject\n\nbody line"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "no commits allowed",
			Req:  port.PushRequest{},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestCommitMessage_DenyRegex(t *testing.T) {
	rule := newCommitMessage(map[string]any{
		"deny_regex": []string{"WIP$", "TODO.*"},
	})
	cases := []ruletest.PushCase{
		{
			Name: "clean subject allowed",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "feat: add thing"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "WIP subject denied",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "feat: WIP"},
			}},
			Want:       port.VerdictDeny,
			WantReason: `commit s1 subject "feat: WIP" matches deny regex "WIP$"`,
		},
		{
			Name: "TODO subject denied",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "docs: TODO later"},
			}},
			Want:       port.VerdictDeny,
			WantReason: `commit s1 subject "docs: TODO later" matches deny regex "TODO.*"`,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestCommitMessage_EmptyConfigAllowsAll(t *testing.T) {
	// Empty require_prefix + empty deny_regex = allow-all (nothing enforced).
	rule := newCommitMessage(map[string]any{})
	cases := []ruletest.PushCase{
		{
			Name: "any subject allowed",
			Req: port.PushRequest{Commits: []port.Commit{
				{SHA: "s1", Message: "whatever"},
			}},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestCommitMessage_BadDenyRegexFailsClosed(t *testing.T) {
	// A malformed deny_regex must fail closed: EvaluatePush returns an error so
	// the engine denies (a bad regex in config must not silently disable the
	// rule). The rule pre-compiles deny_regex in the factory.
	rule := newCommitMessage(map[string]any{
		"deny_regex": []string{"["},
	})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{Commits: []port.Commit{{SHA: "s1", Message: "x"}}})
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny on bad deny_regex", dec.Verdict)
	}
}

func TestCommitMessage_FetchAlwaysAllows(t *testing.T) {
	rule := newCommitMessage(map[string]any{"require_prefix": []string{"feat:"}})
	ruletest.RunFetch(t, rule, []ruletest.FetchCase{
		{Name: "fetch allowed", Req: port.FetchRequest{Agent: "x", Repo: "r"}, Want: port.VerdictAllow},
	})
}

func TestCommitMessage_RegisteredName(t *testing.T) {
	if got := newCommitMessage(nil).Name(); got != "commit_message" {
		t.Fatalf("Name() = %q, want commit_message", got)
	}
}

func TestCommitMessage_FactoryRegistered(t *testing.T) {
	f, ok := policy.LookupRule("commit_message")
	if !ok {
		t.Fatal("commit_message not registered in default registry")
	}
	r := f(policy.RuleConfig{Params: map[string]any{"require_prefix": []string{"feat:"}}})
	if r.Name() != "commit_message" {
		t.Fatalf("factory produced %q, want commit_message", r.Name())
	}
}