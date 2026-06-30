package rules

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/policy/ruletest"
	"github.com/psenna/git-proxy/internal/port"
)

func newPathACL(params map[string]any) port.Rule {
	return newPathACLRule(policy.RuleConfig{Params: params})
}

func TestPathACL_Push(t *testing.T) {
	rule := newPathACL(map[string]any{
		"deny": []string{".github/workflows/*", "secrets/**", "*.env"},
	})
	cases := []ruletest.PushCase{
		{
			Name: "denied workflow file blocked",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: ".github/workflows/ci.yml", Status: "A"},
			}},
			Want:       port.VerdictDeny,
			WantReason: `push touches denied path ".github/workflows/ci.yml" (matched pattern ".github/workflows/*")`,
		},
		{
			Name: "denied nested secret blocked",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "secrets/api/key.pem", Status: "M"},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "denied env file blocked",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "deploy/prod.env", Status: "A"},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "clean files allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "src/main.go", Status: "M"},
				{Path: "README.md", Status: "A"},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "no changed files allowed",
			Req:  port.PushRequest{},
			Want: port.VerdictAllow,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

func TestPathACL_EmptyDenyAllowsAll(t *testing.T) {
	// Empty deny list = allow-all (nothing denied).
	rule := newPathACL(map[string]any{})
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "any path allowed when deny empty",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "secrets/key.pem", Status: "A"},
			}},
			Want: port.VerdictAllow,
		},
	})
}

func TestPathACL_MalformedPatternDropped(t *testing.T) {
	// A malformed deny pattern is dropped (fail-safe, never matches). The good
	// pattern still applies.
	rule := newPathACL(map[string]any{
		"deny": []string{"[unclosed", "secrets/**"},
	})
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "good pattern still denies",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "secrets/x.key", Status: "A"},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "malformed pattern does not deny unrelated path",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "src/app.go", Status: "M"},
			}},
			Want: port.VerdictAllow,
		},
	})
}

func TestPathACL_Fetch(t *testing.T) {
	// EvaluateFetch denies a fetch that requests a denied path. Task 9
	// populates FetchRequest.Paths; the matcher is shared push+fetch.
	rule := newPathACL(map[string]any{
		"deny": []string{"secrets/**"},
	})
	ruletest.RunFetch(t, rule, []ruletest.FetchCase{
		{
			Name:       "fetch of denied path blocked",
			Req:        port.FetchRequest{Agent: "x", Repo: "r", Paths: []string{"secrets/api.key"}},
			Want:       port.VerdictDeny,
			WantReason: `fetch requests denied path "secrets/api.key" (matched pattern "secrets/**")`,
		},
		{
			Name: "fetch of clean path allowed",
			Req:  port.FetchRequest{Agent: "x", Repo: "r", Paths: []string{"src/main.go"}},
			Want: port.VerdictAllow,
		},
		{
			Name: "fetch with no paths allowed",
			Req:  port.FetchRequest{Agent: "x", Repo: "r"},
			Want: port.VerdictAllow,
		},
	})
}

func TestPathACL_RegisteredName(t *testing.T) {
	if got := newPathACL(nil).Name(); got != "path_acl" {
		t.Fatalf("Name() = %q, want path_acl", got)
	}
}

func TestPathACL_FactoryRegistered(t *testing.T) {
	f, ok := policy.LookupRule("path_acl")
	if !ok {
		t.Fatal("path_acl not registered in default registry")
	}
	r := f(policy.RuleConfig{Params: map[string]any{"deny": []string{"secrets/**"}}})
	if r.Name() != "path_acl" {
		t.Fatalf("factory produced %q, want path_acl", r.Name())
	}
}