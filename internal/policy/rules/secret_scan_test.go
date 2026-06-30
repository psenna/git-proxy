package rules

import (
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/policy/ruletest"
	"github.com/psenna/git-proxy/internal/port"
)

func newSecretScan(params map[string]any) port.Rule {
	return newSecretScanRule(policy.RuleConfig{Params: params})
}

func TestSecretScan_DefaultOnDetects(t *testing.T) {
	// enabled:true with no custom config → scan with built-in defaults
	// (default-on security rule).
	rule := newSecretScan(nil)
	cases := []ruletest.PushCase{
		{
			Name: "aws key in pushed blob denied",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "github pat in pushed blob denied",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "tool.sh", Status: "M", BlobOID: "o2", Content: []byte("export T=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "clean blob allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "README.md", Status: "A", BlobOID: "o3", Content: []byte("# hello world\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "deleted file not scanned allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "old.txt", Status: "D"},
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

func TestSecretScan_ReasonDoesNotLeakSecret(t *testing.T) {
	rule := newSecretScan(nil)
	e := policy.NewEngine(policy.FirstDeny, rule)
	secret := "AKIAIOSFODNN7EXAMPLE"
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: " + secret + "\n")},
	}})
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", dec.Verdict)
	}
	for _, r := range dec.Reasons {
		if strings.Contains(r.Message, secret) {
			t.Errorf("deny reason leaks secret %q: %q", secret, r.Message)
		}
	}
}

func TestSecretScan_ExtraPatterns(t *testing.T) {
	rule := newSecretScan(map[string]any{
		"extra_patterns": []any{
			map[string]any{"regex": `company-token-[A-Z0-9]{12}`, "name": "company-token"},
		},
	})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "app.cfg", Status: "A", BlobOID: "o", Content: []byte("token: company-token-AB12CD34EF56\n")},
	}})
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny for extra pattern", dec.Verdict)
	}
	if !strings.Contains(dec.Reasons[0].Message, "company-token") {
		t.Fatalf("reason does not name the rule: %q", dec.Reasons[0].Message)
	}
}

func TestSecretScan_BadExtraPatternFailsClosed(t *testing.T) {
	rule := newSecretScan(map[string]any{
		"extra_patterns": []any{
			map[string]any{"regex": `[`, "name": "bad"},
		},
	})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "app.cfg", Status: "A", BlobOID: "o", Content: []byte("x")},
	}})
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny on bad extra pattern", dec.Verdict)
	}
}

func TestSecretScan_FetchAlwaysAllows(t *testing.T) {
	rule := newSecretScan(nil)
	ruletest.RunFetch(t, rule, []ruletest.FetchCase{
		{Name: "fetch allowed", Req: port.FetchRequest{Agent: "x", Repo: "r"}, Want: port.VerdictAllow},
	})
}

func TestSecretScan_RegisteredName(t *testing.T) {
	if got := newSecretScan(nil).Name(); got != "secret_scan" {
		t.Fatalf("Name() = %q, want secret_scan", got)
	}
}

func TestSecretScan_FactoryRegistered(t *testing.T) {
	f, ok := policy.LookupRule("secret_scan")
	if !ok {
		t.Fatal("secret_scan not registered in default registry")
	}
	r := f(policy.RuleConfig{})
	if r.Name() != "secret_scan" {
		t.Fatalf("factory produced %q, want secret_scan", r.Name())
	}
}