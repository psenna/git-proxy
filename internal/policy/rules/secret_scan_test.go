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

// TestSecretScan_BuiltInIgnoresManifests verifies the built-in ignore set
// (go.sum, go.mod, common lockfiles) is never scanned. Each ignored file
// carries a realistic high-entropy integrity hash that WOULD trip the entropy
// heuristic if scanned — so an Allow here proves the path skip, not that the
// content is uninteresting. The control case (a real AWS key in a normal file)
// confirms scanning still fires for non-ignored files.
func TestSecretScan_BuiltInIgnoresManifests(t *testing.T) {
	// 44-char base64 (SHA256 of random bytes) — satisfies the {40,} length gate
	// and the >=4.5 entropy threshold, i.e. would be flagged "high-entropy".
	const h1Hash = "kL5mG9Tu2UmCEdvuy/e68d30gx6CuDlehax20oyW81o="
	// 88-char base64 (SHA512 of random bytes) — trips entropy the same way.
	const sha512 = "T3stW7cg0f93skE4ECPqzeED5T+dy3iaY3LbK3GVnaIGXCEsl+tbEJu9c53zVfpTGsZQcHrwYVvS5d9WS5WKOA=="
	rule := newSecretScan(nil)
	cases := []ruletest.PushCase{
		{
			Name: "go.sum with h1 integrity hash allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "go.sum", Status: "A", BlobOID: "o1", Content: []byte("gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 h1:" + h1Hash + "\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "go.mod with high-entropy run allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "go.mod", Status: "A", BlobOID: "o2", Content: []byte("module x\nrequire y v1.0.0 // " + h1Hash + "\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "package-lock.json with sha512 integrity allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "package-lock.json", Status: "A", BlobOID: "o3", Content: []byte(`{"integrity":"sha512-` + sha512 + `"}` + "\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "yarn.lock with hash allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "yarn.lock", Status: "A", BlobOID: "o4", Content: []byte("foo@1.0.0:\n  integrity sha512-" + sha512 + "\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "Cargo.lock with hash allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "Cargo.lock", Status: "A", BlobOID: "o5", Content: []byte("checksum = \"" + sha512 + "\"\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			// Control: a real secret in a non-ignored file must still be denied,
			// proving the ignore did not blanket-disable scanning.
			Name: "real secret in normal file still denied",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "config.yml", Status: "A", BlobOID: "o6", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
			}},
			Want: port.VerdictDeny,
		},
	}
	ruletest.RunPush(t, rule, cases)
}

// TestSecretScan_IgnoreMatchesAnyDepth confirms a no-"/" built-in pattern
// matches at any depth (pathmatch gitignore semantics), so a nested module's
// go.sum is also exempt.
func TestSecretScan_IgnoreMatchesAnyDepth(t *testing.T) {
	const h1Hash = "kL5mG9Tu2UmCEdvuy/e68d30gx6CuDlehax20oyW81o="
	rule := newSecretScan(nil)
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "nested sub/go.sum with h1 hash allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "sub/go.sum", Status: "A", BlobOID: "o1", Content: []byte("gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 h1:" + h1Hash + "\n")},
			}},
			Want: port.VerdictAllow,
		},
	})
}

// TestSecretScan_IgnorePathsExtends confirms ignore_paths ADDS to the built-ins
// (does not replace them, does not blanket-allow): an operator-added pattern is
// ignored, a non-ignored sibling with the same high-entropy content is still
// denied, and a built-in (go.sum) is still ignored even when ignore_paths is set.
func TestSecretScan_IgnorePathsExtends(t *testing.T) {
	const sha512 = "T3stW7cg0f93skE4ECPqzeED5T+dy3iaY3LbK3GVnaIGXCEsl+tbEJu9c53zVfpTGsZQcHrwYVvS5d9WS5WKOA=="
	rule := newSecretScan(map[string]any{"ignore_paths": []any{"foo.lock"}})
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "foo.lock (operator ignore_paths) allowed",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "foo.lock", Status: "A", BlobOID: "o1", Content: []byte("k " + sha512 + "\n")},
			}},
			Want: port.VerdictAllow,
		},
		{
			Name: "bar.lock (not ignored) denied by entropy",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "bar.lock", Status: "A", BlobOID: "o2", Content: []byte("k " + sha512 + "\n")},
			}},
			Want: port.VerdictDeny,
		},
		{
			Name: "go.sum (built-in) still allowed with custom ignore_paths",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "go.sum", Status: "A", BlobOID: "o3", Content: []byte("gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 h1:kL5mG9Tu2UmCEdvuy/e68d30gx6CuDlehax20oyW81o=\n")},
			}},
			Want: port.VerdictAllow,
		},
	})
}

// TestSecretScan_BadIgnorePatternFailsClosed mirrors
// TestSecretScan_BadExtraPatternFailsClosed: a malformed ignore_paths pattern
// must surface as a deny (the engine converts the rule's compileErr into a
// deny), never silently disable the ignore.
func TestSecretScan_BadIgnorePatternFailsClosed(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_paths": []any{"[unclosed"}})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "app.cfg", Status: "A", BlobOID: "o", Content: []byte("x")},
	}})
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny on bad ignore_paths pattern", dec.Verdict)
	}
}

// TestSecretScan_IgnoreStringsSuppressesPlaceholder: a secret whose raw value
// exactly matches an ignore_strings entry is allowed, with a masked allow
// reason naming the rule/path/line (never the raw value).
func TestSecretScan_IgnoreStringsSuppressesPlaceholder(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"AKIAIOSFODNN7EXAMPLE"}})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
	}})
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow (placeholder suppressed)", dec.Verdict)
	}
	if len(dec.Reasons) != 1 {
		t.Fatalf("reasons = %+v, want one masked allow reason", dec.Reasons)
	}
	if dec.Reasons[0].Rule != "secret_scan" {
		t.Fatalf("reason rule = %q, want secret_scan", dec.Reasons[0].Rule)
	}
	if !strings.Contains(dec.Reasons[0].Message, "ignored placeholder") {
		t.Fatalf("reason does not mark the placeholder: %q", dec.Reasons[0].Message)
	}
}

// TestSecretScan_IgnoreStringsMaskedReasonFormat pins the exact masked reason
// format: rule/path/line only, no raw value.
func TestSecretScan_IgnoreStringsMaskedReasonFormat(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"AKIAIOSFODNN7EXAMPLE"}})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
	}})
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow", dec.Verdict)
	}
	want := "secret_scan: ignored placeholder for rule aws-access-key-id at config.yml:1"
	if len(dec.Reasons) != 1 || dec.Reasons[0].Message != want {
		t.Fatalf("reasons = %+v, want message %q", dec.Reasons, want)
	}
}

// TestSecretScan_IgnoreStringsRealSecretStillDenied: an ignore_strings entry
// suppresses ONLY its exact match — a different real secret (a ghp_ PAT) is
// still denied.
func TestSecretScan_IgnoreStringsRealSecretStillDenied(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"AKIAIOSFODNN7EXAMPLE"}})
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "ghp pat not allowlisted denied",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "tool.sh", Status: "A", BlobOID: "o2", Content: []byte("export T=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")},
			}},
			Want: port.VerdictDeny,
		},
	})
}

// TestSecretScan_IgnoreStringsMixedPlaceholderAndReal: a push carrying both an
// allowlisted placeholder and a real secret is denied (first active finding
// wins — the allowlist never disables scanning).
func TestSecretScan_IgnoreStringsMixedPlaceholderAndReal(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"AKIAIOSFODNN7EXAMPLE"}})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
		{Path: "tool.sh", Status: "A", BlobOID: "o2", Content: []byte("export T=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")},
	}})
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny (real secret wins)", dec.Verdict)
	}
}

// TestSecretScan_IgnoreStringsDropsWhitespaceEntries: whitespace-only
// ignore_strings entries are dropped silently; a real entry still suppresses
// its exact match.
func TestSecretScan_IgnoreStringsDropsWhitespaceEntries(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"", "   ", "AKIAIOSFODNN7EXAMPLE"}})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
	}})
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow (whitespace entries dropped, real entry works)", dec.Verdict)
	}
	if len(dec.Reasons) != 1 {
		t.Fatalf("reasons = %+v, want one masked reason", dec.Reasons)
	}
}

// TestSecretScan_IgnoreStringsEmptyIsTodayBehavior: an empty ignore_strings
// list is today's behavior — the secret is still denied.
func TestSecretScan_IgnoreStringsEmptyIsTodayBehavior(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{}})
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "empty ignore_strings still denies",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
			}},
			Want: port.VerdictDeny,
		},
	})
}

// TestSecretScan_IgnoreStringsNoLeak: the masked allow reasons never contain the
// raw secret value (the no-leak contract).
func TestSecretScan_IgnoreStringsNoLeak(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"AKIAIOSFODNN7EXAMPLE"}})
	e := policy.NewEngine(policy.FirstDeny, rule)
	dec := e.EvaluatePush(port.PushRequest{ChangedFiles: []port.ChangedFile{
		{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
	}})
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow", dec.Verdict)
	}
	for _, r := range dec.Reasons {
		if strings.Contains(r.Message, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("allow reason leaks the raw secret %q: %q", "AKIAIOSFODNN7EXAMPLE", r.Message)
		}
	}
}

// TestSecretScan_IgnoreStringsDoesNotPartialMatch: a prefix entry ("AKIA")
// does not suppress the full key — the comparison is exact-match, so the push
// is still denied.
func TestSecretScan_IgnoreStringsDoesNotPartialMatch(t *testing.T) {
	rule := newSecretScan(map[string]any{"ignore_strings": []any{"AKIA"}})
	ruletest.RunPush(t, rule, []ruletest.PushCase{
		{
			Name: "prefix entry does not suppress full key",
			Req: port.PushRequest{ChangedFiles: []port.ChangedFile{
				{Path: "config.yml", Status: "A", BlobOID: "o1", Content: []byte("key: AKIAIOSFODNN7EXAMPLE\n")},
			}},
			Want: port.VerdictDeny,
		},
	})
}
