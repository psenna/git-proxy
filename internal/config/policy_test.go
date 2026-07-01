package config

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
)

func TestParsePolicy(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
policy:
  mode: collect_all
  rules:
    history_protect:
      enabled: true
    branch_pattern:
      enabled: true
      agents: ["agent-1"]
      repos: ["team/repo.git"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Policy.Mode != "collect_all" {
		t.Errorf("mode = %q, want collect_all", c.Policy.Mode)
	}
	hp, ok := c.Policy.Rules["history_protect"]
	if !ok || !hp.Enabled {
		t.Errorf("history_protect not enabled: %+v", c.Policy.Rules)
	}
	bp := c.Policy.Rules["branch_pattern"]
	if !bp.Enabled || len(bp.Agents) != 1 || bp.Agents[0] != "agent-1" {
		t.Errorf("branch_pattern agents = %+v", bp.Agents)
	}
	if len(bp.Repos) != 1 || bp.Repos[0] != "team/repo.git" {
		t.Errorf("branch_pattern repos = %+v", bp.Repos)
	}
}

func TestPolicyToPolicyDefaultsFirstDeny(t *testing.T) {
	// Unknown/empty mode maps to FirstDeny (fail-closed default).
	p := PolicyConfig{Mode: "nonsense", Rules: map[string]RuleConfig{
		"r": {Enabled: true},
	}}.ToPolicy()
	if p.Mode != policy.FirstDeny {
		t.Errorf("mode = %v, want FirstDeny", p.Mode)
	}
	if got := p.Rules["r"]; !got.Enabled {
		t.Errorf("rule r not enabled: %+v", got)
	}
}

func TestPolicyToPolicyCollectAll(t *testing.T) {
	p := PolicyConfig{Mode: "collect_all"}.ToPolicy()
	if p.Mode != policy.CollectAll {
		t.Errorf("mode = %v, want CollectAll", p.Mode)
	}
}

func TestParsePolicyMirrorAndPush(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
policy:
  mirror:
    dir: "/var/cache/git-proxy/mirror"
  push:
    max_packfile_bytes: 134217728
  rules:
    history_protect:
      enabled: true
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Policy.Mirror.Dir != "/var/cache/git-proxy/mirror" {
		t.Errorf("mirror.dir = %q", c.Policy.Mirror.Dir)
	}
	if c.Policy.Push.MaxPackfileBytes != 134217728 {
		t.Errorf("push.max_packfile_bytes = %d, want 134217728", c.Policy.Push.MaxPackfileBytes)
	}
	if !c.Policy.HasEnabledRules() {
		t.Errorf("HasEnabledRules = false, want true (history_protect enabled)")
	}
	if got := c.Policy.MaxPackfileBytesOrDefault(); got != 134217728 {
		t.Errorf("MaxPackfileBytesOrDefault = %d, want 134217728", got)
	}
}

func TestPolicyHasEnabledRulesFalseOnEmpty(t *testing.T) {
	p := PolicyConfig{}
	if p.HasEnabledRules() {
		t.Errorf("empty policy HasEnabledRules = true, want false (passthrough)")
	}
	// A disabled rule does not count as enabled.
	p = PolicyConfig{Rules: map[string]RuleConfig{"r": {Enabled: false}}}
	if p.HasEnabledRules() {
		t.Errorf("disabled-only policy HasEnabledRules = true, want false")
	}
}

func TestPolicyMaxPackfileBytesDefault(t *testing.T) {
	p := PolicyConfig{}
	if got := p.MaxPackfileBytesOrDefault(); got != DefaultMaxPackfileBytes {
		t.Errorf("default = %d, want %d", got, DefaultMaxPackfileBytes)
	}
}

func TestParsePolicyReadDeny(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
policy:
  read:
    deny:
      - "secrets/**"
      - "*.env"
      - "config/production.yml"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Policy.Read.Deny) != 3 {
		t.Fatalf("read.deny = %v, want 3 entries", c.Policy.Read.Deny)
	}
	if !c.Policy.ReadDenyEnabled() {
		t.Errorf("ReadDenyEnabled = false, want true")
	}
	if bad := c.Policy.MalformedReadDenyPatterns(); len(bad) != 0 {
		t.Errorf("MalformedReadDenyPatterns = %v, want empty", bad)
	}
}

func TestReadDenyDisabledWhenAbsent(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Policy.ReadDenyEnabled() {
		t.Errorf("ReadDenyEnabled = true on absent read, want false (passthrough)")
	}
}

func TestMalformedReadDenyPatternsDetected(t *testing.T) {
	p := PolicyConfig{Read: ReadConfig{Deny: []string{"secrets/**", "[unclosed", "ok.env", "[also["}}}
	bad := p.MalformedReadDenyPatterns()
	if len(bad) != 2 {
		t.Fatalf("MalformedReadDenyPatterns = %v, want 2 ([unclosed, [also[)", bad)
	}
	// A blank pattern is NOT malformed (it means "nothing configured" and is
	// dropped by pathmatch.New), so it must not surface here.
	p2 := PolicyConfig{Read: ReadConfig{Deny: []string{"   ", ""}}}
	if bad := p2.MalformedReadDenyPatterns(); len(bad) != 0 {
		t.Errorf("blank patterns reported as malformed: %v", bad)
	}
	// ReadDenyEnabled is true for a non-empty Deny list even if all entries are
	// blank — the wiring layer must reject malformed configs before building a
	// matcher, so ReadDenyEnabled stays a pure "is it configured" check.
	if !p2.ReadDenyEnabled() {
		t.Errorf("blank-only Deny: ReadDenyEnabled = false, want true (configured)")
	}
}