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