package config

import "github.com/psenna/git-proxy/internal/policy"

// PolicyConfig is the YAML-facing policy configuration. It mirrors
// policy.PolicyConfig but uses a string mode (so YAML reads naturally) and
// decouples the config layer from the engine's int constants. Rule enablement
// is per agent/repo: an empty Agents list means all agents; an empty Repos
// list means all repos.
type PolicyConfig struct {
	// Mode is "first_deny" (default) or "collect_all". An unknown value
	// resolves to first_deny (the fail-closed default).
	Mode  string               `yaml:"mode"`
	Rules map[string]RuleConfig `yaml:"rules"`
}

// RuleConfig enables a named rule and optionally restricts it to a subset of
// agents and/or repos. Params is the rule-specific configuration block decoded
// as a generic map and forwarded verbatim to the rule's factory.
type RuleConfig struct {
	Enabled bool           `yaml:"enabled"`
	Agents  []string       `yaml:"agents"`
	Repos   []string       `yaml:"repos"`
	Params  map[string]any `yaml:"params"`
}

// ToPolicy converts the YAML-facing policy config into the engine's
// policy.PolicyConfig. An unknown mode string maps to FirstDeny (fail-closed).
func (p PolicyConfig) ToPolicy() policy.PolicyConfig {
	mode := policy.FirstDeny
	if p.Mode == "collect_all" {
		mode = policy.CollectAll
	}
	rules := make(map[string]policy.RuleConfig, len(p.Rules))
	for name, rc := range p.Rules {
		rules[name] = policy.RuleConfig{
			Enabled: rc.Enabled,
			Agents:  rc.Agents,
			Repos:   rc.Repos,
			Params:  rc.Params,
		}
	}
	return policy.PolicyConfig{Mode: mode, Rules: rules}
}