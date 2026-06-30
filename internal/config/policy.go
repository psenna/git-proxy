package config

import "github.com/psenna/git-proxy/internal/policy"

// PolicyConfig is the YAML-facing policy configuration. It mirrors
// policy.PolicyConfig but uses a string mode (so YAML reads naturally) and
// decouples the config layer from the engine's int constants. Rule enablement
// is per agent/repo: an empty Agents list means all agents; an empty Repos
// list means all repos.
//
// Mirror and Push carry the enforcement-side knobs the engine itself does not
// need (the engine stays pure): the mirror cache root and the receive-pack
// request size cap. They are consumed by the wiring in cmd/git-proxy.
type PolicyConfig struct {
	// Mode is "first_deny" (default) or "collect_all". An unknown value
	// resolves to first_deny (the fail-closed default).
	Mode  string               `yaml:"mode"`
	Rules map[string]RuleConfig `yaml:"rules"`
	// Mirror configures the read-only inspection mirror cache. Mirror.Dir is
	// required when any rule is enabled (the proxy needs a place to clone the
	// upstream for ancestry walks). It is ignored in passthrough mode.
	Mirror MirrorConfig `yaml:"mirror"`
	// Push configures receive-pack enforcement limits.
	Push PushConfig `yaml:"push"`
}

// MirrorConfig configures the inspection mirror cache.
type MirrorConfig struct {
	// Dir is the filesystem root under which bare mirrors are cached, one
	// sub-directory per upstream repo (named after the repo slug). Required
	// when policy is on; tests use t.TempDir().
	Dir string `yaml:"dir"`
}

// PushConfig configures receive-pack (push) enforcement limits.
type PushConfig struct {
	// MaxPackfileBytes is the maximum receive-pack request body size the proxy
	// buffers and inspects. A push larger than this is denied fail-closed
	// (never forwarded uninspected). Default 256 MiB (268435456) when <= 0.
	MaxPackfileBytes int64 `yaml:"max_packfile_bytes"`
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

// DefaultMaxPackfileBytes is the default receive-pack request body size cap
// (256 MiB) when Push.MaxPackfileBytes is not set.
const DefaultMaxPackfileBytes int64 = 256 << 20

// ToPolicy converts the YAML-facing policy config into the engine's
// policy.PolicyConfig. An unknown mode string maps to FirstDeny (fail-closed).
// Mirror and Push are not carried into the engine (it is pure); they are read
// directly from PolicyConfig by the wiring layer.
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

// HasEnabledRules reports whether any rule in the policy is enabled. The proxy
// stays passthrough (no mirror, no enforcement) when this is false, preserving
// the existing unauthenticated/passthrough behavior when policy is unconfigured.
func (p PolicyConfig) HasEnabledRules() bool {
	for _, rc := range p.Rules {
		if rc.Enabled {
			return true
		}
	}
	return false
}

// MaxPackfileBytesOrDefault returns the configured push size cap, or the
// default (256 MiB) when it is <= 0.
func (p PolicyConfig) MaxPackfileBytesOrDefault() int64 {
	if p.Push.MaxPackfileBytes > 0 {
		return p.Push.MaxPackfileBytes
	}
	return DefaultMaxPackfileBytes
}