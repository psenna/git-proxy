package config

import (
	"github.com/psenna/git-proxy/internal/pathmatch"
	"github.com/psenna/git-proxy/internal/policy"
)

// PolicyConfig is the YAML-facing policy configuration. It mirrors
// policy.PolicyConfig but uses a string mode (so YAML reads naturally) and
// decouples the config layer from the engine's int constants. Rule enablement
// is per agent/repo: an empty Agents list means all agents; an empty Repos
// list means all repos.
//
// Mirror and Push carry the enforcement-side knobs the engine itself does not
// need (the engine stays pure): the mirror cache root and the receive-pack
// request size cap. Read carries the proxy-level fetch read-protection path
// matcher (NOT an engine rule). They are consumed by the wiring in cmd/git-proxy.
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
	// Read configures proxy-level fetch read-protection (object withholding on
	// clone/fetch). This is a PROXY-LEVEL per-path filter (pathmatch), NOT an
	// engine rule: the proxy assembles the packfile and omits blobs whose path
	// matches Read.Deny. Empty/absent Read → read protection OFF → passthrough
	// (the proxy forwards to the upstream, which speaks whatever the client
	// negotiated). The same gitignore-style matcher as the push path_acl rule.
	Read ReadConfig `yaml:"read"`
	// DryRun enables dry-run mode: the proxy FORWARDS a clean engine push-deny
	// (instead of writing the deny response) and records the TRUE verdict
	// (deny) with DryRun=true, so teams observe violations before turning on
	// enforcement. Default false (enforce-on-deny — today's behavior). Dry-run
	// softens POLICY denies only, NOT inspection failures (mirror/ancestry/
	// ingest/parse errors still fail-closed). Read-protection dry-run is OUT of
	// v1 scope (read protection withholds regardless of dry-run). The engine
	// stays pure — it returns the true verdict; dry-run is a proxy-level
	// concern wired via SetDryRun in main.go (NOT in the engine).
	//
	// Recommended pairing: mode: collect_all + dry_run: true is the
	// observe-everything configuration (collect_all reports every violation
	// rather than short-circuiting on the first, so a dry-run log shows the
	// full set of violations a push triggers — useful for staged rollout).
	DryRun bool `yaml:"dry_run"`
}

// ReadConfig configures proxy-level read protection on fetch/clone. When Deny
// is non-empty, the proxy assembles the served packfile and withholds blobs
// whose path matches any Deny pattern (commits and trees are kept). A nil/empty
// Deny list means read protection is OFF (passthrough).
type ReadConfig struct {
	// Deny is a list of gitignore-style path patterns (via internal/pathmatch)
	// matching blob paths to withhold from the served packfile. A malformed
	// pattern (e.g. an unclosed `[`) is rejected at config load time so a typo
	// fails closed rather than silently allowing everything through.
	Deny []string `yaml:"deny"`
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

// ReadDenyEnabled reports whether read protection is configured (a non-empty
// Deny list). When false the proxy stays passthrough on fetch (no mirror
// assembly, no advertisement rewrite).
func (p PolicyConfig) ReadDenyEnabled() bool {
	return len(p.Read.Deny) > 0
}

// MalformedReadDenyPatterns returns the Read.Deny patterns that are structurally
// malformed (per pathmatch.IsMalformed). A non-empty result means the config is
// invalid: the wiring layer must fail closed at startup rather than build a
// matcher that silently drops the malformed pattern (which would under-protect
// — a typo'd deny pattern must not become "deny nothing"). Blank patterns are
// NOT malformed (they mean "nothing configured" and are dropped by pathmatch.New
// as a no-op), so they do not appear here.
func (p PolicyConfig) MalformedReadDenyPatterns() []string {
	var bad []string
	for _, pat := range p.Read.Deny {
		if pathmatch.IsMalformed(pat) {
			bad = append(bad, pat)
		}
	}
	return bad
}

// ReadDenyMatcher builds the pathmatch.Matcher for Read.Deny, or returns nil
// when read protection is OFF (empty Deny). The caller MUST call
// MalformedReadDenyPatterns first and fail closed at startup on a non-empty
// result; this method does not re-validate (pathmatch.New drops malformed
// patterns fail-safe, which would under-protect a typo'd config).
func (p PolicyConfig) ReadDenyMatcher() *pathmatch.Matcher {
	if !p.ReadDenyEnabled() {
		return nil
	}
	return pathmatch.New(p.Read.Deny)
}