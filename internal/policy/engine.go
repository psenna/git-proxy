package policy

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/port"
)

// EvalMode controls how the engine combines verdicts from multiple rules.
type EvalMode int

const (
	// FirstDeny stops evaluation at the first rule that denies (or errors).
	// Subsequent rules are not evaluated. This is the default for push
	// enforcement where a single denial is sufficient to block.
	FirstDeny EvalMode = iota
	// CollectAll evaluates every applicable rule and aggregates all deny
	// reasons into the final Decision. Used when a full accounting of every
	// violated rule is wanted (e.g. dry-run / observe mode).
	CollectAll
)

// ruleEntry pairs a Rule with the agent/repo subset it applies to. An empty
// Agents slice means "all agents"; an empty Repos slice means "all repos".
type ruleEntry struct {
	rule   port.Rule
	agents map[string]struct{}
	repos  map[string]struct{}
}

// applies reports whether the rule should be evaluated for the given agent and
// repo. A rule that does not apply is skipped (treated as allow) — it is not a
// denial.
func (e ruleEntry) applies(agent, repo string) bool {
	if len(e.agents) > 0 {
		if _, ok := e.agents[agent]; !ok {
			return false
		}
	}
	if len(e.repos) > 0 {
		if _, ok := e.repos[repo]; !ok {
			return false
		}
	}
	return true
}

// Engine evaluates a pipeline of Rules against a push or fetch request and
// returns a single Decision. It is pure: it holds only rule instances and an
// evaluation mode, performs no I/O, and is safe to call concurrently.
type Engine struct {
	mode    EvalMode
	entries []ruleEntry
}

// NewEngine builds an Engine that applies rules in order to every request (no
// agent/repo filtering). Use Resolve to build an engine from config that
// restricts rules to specific agents/repos.
func NewEngine(mode EvalMode, rules ...port.Rule) *Engine {
	entries := make([]ruleEntry, len(rules))
	for i, r := range rules {
		entries[i] = ruleEntry{rule: r}
	}
	return &Engine{mode: mode, entries: entries}
}

func newFilteredEngine(mode EvalMode, entries []ruleEntry) *Engine {
	return &Engine{mode: mode, entries: entries}
}

// EvaluatePush evaluates the request against every applicable rule's push
// path. Fail-closed: a rule returning an error yields a deny. In FirstDeny
// mode the first deny short-circuits; in CollectAll mode all deny reasons are
// aggregated.
func (e *Engine) EvaluatePush(req port.PushRequest) port.Decision {
	var reasons []port.Reason
	denied := false
	for _, entry := range e.entries {
		if !entry.applies(req.Agent, req.Repo) {
			continue
		}
		dec, err := entry.rule.EvaluatePush(req)
		if err != nil {
			reasons = append(reasons, port.Reason{Rule: entry.rule.Name(), Message: errorMessage(err)})
			denied = true
			if e.mode == FirstDeny {
				return port.Decision{Verdict: port.VerdictDeny, Reasons: reasons}
			}
			continue
		}
		if dec.Verdict == port.VerdictDeny {
			denied = true
			reasons = append(reasons, dec.Reasons...)
			if e.mode == FirstDeny {
				return port.Decision{Verdict: port.VerdictDeny, Reasons: reasons}
			}
		}
	}
	if denied || len(reasons) > 0 {
		return port.Decision{Verdict: port.VerdictDeny, Reasons: reasons}
	}
	return port.Decision{Verdict: port.VerdictAllow}
}

// EvaluateFetch evaluates the request against every applicable rule's fetch
// path. Semantics mirror EvaluatePush.
func (e *Engine) EvaluateFetch(req port.FetchRequest) port.Decision {
	var reasons []port.Reason
	denied := false
	for _, entry := range e.entries {
		if !entry.applies(req.Agent, req.Repo) {
			continue
		}
		dec, err := entry.rule.EvaluateFetch(req)
		if err != nil {
			reasons = append(reasons, port.Reason{Rule: entry.rule.Name(), Message: errorMessage(err)})
			denied = true
			if e.mode == FirstDeny {
				return port.Decision{Verdict: port.VerdictDeny, Reasons: reasons}
			}
			continue
		}
		if dec.Verdict == port.VerdictDeny {
			denied = true
			reasons = append(reasons, dec.Reasons...)
			if e.mode == FirstDeny {
				return port.Decision{Verdict: port.VerdictDeny, Reasons: reasons}
			}
		}
	}
	if denied || len(reasons) > 0 {
		return port.Decision{Verdict: port.VerdictDeny, Reasons: reasons}
	}
	return port.Decision{Verdict: port.VerdictAllow}
}

func errorMessage(err error) string {
	if err == nil {
		return "evaluation error"
	}
	return err.Error()
}

// RuleFactory constructs a fresh instance of a Rule from its RuleConfig.
// Factories let the engine build per-request rule instances from a name keyed
// by config; a factory is registered once (typically from an init() in the
// rule's package) and may be invoked many times. The config carries the rule's
// Params block so the factory can decode rule-specific options (e.g. protected
// refs or allowed branch patterns).
type RuleFactory func(cfg RuleConfig) port.Rule

// Registry maps rule names to factories. The zero-value Registry is empty and
// ready to use. A package-level default registry is exposed via RegisterRule
// and Resolve so rule packages can self-register in init().
type Registry struct {
	factories map[string]RuleFactory
}

// NewRegistry returns an empty Registry. Tests use an isolated registry to
// avoid mutating the global registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[string]RuleFactory{}}
}

// Register adds a factory under name. Panics on duplicate registration to fail
// fast on conflicting init() blocks — a silent overwrite would hide a wiring
// bug.
func (r *Registry) Register(name string, f RuleFactory) {
	if r.factories == nil {
		r.factories = map[string]RuleFactory{}
	}
	if _, ok := r.factories[name]; ok {
		panic(fmt.Sprintf("policy: rule %q registered twice", name))
	}
	r.factories[name] = f
}

// Lookup returns the factory registered under name, or false if no rule is
// registered with that name.
func (r *Registry) Lookup(name string) (RuleFactory, bool) {
	f, ok := r.factories[name]
	return f, ok
}

// defaultRegistry is the package-level registry that rule packages attach to
// via init(). Resolve consults it when no explicit registry is supplied.
var defaultRegistry = NewRegistry()

// RegisterRule registers a factory on the default (package-level) registry.
// It is intended to be called from a rule package's init().
func RegisterRule(name string, f RuleFactory) {
	defaultRegistry.Register(name, f)
}

// RuleConfig enables a named rule and optionally restricts it to a subset of
// agents and/or repos. An empty Agents list means "all agents"; an empty Repos
// list means "all repos". Params is the rule-specific configuration mirrored
// verbatim from the YAML params block; a rule's factory decodes the keys it
// understands (e.g. history_protect's "refs", branch_pattern's "allow").
type RuleConfig struct {
	Enabled bool              `yaml:"enabled"`
	Agents  []string          `yaml:"agents"`
	Repos   []string          `yaml:"repos"`
	Params  map[string]any    `yaml:"params"`
}

// PolicyConfig selects the evaluation mode and which rules are enabled for
// which agents/repos. It is the policy section of the proxy config.
type PolicyConfig struct {
	Mode  EvalMode              `yaml:"mode"`
	Rules map[string]RuleConfig `yaml:"rules"`
}

// Resolve builds an Engine from config by looking up each enabled rule in the
// registry. Fail-closed: a rule referenced in config but not registered is an
// error (the proxy must not silently skip an unknown rule). If reg is nil, the
// package-level default registry is used.
func Resolve(cfg PolicyConfig, reg *Registry) (*Engine, error) {
	if reg == nil {
		reg = defaultRegistry
	}
	entries := make([]ruleEntry, 0, len(cfg.Rules))
	// Iterate is deterministic only if we sort keys; map order is random and
	// would make pipeline order nondeterministic. Sort for determinism.
	names := make([]string, 0, len(cfg.Rules))
	for name, rc := range cfg.Rules {
		if rc.Enabled {
			names = append(names, name)
		}
	}
	// Stable sort for deterministic rule ordering.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	for _, name := range names {
		f, ok := reg.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("policy: rule %q enabled in config but not registered", name)
		}
		rc := cfg.Rules[name]
		entry := ruleEntry{rule: f(rc)}
		if len(rc.Agents) > 0 {
			entry.agents = make(map[string]struct{}, len(rc.Agents))
			for _, a := range rc.Agents {
				entry.agents[a] = struct{}{}
			}
		}
		if len(rc.Repos) > 0 {
			entry.repos = make(map[string]struct{}, len(rc.Repos))
			for _, r := range rc.Repos {
				entry.repos[r] = struct{}{}
			}
		}
		entries = append(entries, entry)
	}
	return newFilteredEngine(cfg.Mode, entries), nil
}