// Package upstream holds the upstream/SCM adapter registry — the upstream
// counterpart of the policy rule registry (internal/policy/engine.go). Adapters
// implement port.Upstream and self-register via init(); config selects an
// adapter by Kind (default "plain"), the registry resolves the factory, and the
// factory builds the adapter. Fail-closed: an unknown Kind is a startup error
// (no silent fallback).
//
// UpstreamConfig is the registry's config type. It lives here (in the consumer
// package), mirroring how the rule registry's RuleConfig lives in
// internal/policy. internal/config stays a pure YAML leaf: it does NOT import
// this package (no config→upstream→port cycle). main.go maps the YAML-shaped
// config.UpstreamConfig into this UpstreamConfig and calls Build.
package upstream

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/port"
)

// UpstreamConfig is the registry's config type: the inputs a factory needs to
// build an adapter. main.go constructs it from the YAML-shaped
// config.UpstreamConfig (mapping Kind + URL + the loaded CredentialStore).
// Params carries adapter-specific options (currently unused by the plain and
// github skeletons; reserved for future adapters).
type UpstreamConfig struct {
	// Kind selects the adapter by registry name. Empty means "plain" (the
	// default, backward-compatible). An unknown Kind fails at Build with an
	// error (fail-closed — no silent fallback).
	Kind string
	// URL is the upstream git server base URL (e.g. "https://git.example.com").
	URL string
	// CredentialsStore is the loaded upstream credential vault the proxy
	// attaches on the proxy→upstream leg. May be nil (no credentials —
	// passthrough). main.go loads it once (as today) and passes it in so every
	// adapter built from the same config shares one store.
	CredentialsStore port.CredentialStore
	// Params is reserved for adapter-specific configuration (mirror of policy
	// RuleConfig.Params). Currently unused by plain/github; future adapters
	// may decode keys they understand.
	Params map[string]any
}

// UpstreamFactory constructs an Upstream from its config. It is the upstream
// counterpart of policy.RuleFactory: config selects an adapter by Kind, the
// registry resolves the factory, and the factory builds the adapter. The
// factory may return an error (e.g. malformed params); Build propagates it
// fail-fast at startup.
type UpstreamFactory func(cfg UpstreamConfig) (port.Upstream, error)

// Registry maps adapter names to factories. The zero-value Registry is empty
// and ready to use. A package-level default registry is exposed via Register
// and Build so adapter packages can self-register in init().
type Registry struct {
	factories map[string]UpstreamFactory
}

// NewRegistry returns an empty Registry. Tests use an isolated registry to
// avoid mutating the global registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[string]UpstreamFactory{}}
}

// Register adds a factory under name. Panics on duplicate registration to fail
// fast on conflicting init() blocks — a silent overwrite would hide a wiring
// bug. Mirrors policy.Registry.Register.
func (r *Registry) Register(name string, f UpstreamFactory) {
	if r.factories == nil {
		r.factories = map[string]UpstreamFactory{}
	}
	if _, ok := r.factories[name]; ok {
		panic(fmt.Sprintf("upstream: kind %q registered twice", name))
	}
	r.factories[name] = f
}

// Lookup returns the factory registered under name, or false if no adapter is
// registered with that name.
func (r *Registry) Lookup(name string) (UpstreamFactory, bool) {
	f, ok := r.factories[name]
	return f, ok
}

// Build resolves the adapter for cfg.Kind and constructs it. The empty Kind
// defaults to "plain" (backward compatible). An unknown Kind fails closed
// with an error (no silent fallback). A factory error propagates fail-fast.
func (r *Registry) Build(cfg UpstreamConfig) (port.Upstream, error) {
	kind := cfg.Kind
	if kind == "" {
		kind = "plain"
	}
	f, ok := r.Lookup(kind)
	if !ok {
		return nil, fmt.Errorf("upstream: unknown kind %q", kind)
	}
	cfg.Kind = kind
	return f(cfg)
}

// defaultRegistry is the package-level registry that adapter packages attach to
// via init(). Build/Lookup/Register consult it when no explicit registry is
// supplied.
var defaultRegistry = NewRegistry()

// Register registers a factory on the default (package-level) registry. It is
// intended to be called from an adapter package's init().
func Register(name string, f UpstreamFactory) {
	defaultRegistry.Register(name, f)
}

// Lookup returns the factory registered under name on the default registry, or
// false if no adapter is registered with that name. It is the read-side
// counterpart to Register.
func Lookup(name string) (UpstreamFactory, bool) {
	return defaultRegistry.Lookup(name)
}

// Build resolves the adapter for cfg.Kind on the default registry and
// constructs it. See Registry.Build for the empty-default and fail-closed
// semantics.
func Build(cfg UpstreamConfig) (port.Upstream, error) {
	return defaultRegistry.Build(cfg)
}