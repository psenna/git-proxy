package preflight

import "fmt"

// ProberFactory builds a Prober for a given upstream URL. It is the preflight
// counterpart of upstream.UpstreamFactory: a provider package (e.g.
// internal/upstream/github) self-registers one in init() keyed by the same
// kind string config uses for upstream.kind.
type ProberFactory func(upstreamURL string) (Prober, error)

// Registry maps a provider kind to its ProberFactory. The zero value is not
// usable; use the package-level Register/ProberFor which back a default
// registry, mirroring internal/upstream/registry.go.
type registry struct {
	factories map[string]ProberFactory
}

var defaultRegistry = &registry{factories: map[string]ProberFactory{}}

// Register adds a factory under kind on the default registry. It panics on a
// duplicate registration to fail fast on conflicting init() blocks, matching
// upstream.Register.
func Register(kind string, f ProberFactory) {
	if _, ok := defaultRegistry.factories[kind]; ok {
		panic(fmt.Sprintf("preflight: kind %q registered twice", kind))
	}
	defaultRegistry.factories[kind] = f
}

// ProberFor resolves the prober for kind and builds it for upstreamURL.
//
//	ok=false, err=nil  -> no prober registered for kind; the caller skips the
//	                      preflight for that leg silently (not every provider
//	                      has a prober, and that is fine — the preflight is a
//	                      diagnostic).
//	ok=true,  err!=nil -> the factory failed; the caller logs and skips.
//	ok=true,  err=nil  -> use the returned Prober.
func ProberFor(kind, upstreamURL string) (Prober, bool, error) {
	f, ok := defaultRegistry.factories[kind]
	if !ok {
		return nil, false, nil
	}
	p, err := f(upstreamURL)
	if err != nil {
		return nil, true, err
	}
	return p, true, nil
}
