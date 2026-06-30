// Package rules hosts the concrete push/fetch Rules. Each rule lives in its
// own file, implements port.Rule, and self-registers via init() calling
// policy.RegisterRule so the engine's Resolve can build it from config.
//
// Rules are pure: they perform no I/O, never invoke the git binary, and use no
// time or randomness. Fast-forward detection is a pre-computed Force bool in
// port.RefUpdate, not computed here.
package rules

import "path"

// matchAny reports whether ref matches any of the given patterns. Patterns use
// path.Match-style globs (a `*` matches any run of characters within a single
// path segment as defined by path.Match). An empty pattern set matches nothing.
// A malformed pattern is treated as never-matching (fail-safe: a bad config
// does not accidentally protect or allow a ref).
func matchAny(patterns []string, ref string) bool {
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if ok, err := path.Match(p, ref); err == nil && ok {
			return true
		}
	}
	return false
}

// parseStringList extracts a []string from params[key]. YAML decodes a list of
// scalars as []any, and a list of strings typed elsewhere as []string; both are
// accepted. Non-string entries are dropped. A missing or nil key yields nil.
func parseStringList(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	v, ok := params[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}