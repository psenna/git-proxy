package rules

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/pathmatch"
	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

const pathACLName = "path_acl"

func init() {
	// Self-register so policy.Resolve can build the rule from config. The
	// factory compiles the deny patterns into per-pattern matchers so the rule
	// can attribute a denial to the specific pattern that matched. An empty
	// deny list means allow-all (nothing denied). Malformed patterns are
	// dropped by pathmatch.New (fail-safe: never match, no panic) — this is
	// fail-open for that specific pattern but prevents a config typo from
	// breaking the whole rule; flagged for the reviewer.
	policy.RegisterRule(pathACLName, func(cfg policy.RuleConfig) port.Rule {
		return newPathACLRule(cfg)
	})
}

// newPathACLRule builds a path_acl rule from its RuleConfig. It is the
// package-internal constructor used by both the factory and the tests.
func newPathACLRule(cfg policy.RuleConfig) port.Rule {
	deny := parseStringList(cfg.Params, "deny")
	matchers := make([]denyMatcher, 0, len(deny))
	for _, p := range deny {
		matchers = append(matchers, denyMatcher{pattern: p, m: pathmatch.New([]string{p})})
	}
	return &pathACLRule{matchers: matchers}
}

// denyMatcher pairs a raw pattern string with its compiled matcher so a denial
// can name the pattern that triggered it.
type denyMatcher struct {
	pattern string
	m       *pathmatch.Matcher
}

// pathACLRule denies pushes/fetches that touch denied file paths. It uses the
// shared gitignore-style path matcher (internal/pathmatch) so push (changed
// files) and fetch (requested paths) share one matching implementation. It is
// a push+fetch rule.
type pathACLRule struct {
	matchers []denyMatcher
}

func (r *pathACLRule) Name() string { return pathACLName }

func (r *pathACLRule) EvaluatePush(req port.PushRequest) (port.Decision, error) {
	for _, f := range req.ChangedFiles {
		if pat, ok := r.matchingPattern(f.Path); ok {
			return policy.Deny(r.Name(), fmt.Sprintf(
				"push touches denied path %q (matched pattern %q)", f.Path, pat)), nil
		}
	}
	return policy.Allow(), nil
}

func (r *pathACLRule) EvaluateFetch(req port.FetchRequest) (port.Decision, error) {
	// Task 9 populates FetchRequest.Paths; the matcher is genuinely shared
	// push+fetch. Deny if any requested path matches a deny pattern.
	for _, p := range req.Paths {
		if pat, ok := r.matchingPattern(p); ok {
			return policy.Deny(r.Name(), fmt.Sprintf(
				"fetch requests denied path %q (matched pattern %q)", p, pat)), nil
		}
	}
	return policy.Allow(), nil
}

// matchingPattern returns the first deny pattern that matches path, for
// attribution in the denial reason.
func (r *pathACLRule) matchingPattern(path string) (string, bool) {
	for _, dm := range r.matchers {
		if dm.m.Match(path) {
			return dm.pattern, true
		}
	}
	return "", false
}