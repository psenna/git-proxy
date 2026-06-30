package rules

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

const branchPatternName = "branch_pattern"

func init() {
	// Self-register so policy.Resolve can build the rule from config. The
	// factory decodes the rule's params block; an empty "allow" list means
	// "nothing permitted" → the rule denies all pushes (fail-closed for an
	// empty allow list, contrast with history_protect's allow-all on empty
	// refs).
	policy.RegisterRule(branchPatternName, func(cfg policy.RuleConfig) port.Rule {
		return newBranchPatternRule(cfg)
	})
}

// newBranchPatternRule builds a branch_pattern rule from its RuleConfig. It is
// the package-internal constructor used by both the factory and the tests.
func newBranchPatternRule(cfg policy.RuleConfig) port.Rule {
	return &branchPatternRule{
		allow: parseStringList(cfg.Params, "allow"),
	}
}

// branchPatternRule enforces allowed branch-name patterns for pushes. A push is
// allowed only if every ref it updates matches at least one allowed pattern.
// An empty allow list denies all pushes (fail-closed for "nothing permitted").
// It is a push-only rule: EvaluateFetch always allows.
type branchPatternRule struct {
	allow []string
}

func (r *branchPatternRule) Name() string { return branchPatternName }

func (r *branchPatternRule) EvaluatePush(req port.PushRequest) (port.Decision, error) {
	if len(r.allow) == 0 {
		return policy.Deny(r.Name(), "no branches are allowed (allow list is empty)"), nil
	}
	for _, u := range req.RefUpdates {
		if !matchAny(r.allow, u.Ref) {
			return policy.Deny(r.Name(), fmt.Sprintf("push to ref %q is not allowed by any allow pattern", u.Ref)), nil
		}
	}
	return policy.Allow(), nil
}

func (r *branchPatternRule) EvaluateFetch(port.FetchRequest) (port.Decision, error) {
	return policy.Allow(), nil
}
