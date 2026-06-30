package rules

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

const historyProtectName = "history_protect"

func init() {
	// Self-register so policy.Resolve can build the rule from config. The
	// factory decodes the rule's params block; a missing/empty "refs" list
	// means "no refs protected" → the rule allows everything (allow-all on
	// empty config; fail-closed applies to evaluation errors, not to
	// "nothing configured").
	policy.RegisterRule(historyProtectName, func(cfg policy.RuleConfig) port.Rule {
		return newHistoryProtectRule(cfg)
	})
}

// newHistoryProtectRule builds a history_protect rule from its RuleConfig. It is
// the package-internal constructor used by both the factory and the tests.
func newHistoryProtectRule(cfg policy.RuleConfig) port.Rule {
	return &historyProtectRule{
		refs: parseStringList(cfg.Params, "refs"),
	}
}

// historyProtectRule denies force-pushes and ref deletions on protected refs.
// Fast-forward updates (including creates and fast-forward updates to protected
// refs) are allowed, as are any updates to non-protected refs. It is a push-only
// rule: EvaluateFetch always allows.
type historyProtectRule struct {
	refs []string
}

func (r *historyProtectRule) Name() string { return historyProtectName }

func (r *historyProtectRule) EvaluatePush(req port.PushRequest) (port.Decision, error) {
	for _, u := range req.RefUpdates {
		if !matchAny(r.refs, u.Ref) {
			// Ref not protected: skip (no opinion).
			continue
		}
		if u.IsDelete() {
			return policy.Deny(r.Name(), fmt.Sprintf("ref deletion on protected ref %q is not allowed", u.Ref)), nil
		}
		if u.Force {
			return policy.Deny(r.Name(), fmt.Sprintf("force-push to protected ref %q is not allowed", u.Ref)), nil
		}
		// Fast-forward (including create): allow this ref, keep checking others.
	}
	return policy.Allow(), nil
}

func (r *historyProtectRule) EvaluateFetch(port.FetchRequest) (port.Decision, error) {
	return policy.Allow(), nil
}
