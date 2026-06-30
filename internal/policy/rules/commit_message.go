package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

const commitMessageName = "commit_message"

func init() {
	// Self-register so policy.Resolve can build the rule from config. The
	// factory pre-compiles deny_regex patterns; a compile error is stored on
	// the rule and surfaced as an evaluation error (fail-closed) so a bad regex
	// in config never silently disables the rule. require_prefix is a plain
	// string-prefix check (no regex). Empty config (both lists empty) means
	// allow-all — nothing is enforced.
	policy.RegisterRule(commitMessageName, func(cfg policy.RuleConfig) port.Rule {
		return newCommitMessageRule(cfg)
	})
}

// newCommitMessageRule builds a commit_message rule from its RuleConfig. It is
// the package-internal constructor used by both the factory and the tests.
func newCommitMessageRule(cfg policy.RuleConfig) port.Rule {
	r := &commitMessageRule{
		requirePrefix: parseStringList(cfg.Params, "require_prefix"),
		denyPatterns:  parseStringList(cfg.Params, "deny_regex"),
	}
	// Pre-compile deny regexes at factory time. A compile error is stored and
	// returned from EvaluatePush so the engine denies fail-closed rather than
	// silently skipping a misconfigured deny rule. This is the documented
	// regex-compile-error policy for commit_message.
	for _, p := range r.denyPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			r.compileErr = fmt.Errorf("commit_message: bad deny_regex %q: %w", p, err)
			break
		}
		r.denyREs = append(r.denyREs, re)
	}
	return r
}

// commitMessageRule enforces commit-message conventions on the NEW commits of a
// push: an optional required-prefix list for the subject and an optional deny
// regex list. It is a push-only rule: EvaluateFetch always allows.
type commitMessageRule struct {
	requirePrefix []string
	denyPatterns  []string
	denyREs       []*regexp.Regexp
	compileErr    error // set when a deny_regex failed to compile
}

func (r *commitMessageRule) Name() string { return commitMessageName }

func (r *commitMessageRule) EvaluatePush(req port.PushRequest) (port.Decision, error) {
	if r.compileErr != nil {
		// Fail-closed: a bad deny_regex in config must not silently disable the
		// rule. Return the error so the engine denies.
		return port.Decision{}, r.compileErr
	}
	for _, c := range req.Commits {
		subject := commitSubject(c.Message)
		if len(r.requirePrefix) > 0 && !hasAnyPrefix(subject, r.requirePrefix) {
			return policy.Deny(r.Name(), fmt.Sprintf(
				"commit %s subject %q does not start with any required prefix", c.SHA, subject)), nil
		}
		for i, re := range r.denyREs {
			if re.MatchString(subject) {
				return policy.Deny(r.Name(), fmt.Sprintf(
					"commit %s subject %q matches deny regex %q", c.SHA, subject, r.denyPatterns[i])), nil
			}
		}
	}
	return policy.Allow(), nil
}

func (r *commitMessageRule) EvaluateFetch(port.FetchRequest) (port.Decision, error) {
	return policy.Allow(), nil
}

// commitSubject returns the first line of a commit message (the subject).
func commitSubject(msg string) string {
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		return msg[:i]
	}
	return msg
}

// hasAnyPrefix reports whether s starts with any of the given prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}