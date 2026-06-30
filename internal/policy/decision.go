// Package policy implements the pure policy engine that evaluates a git
// request against a registered set of Rules and returns a Decision.
//
// The engine is deterministic and performs no I/O. Rules register themselves
// by name via a factory; config selects which rules apply to which agent/repo.
// Evaluation is fail-closed: a rule that returns an error, or a config that
// references an unknown rule, denies the request rather than silently allowing
// it.
package policy

import "github.com/psenna/git-proxy/internal/port"

// Allow is the zero-value Decision: no deny reasons, verdict allow. Rules
// return this (with a nil error) to permit a request.
func Allow() port.Decision { return port.Decision{Verdict: port.VerdictAllow} }

// Deny builds a deny Decision carrying a single Reason attributed to rule.
func Deny(rule, message string) port.Decision {
	return port.Decision{
		Verdict: port.VerdictDeny,
		Reasons: []port.Reason{{Rule: rule, Message: message}},
	}
}

// DenyFromError builds a fail-closed deny Decision for a rule that returned an
// error during evaluation. The error's message is preserved as the Reason.
func DenyFromError(rule string, err error) port.Decision {
	msg := "evaluation error"
	if err != nil {
		msg = err.Error()
	}
	return Deny(rule, msg)
}