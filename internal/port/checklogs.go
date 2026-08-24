package port

import "context"

// CheckLogSupport is an OPTIONAL capability sub-interface an Upstream MAY
// implement when the provider can serve raw job log text for a CI check (e.g.
// GitHub Actions job logs behind the Checks API). The proxy core NEVER depends
// on it: it is a seam the agent-facing broker (internal/broker) type-asserts
// off the SAME SCM upstream that backs PRSupport/Checks — unlike IssueSupport,
// there is no separate "check-log upstream" config, since the log is always
// sourced from wherever the check run itself came from.
//
// Code that wants to use it must type-assert:
//
//	if cls, ok := scmUp.(CheckLogSupport); ok { ... }
//
// Because a GitHub adapter always implements this capability (the method
// exists on *Adapter unconditionally), the broker additionally gates the
// route behind an explicit deployment-level opt-in (config.broker.allow_check_logs)
// rather than relying on the type-assert alone — log text can itself contain
// sensitive output a build step echoed, so exposing it is a deliberate operator
// decision distinct from exposing pass/fail status (port.PRSupport.Checks).
//
// No-leak / fail-closed: implementations attach the provider token ONLY on the
// proxy→provider leg (never to the agent), and the redirect to a signed
// log-archive URL (GitHub's job-logs endpoint 302s to one) must NOT carry the
// proxy's token. The sentinel errors an implementation returns are the generic
// ones in errors.go; they never echo the upstream response body.
type CheckLogSupport interface {
	// CheckLog returns the (tail-truncated at maxBytes) raw log text for the
	// job backing the check run named checkName on ref. checkName matches a
	// check-run's Name from the checks/{ref} route (port.PRSupport.Checks).
	// Zero matching check-runs, or a check-run not backed by a fetchable job
	// log (e.g. a third-party check app), returns ErrNotFound.
	CheckLog(ctx context.Context, repo, ref, checkName string, maxBytes int64) (CheckLog, error)
}

// CheckLog is the raw log text for one check run, tail-truncated at the
// caller-supplied maxBytes. The JSON tags let the broker serialize it directly
// as the ci.log response.
type CheckLog struct {
	// Log is the (possibly tail-truncated) raw log text.
	Log string `json:"log"`
	// Truncated is true when Log was cut down from a larger log (the TAIL is
	// kept, matching the common case of wanting to see how a job failed).
	Truncated bool `json:"truncated"`
}
