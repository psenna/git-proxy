package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/psenna/git-proxy/internal/port"
)

// Overall check-state roll-up values returned by Summary.
const (
	StateNone    = "none"    // no check runs and no workflow runs for the ref
	StatePending = "pending" // at least one run is queued/in_progress or has no conclusion yet
	StateFailure = "failure" // at least one run failed (failure, cancelled, timed_out, ...)
	StateSuccess = "success" // all runs completed with a passing conclusion
	StateUnknown = "unknown" // a run is in a state the roll-up cannot classify
)

// CheckSummary is the rest-internal roll-up of CI state for a ref. The github
// adapter maps it to port.CheckSummary. Overall is one of the State* constants.
type CheckSummary struct {
	Overall   string
	Checks    []CheckRun
	Workflows []WorkflowRun
	// ChecksUnavailable reports that the Checks-API leg (proxy→upstream) was
	// refused with a plain 403 and this summary was rolled up from the Actions
	// workflow-runs leg alone. It is a class flag about the proxy→upstream call
	// — it never carries an upstream response body, a token, or a URL, so it is
	// no-leak-permitted. When true, Checks is empty and Overall reflects only
	// the workflow runs (issue #95: a credential that can read Actions but not
	// Checks still gets an honest CI verdict rather than a 403).
	ChecksUnavailable bool
}

// ListCheckRuns returns the Checks-API check runs for ref (a SHA or branch
// name). GitHub REST: GET /repos/{owner}/{repo}/commits/{ref}/check-runs,
// following the Link header for pagination (max maxPages). The response is the
// GitHub envelope {"check_runs":[...]}; the slice is extracted page by page.
//
// ref is agent-controlled (it comes straight from the ci.status/ci.log broker
// routes) and MUST be escaped before it is spliced into the request path —
// security review finding H1. Verified without escaping: a percent-encoded
// dot-segment in ref (e.g. "%2e%2e") survives the broker's own routing
// unmolested and, with no escaping here, would reach GitHub as a literal
// "../" in the outbound path — a repo the agent isn't scoped to, read with
// the proxy's own credential. url.PathEscape neutralizes this: it escapes the
// "/" a traversal needs to move between path segments, so whatever ref
// contains stays inside this single path segment.
func (c *Client) ListCheckRuns(ctx context.Context, repo, ref string) ([]CheckRun, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/commits/%s/check-runs?per_page=100", p, url.PathEscape(ref))
	var out []CheckRun
	for i := 0; i < maxPages; i++ {
		var page checkRunsResponse
		resp, err := c.do(ctx, http.MethodGet, path, nil, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page.CheckRuns...)
		next, ok := parseNextLink(resp.Header.Get("Link"))
		if !ok {
			break
		}
		path = c.stripToPath(next)
	}
	return out, nil
}

// ListWorkflowRuns returns GitHub Actions workflow runs whose head SHA is ref.
// GitHub REST: GET /repos/{owner}/{repo}/actions/runs?head_sha={ref}, paginated.
// The response is the envelope {"workflow_runs":[...]}; the slice is extracted
// page by page. Callers that want branch-scoped runs can pass a branch name;
// the adapter chooses head_sha= for SHA refs (the gate-on-green case, where the
// agent has a concrete commit) and reserves branch= for a future follow-up.
//
// ref is agent-controlled and MUST be escaped before it is spliced into the
// query string — security review finding H1. Unescaped, an agent could
// inject additional query parameters (e.g. a "&" in ref) or truncate the
// fixed "&per_page=100" suffix (e.g. via "#"), taking control of the request
// GitHub receives with the proxy's own credential. url.QueryEscape is the
// correct escaper here (this is a query value, not a path segment).
func (c *Client) ListWorkflowRuns(ctx context.Context, repo, ref string) ([]WorkflowRun, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/actions/runs?head_sha=%s&per_page=100", p, url.QueryEscape(ref))
	var out []WorkflowRun
	for i := 0; i < maxPages; i++ {
		var page workflowRunsResponse
		resp, err := c.do(ctx, http.MethodGet, path, nil, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page.WorkflowRuns...)
		next, ok := parseNextLink(resp.Header.Get("Link"))
		if !ok {
			break
		}
		path = c.stripToPath(next)
	}
	return out, nil
}

// Summary returns the rolled-up CI state for ref: it lists check runs and
// workflow runs, then rolls them into a single Overall value. The precedence is
// failure > pending > success > unknown: a single failed run fails the whole
// ref; otherwise a single in-flight run makes it pending; otherwise, if every
// run completed with a passing conclusion, it is success. A ref with no runs
// at all is StateNone. The bundle (checks + workflows) is returned alongside so
// the adapter can surface the per-run detail to agents without a second call.
// Issue #95: a plain 403 on the Checks-API leg (the credential can read Actions
// but not Checks — a common fine-grained-PAT shape) no longer fails the whole
// call. Only errors.Is(err, port.ErrForbidden) triggers the Actions-only
// fallback; ErrUnauthorized (401), *RateLimitedError (403 + X-RateLimit-Remaining:
// 0, or 429), ErrNotFound, ErrUpstream, and transport/decode errors all
// propagate unchanged. When the Checks leg was forbidden the returned summary
// has ChecksUnavailable=true so the agent knows the check-run detail was
// withheld (even when the Actions leg then reports no runs → StateNone).
func (c *Client) Summary(ctx context.Context, repo, ref string) (CheckSummary, error) {
	checks, checksErr := c.ListCheckRuns(ctx, repo, ref)
	if checksErr != nil && !errors.Is(checksErr, port.ErrForbidden) {
		return CheckSummary{}, checksErr
	}
	workflows, wfErr := c.ListWorkflowRuns(ctx, repo, ref)
	if wfErr != nil {
		if checksErr != nil {
			return CheckSummary{}, forbiddenFallbackErr(checksErr, wfErr)
		}
		return CheckSummary{}, wfErr
	}
	s := rollupCI(checks, workflows)
	s.ChecksUnavailable = checksErr != nil
	return s, nil
}

// forbiddenFallbackErr picks the error to surface when the Checks leg was
// forbidden AND the Actions fallback leg also failed. If the fallback failed
// with only a plain 403 too, the credential can read neither family, so the
// ORIGINAL Checks error is returned — it is still ErrForbidden, so the broker
// maps it to today's 403 verbatim (no regression). Any richer fallback failure
// (a rate limit with its Retry-After, a 5xx, a transport error) propagates as
// itself so its class is not flattened into a bare 403.
func forbiddenFallbackErr(checksErr, fallbackErr error) error {
	if errors.Is(fallbackErr, port.ErrForbidden) {
		return checksErr
	}
	return fallbackErr
}

// rollupCI is the pure roll-up of CI state over check runs and workflow runs,
// separated from Summary so it is directly table-testable with no HTTP.
func rollupCI(checks []CheckRun, workflows []WorkflowRun) CheckSummary {
	s := CheckSummary{Checks: checks, Workflows: workflows}
	if len(checks) == 0 && len(workflows) == 0 {
		s.Overall = StateNone
		return s
	}
	var hasFailure, hasPending, hasSuccess bool
	for _, cr := range checks {
		switch classifyRun(cr.Status, cr.Conclusion) {
		case StateFailure:
			hasFailure = true
		case StatePending:
			hasPending = true
		case StateSuccess:
			hasSuccess = true
		}
	}
	for _, wr := range workflows {
		switch classifyRun(wr.Status, wr.Conclusion) {
		case StateFailure:
			hasFailure = true
		case StatePending:
			hasPending = true
		case StateSuccess:
			hasSuccess = true
		}
	}
	switch {
	case hasFailure:
		s.Overall = StateFailure
	case hasPending:
		s.Overall = StatePending
	case hasSuccess:
		s.Overall = StateSuccess
	default:
		s.Overall = StateUnknown
	}
	return s
}

// classifyRun maps a single run's (status, conclusion) to one of the roll-up
// states. A run whose status is not yet "completed" is pending. A completed
// run's conclusion decides failure vs success; an empty conclusion on a
// completed run is pending (GitHub has not reported a terminal result yet).
// Recognized passing conclusions are success, neutral, and skipped (GitHub
// branch protection treats these as non-blocking). Recognized failing
// conclusions are failure, cancelled, timed_out, action_required, and stale.
// Any other conclusion string yields StateUnknown (the roll-up does not guess).
func classifyRun(status, conclusion string) string {
	if status != "completed" {
		return StatePending
	}
	switch conclusion {
	case "":
		return StatePending
	case "success", "neutral", "skipped":
		return StateSuccess
	case "failure", "cancelled", "timed_out", "action_required", "stale":
		return StateFailure
	default:
		return StateUnknown
	}
}
