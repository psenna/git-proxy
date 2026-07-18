package rest

import (
	"context"
	"fmt"
	"net/http"
)

// Overall check-state roll-up values returned by Summary.
const (
	StateNone    = "none"    // no check runs and no workflow runs for the ref
	StatePending = "pending" // at least one run is queued/in_progress or has no conclusion yet
	StateFailure = "failure" // at least one run failed (failure, cancelled, timed_out, ...)
	StateSuccess = "success" // all runs completed with a passing conclusion
	StateUnknown = "unknown"  // a run is in a state the roll-up cannot classify
)

// CheckSummary is the rest-internal roll-up of CI state for a ref. The github
// adapter maps it to port.CheckSummary. Overall is one of the State* constants.
type CheckSummary struct {
	Overall   string
	Checks    []CheckRun
	Workflows []WorkflowRun
}

// ListCheckRuns returns the Checks-API check runs for ref (a SHA or branch
// name). GitHub REST: GET /repos/{owner}/{repo}/commits/{ref}/check-runs,
// following the Link header for pagination (max maxPages). The response is the
// GitHub envelope {"check_runs":[...]}; the slice is extracted page by page.
func (c *Client) ListCheckRuns(ctx context.Context, repo, ref string) ([]CheckRun, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/commits/%s/check-runs?per_page=100", p, ref)
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
func (c *Client) ListWorkflowRuns(ctx context.Context, repo, ref string) ([]WorkflowRun, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/actions/runs?head_sha=%s&per_page=100", p, ref)
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
func (c *Client) Summary(ctx context.Context, repo, ref string) (CheckSummary, error) {
	checks, err := c.ListCheckRuns(ctx, repo, ref)
	if err != nil {
		return CheckSummary{}, err
	}
	workflows, err := c.ListWorkflowRuns(ctx, repo, ref)
	if err != nil {
		return CheckSummary{}, err
	}
	return rollupCI(checks, workflows), nil
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