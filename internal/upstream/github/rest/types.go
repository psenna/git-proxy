package rest

import "encoding/json"

// types.go holds the rest-internal shapes of the GitHub REST payloads the client
// decodes. These are NOT the port-level types (port.PRState, port.CheckSummary):
// the github adapter (internal/upstream/github) maps these rest types to the
// port types so the rest package stays a pure GitHub client with no port
// dependency for its response shapes (it imports port only for sentinel errors).

// PR is the GitHub REST pull-request payload as the rest client exposes it. It
// carries only the fields an agent needs; no internal GitHub fields leak beyond
// those listed. Mergeable is a pointer because GitHub returns null while it is
// still computing the mergeability state.
type PR struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	State     string `json:"state"` // "open" | "closed"
	Mergeable *bool  `json:"mergeable"`
	Head      string `json:"-"` // populated from head.ref below
	Base      string `json:"-"` // populated from base.ref below
	URL       string `json:"html_url"`
}

// prHeadBase is the inner shape GitHub uses for a PR's head/base objects; the
// client decodes into this and copies the ref names onto PR.Head/Base so the
// rest type stays flat for callers.
type prHeadBase struct {
	Ref string `json:"ref"`
}

// prPayload is the full decoded PR response; the client flattens head/base.
type prPayload struct {
	Number    int        `json:"number"`
	Title     string     `json:"title"`
	State     string     `json:"state"`
	Mergeable *bool      `json:"mergeable"`
	Head      prHeadBase `json:"head"`
	Base      prHeadBase `json:"base"`
	HTMLURL   string     `json:"html_url"`
}

// toPR flattens a prPayload into a PR.
func (p prPayload) toPR() PR {
	return PR{
		Number:    p.Number,
		Title:     p.Title,
		State:     p.State,
		Mergeable: p.Mergeable,
		Head:      p.Head.Ref,
		Base:      p.Base.Ref,
		URL:       p.HTMLURL,
	}
}

// createPRRequest is the body of POST /repos/{owner}/{repo}/pulls.
type createPRRequest struct {
	Head  string `json:"head"`
	Base  string `json:"base"`
	Title string `json:"title"`
}

// mergePRRequest is the body of PUT /repos/{owner}/{repo}/pulls/{n}/merge.
type mergePRRequest struct {
	MergeMethod string `json:"merge_method"`
}

// reviewRequest is the body of POST /repos/{owner}/{repo}/pulls/{n}/reviews.
type reviewRequest struct {
	Event string `json:"event"`
	Body  string `json:"body"`
}

// commentRequest is the body of POST /repos/{owner}/{repo}/issues/{n}/comments.
type commentRequest struct {
	Body string `json:"body"`
}

// CheckRun is a single GitHub check run (e.g. a CI job from the Checks API).
type CheckRun struct {
	Name       string `json:"name"`
	Status     string `json:"status"`     // queued | in_progress | completed
	Conclusion string `json:"conclusion"` // success | failure | neutral | cancelled | skipped | timed_out | "" (when not completed)
}

// checkRunsResponse is the paginated /commits/{ref}/check-runs envelope.
type checkRunsResponse struct {
	CheckRuns []CheckRun `json:"check_runs"`
}

// WorkflowRun is a single GitHub Actions workflow run.
type WorkflowRun struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HTMLURL    string `json:"html_url"`
}

// workflowRunsResponse is the paginated /actions/runs envelope.
type workflowRunsResponse struct {
	WorkflowRuns []WorkflowRun `json:"workflow_runs"`
}

// Issue is the GitHub REST issue payload as the rest client exposes it for the
// create-side result (number + url). It is the rest-internal counterpart of
// port.Issue; the github adapter maps it. It carries only the fields an agent
// needs immediately after filing — no internal GitHub fields leak beyond those.
type Issue struct {
	// Number is the GitHub issue number.
	Number int `json:"number"`
	// URL is the HTML URL of the issue.
	URL string `json:"html_url"`
}

// IssueState is the full state of an issue as GetIssue/ListIssues/EditIssue
// return it. It is the rest-internal counterpart of port.IssueState; the github
// adapter maps it. Labels is the list of label names (flat []string, not
// GitHub's label objects), normalized to a non-nil empty slice when there are
// none so the JSON renders [] not null.
type IssueState struct {
	// Number is the GitHub issue number.
	Number int `json:"number"`
	// Title is the issue title.
	Title string `json:"title"`
	// State is "open" or "closed".
	State string `json:"state"`
	// Body is the issue body (markdown), if any.
	Body string `json:"body"`
	// URL is the HTML URL of the issue.
	URL string `json:"html_url"`
	// Labels is the list of label names on the issue.
	Labels []string `json:"labels"`
}

// issueLabel is GitHub's label-object shape inside an issue payload. The REST
// API returns labels as objects ({name,color,...}); the client keeps only the
// name and flattens to []string for callers.
type issueLabel struct {
	Name string `json:"name"`
}

// issuePayload is the full decoded issue response. It is the raw GitHub shape
// (labels as objects); toIssueState flattens it into the caller-facing
// IssueState. PullRequest is the raw "pull_request" field GitHub attaches to
// PRs (GitHub models every PR as an issue): when present and non-null the entry
// is a PR, not an issue, so ListIssues filters it out.
type issuePayload struct {
	Number      int            `json:"number"`
	Title       string         `json:"title"`
	State       string         `json:"state"`
	Body        string         `json:"body"`
	HTMLURL     string         `json:"html_url"`
	Labels      []issueLabel   `json:"labels"`
	PullRequest json.RawMessage `json:"pull_request"`
}

// toIssue flattens an issuePayload into the create-side Issue result.
func (p issuePayload) toIssue() Issue {
	return Issue{
		Number: p.Number,
		URL:   p.HTMLURL,
	}
}

// toIssueState flattens an issuePayload into the read-side IssueState, turning
// GitHub's label objects into a flat []string (non-nil even when empty).
func (p issuePayload) toIssueState() IssueState {
	labels := make([]string, 0, len(p.Labels))
	for _, l := range p.Labels {
		labels = append(labels, l.Name)
	}
	return IssueState{
		Number: p.Number,
		Title:  p.Title,
		State:  p.State,
		Body:   p.Body,
		URL:    p.HTMLURL,
		Labels: labels,
	}
}

// isPullRequest reports whether the decoded issue entry is actually a pull
// request (GitHub attaches a non-null "pull_request" object to PRs). ListIssues
// uses this to keep PRs out of the issue list.
func (p issuePayload) isPullRequest() bool {
	return len(p.PullRequest) > 0 && string(p.PullRequest) != "null"
}

// createIssueRequest is the body of POST /repos/{owner}/{repo}/issues.
type createIssueRequest struct {
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`
}

// editIssueRequest is the body of PATCH /repos/{owner}/{repo}/issues/{n}. Title
// and Body are pointers so an empty (unchanged) field is omitted from the PATCH:
// GitHub would otherwise blank it. A nil pointer → field absent → leave as-is.
type editIssueRequest struct {
	Title *string `json:"title,omitempty"`
	Body  *string `json:"body,omitempty"`
}

// issueStateRequest is the body used by CloseIssue/ReopenIssue
// (PATCH /repos/{owner}/{repo}/issues/{n} with {"state":"closed"|"open"}).
type issueStateRequest struct {
	State string `json:"state"`
}

// addLabelsRequest is the body of POST /repos/{owner}/{repo}/issues/{n}/labels.
type addLabelsRequest struct {
	Labels []string `json:"labels"`
}