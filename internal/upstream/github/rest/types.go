package rest

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