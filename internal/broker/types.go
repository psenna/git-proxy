package broker

// types.go holds the broker's request/response wire shapes. Responses serialize
// the port types directly (port.PRState, port.PR, port.CheckSummary carry JSON
// tags), so only the request bodies are defined here.

// createPRReq is the body of POST /{repo}/prs. Head and Base are branch names;
// Title is the PR title. All three are required (a missing field yields 422 via
// the adapter's GitHub call, which rejects an empty payload).
type createPRReq struct {
	Head  string `json:"head"`
	Base  string `json:"base"`
	Title string `json:"title"`
}

// mergePRReq is the body of POST /{repo}/prs/{number}/merge. Method is optional
// ("merge"|"squash"|"rebase"); an empty value defaults to the broker's
// configured MergeMethod (BrokerConfig.MergeMethod, itself defaulting to
// "merge").
type mergePRReq struct {
	Method string `json:"method"`
}

// commentReq is the body of POST /{repo}/prs/{number}/comments.
type commentReq struct {
	Body string `json:"body"`
}

// reviewReq is the body of POST /{repo}/prs/{number}/reviews. Event is required
// ("APPROVE"|"REQUEST_CHANGES"|"COMMENT"); Body is optional review text.
type reviewReq struct {
	Event string `json:"event"`
	Body  string `json:"body"`
}

// createIssueReq is the body of POST /{repo}/issues. Title is required; Body is
// optional (an empty body is omitted on the proxy→provider leg).
type createIssueReq struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// editIssueReq is the body of POST /{repo}/issues/{number}/edit. An empty Title
// or Body means "leave unchanged" — the adapter omits it from the PATCH so an
// agent does not blank a field by accident. Both empty is a no-op edit.
type editIssueReq struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// addLabelsReq is the body of POST /{repo}/issues/{number}/labels.
type addLabelsReq struct {
	Labels []string `json:"labels"`
}

// removeLabelReq is the body of POST /{repo}/issues/{number}/labels/remove.
// Label travels in the body (not the path) so label path-encoding stays inside
// the rest client, not the broker URL.
type removeLabelReq struct {
	Label string `json:"label"`
}

// errorResp is the body of every broker error response. The message is generic
// and carries NO upstream response body, credential, or token content (the
// no-leak contract): it names only the failure class (e.g. "upstream denied",
// "not mergeable"), never the upstream's words.
type errorResp struct {
	Error string `json:"error"`
}