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

// errorResp is the body of every broker error response. The message is generic
// and carries NO upstream response body, credential, or token content (the
// no-leak contract): it names only the failure class (e.g. "upstream denied",
// "not mergeable"), never the upstream's words.
type errorResp struct {
	Error string `json:"error"`
}