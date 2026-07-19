package port

import "context"

// IssueSupport is an OPTIONAL capability sub-interface an Upstream MAY implement
// when the provider exposes an issue tracker (GitHub issues, a future Jira/etc.
// adapter). The proxy core NEVER depends on it: it is a seam the agent-facing
// broker (internal/broker) type-asserts off a SEPARATELY-configured issue upstream
// (config.issue_upstream), distinct from the SCM upstream that backs
// PRSupport/branch-protection. Decoupling the issue provider from the SCM lets a
// deployment run, e.g., GitHub as the SCM (PRs) and Jira as the issue source with
// no core change — mirroring how PRSupport lets a future GitLab adapter slot in.
//
// Code that wants to use it must type-assert:
//
//	if is, ok := issueUp.(IssueSupport); ok { ... }
//
// Like PRSupport, the method signatures are minimal REAL signatures (not an empty
// interface — an empty interface would be trivially satisfied by anything,
// defeating `var _ IssueSupport = (*Adapter)(nil)` as a compile check). A partial
// adapter that implements some methods and not others returns ErrNotImplemented for
// the rest; the broker maps that to HTTP 501 per-op so the supported ops still work.
//
// No-leak / fail-closed: implementations attach the provider token ONLY on the
// proxy→provider leg (never to the agent) and fail closed with ErrUnauthorized when
// no per-repo token is configured — never anonymous. The sentinel errors an
// implementation returns are the generic ones in errors.go; they never echo the
// upstream response body.
type IssueSupport interface {
	// CreateIssue opens an issue on repo with title and an optional body.
	// GitHub REST: POST /repos/{owner}/{repo}/issues. Returns the new issue
	// (number + url).
	CreateIssue(ctx context.Context, repo, title, body string) (Issue, error)
	// GetIssue fetches a single issue by number. GitHub REST:
	// GET /repos/{owner}/{repo}/issues/{number}.
	GetIssue(ctx context.Context, repo string, number int) (IssueState, error)
	// ListIssues lists issues on repo filtered by state
	// ("open"|"closed"|"all"; an empty string means "open"). GitHub REST:
	// GET /repos/{owner}/{repo}/issues?state={state}, paginated.
	ListIssues(ctx context.Context, repo, state string) ([]IssueState, error)
	// CommentIssue adds a line comment to issue number. GitHub REST:
	// POST /repos/{owner}/{repo}/issues/{number}/comments (the same
	// issues-comments endpoint CommentPR uses).
	CommentIssue(ctx context.Context, repo string, number int, body string) error
	// CloseIssue closes issue number. GitHub REST:
	// PATCH /repos/{owner}/{repo}/issues/{number} with {"state":"closed"}.
	CloseIssue(ctx context.Context, repo string, number int) error
	// ReopenIssue reopens issue number. GitHub REST:
	// PATCH /repos/{owner}/{repo}/issues/{number} with {"state":"open"}.
	ReopenIssue(ctx context.Context, repo string, number int) error
	// EditIssue edits the title and/or body of issue number. An empty title or
	// body means "leave unchanged" (the adapter omits it from the PATCH), so an
	// agent does not blank a field by accident. GitHub REST:
	// PATCH /repos/{owner}/{repo}/issues/{number}. Returns the updated issue.
	EditIssue(ctx context.Context, repo string, number int, title, body string) (IssueState, error)
	// AddLabels adds labels to issue number and returns the resulting label set.
	// GitHub REST: POST /repos/{owner}/{repo}/issues/{number}/labels.
	AddLabels(ctx context.Context, repo string, number int, labels []string) ([]string, error)
	// RemoveLabel removes a single label from issue number. GitHub REST:
	// DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name}.
	RemoveLabel(ctx context.Context, repo string, number int, label string) error
}

// Issue describes an issue created via CreateIssue. It is the create-side
// counterpart of IssueState (which GetIssue/ListIssues return): it carries only
// the fields an agent needs immediately after filing. The JSON tags let the
// broker serialize it directly as the create-issue response, mirroring PR.
type Issue struct {
	// Number is the provider issue number.
	Number int `json:"number"`
	// URL is the HTML URL of the issue.
	URL string `json:"url"`
}

// IssueState is the full state of an issue as returned by GetIssue/ListIssues/
// EditIssue. It carries the fields an agent needs to decide whether to act on an
// issue. The JSON tags let the broker serialize it directly. Labels is the list of
// label names on the issue (empty slice, not nil, when there are none — the
// adapter normalizes so the JSON renders [] not null).
type IssueState struct {
	// Number is the provider issue number.
	Number int `json:"number"`
	// Title is the issue title.
	Title string `json:"title"`
	// State is "open" or "closed".
	State string `json:"state"`
	// Body is the issue body (markdown), if any.
	Body string `json:"body"`
	// URL is the HTML URL of the issue.
	URL string `json:"url"`
	// Labels is the list of label names on the issue.
	Labels []string `json:"labels"`
}