package rest

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// strPtr returns a pointer to s, or nil when s is empty. It lets EditIssue send
// only non-empty fields in the PATCH (a nil pointer omits the JSON key) so an
// agent never blanks a field by accident.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CreateIssue opens an issue on repo with title and an optional body. An empty
// body is omitted from the POST. GitHub REST: POST /repos/{owner}/{repo}/issues.
// Returns the new issue (number + url).
func (c *Client) CreateIssue(ctx context.Context, repo, title, body string) (Issue, error) {
	p, err := repoPath(repo)
	if err != nil {
		return Issue{}, err
	}
	var payload issuePayload
	if _, err := c.do(ctx, http.MethodPost, p+"/issues", createIssueRequest{Title: title, Body: body}, &payload); err != nil {
		return Issue{}, err
	}
	return payload.toIssue(), nil
}

// GetIssue fetches a single issue by number.
// GitHub REST: GET /repos/{owner}/{repo}/issues/{number}.
func (c *Client) GetIssue(ctx context.Context, repo string, number int) (IssueState, error) {
	p, err := repoPath(repo)
	if err != nil {
		return IssueState{}, err
	}
	var payload issuePayload
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/issues/%d", p, number), nil, &payload); err != nil {
		return IssueState{}, err
	}
	return payload.toIssueState(), nil
}

// ListIssues lists issues on repo filtered by state ("open"|"closed"|"all").
// GitHub REST: GET /repos/{owner}/{repo}/issues?state={state}, paginated via the
// Link header. An empty state defaults to "open". GitHub models every pull
// request as an issue, so the issues endpoint also returns PRs (a non-null
// "pull_request" field); those are filtered out so the list is issues only.
func (c *Client) ListIssues(ctx context.Context, repo, state string) ([]IssueState, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	if state == "" {
		state = "open"
	}
	var payloads []issuePayload
	if err := c.listAll(ctx, p+"/issues?state="+state+"&per_page=100", &payloads); err != nil {
		return nil, err
	}
	issues := make([]IssueState, 0, len(payloads))
	for _, pl := range payloads {
		if pl.isPullRequest() {
			continue
		}
		issues = append(issues, pl.toIssueState())
	}
	return issues, nil
}

// CommentIssue adds a line comment to issue number. GitHub REST:
// POST /repos/{owner}/{repo}/issues/{number}/comments (the same
// issues-comments endpoint CommentPR uses).
func (c *Client) CommentIssue(ctx context.Context, repo string, number int, body string) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", p, number), commentRequest{Body: body}, nil)
	return err
}

// CloseIssue closes issue number. GitHub REST:
// PATCH /repos/{owner}/{repo}/issues/{number} with {"state":"closed"}.
func (c *Client) CloseIssue(ctx context.Context, repo string, number int) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/%d", p, number), issueStateRequest{State: "closed"}, nil)
	return err
}

// ReopenIssue reopens issue number. GitHub REST:
// PATCH /repos/{owner}/{repo}/issues/{number} with {"state":"open"}.
func (c *Client) ReopenIssue(ctx context.Context, repo string, number int) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/%d", p, number), issueStateRequest{State: "open"}, nil)
	return err
}

// EditIssue edits the title and/or body of issue number. An empty title or body
// means "leave unchanged" (the field is omitted from the PATCH via a nil
// pointer), so an agent does not blank a field by accident. GitHub REST:
// PATCH /repos/{owner}/{repo}/issues/{number}. Returns the updated issue.
func (c *Client) EditIssue(ctx context.Context, repo string, number int, title, body string) (IssueState, error) {
	p, err := repoPath(repo)
	if err != nil {
		return IssueState{}, err
	}
	var payload issuePayload
	if _, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/%d", p, number), editIssueRequest{Title: strPtr(title), Body: strPtr(body)}, &payload); err != nil {
		return IssueState{}, err
	}
	return payload.toIssueState(), nil
}

// AddLabels adds labels to issue number and returns the resulting label set.
// GitHub REST: POST /repos/{owner}/{repo}/issues/{number}/labels.
func (c *Client) AddLabels(ctx context.Context, repo string, number int, labels []string) ([]string, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	var labelObjs []issueLabel
	if _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/issues/%d/labels", p, number), addLabelsRequest{Labels: labels}, &labelObjs); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(labelObjs))
	for _, l := range labelObjs {
		names = append(names, l.Name)
	}
	return names, nil
}

// RemoveLabel removes a single label from issue number. The label name is
// URL-path-escaped (GitHub labels may contain spaces/emoji). GitHub REST:
// DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name}.
func (c *Client) RemoveLabel(ctx context.Context, repo string, number int, label string) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, fmt.Sprintf("%s/issues/%d/labels/%s", p, number, url.PathEscape(label)), nil, nil)
	return err
}