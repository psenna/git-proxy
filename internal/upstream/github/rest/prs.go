package rest

import (
	"context"
	"fmt"
	"net/http"
)

// CreatePR opens a pull request on repo from head into base with title.
// GitHub REST: POST /repos/{owner}/{repo}/pulls. Returns the new PR (number,
// url, head/base/state).
func (c *Client) CreatePR(ctx context.Context, repo, head, base, title string) (PR, error) {
	p, err := repoPath(repo)
	if err != nil {
		return PR{}, err
	}
	var payload prPayload
	if _, err := c.do(ctx, http.MethodPost, p+"/pulls", createPRRequest{Head: head, Base: base, Title: title}, &payload); err != nil {
		return PR{}, err
	}
	return payload.toPR(), nil
}

// GetPR fetches a single pull request by number.
// GitHub REST: GET /repos/{owner}/{repo}/pulls/{number}.
func (c *Client) GetPR(ctx context.Context, repo string, number int) (PR, error) {
	p, err := repoPath(repo)
	if err != nil {
		return PR{}, err
	}
	var payload prPayload
	if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s/pulls/%d", p, number), nil, &payload); err != nil {
		return PR{}, err
	}
	return payload.toPR(), nil
}

// ListPRs lists pull requests on repo filtered by state ("open"|"closed"|"all").
// GitHub REST: GET /repos/{owner}/{repo}/pulls?state={state}, following the Link
// header for pagination. An empty state defaults to "open".
func (c *Client) ListPRs(ctx context.Context, repo, state string) ([]PR, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	if state == "" {
		state = "open"
	}
	var payloads []prPayload
	if err := c.listAll(ctx, p+"/pulls?state="+state+"&per_page=100", &payloads); err != nil {
		return nil, err
	}
	prs := make([]PR, 0, len(payloads))
	for _, pl := range payloads {
		prs = append(prs, pl.toPR())
	}
	return prs, nil
}

// MergePR merges pull request number on repo using method ("merge"|"squash"
//|"rebase"). An empty method defaults to "merge" (the caller — the broker —
// fills it from BrokerConfig.MergeMethod). GitHub REST:
// PUT /repos/{owner}/{repo}/pulls/{number}/merge. A 409 (conflict / not
// mergeable) is mapped to port.ErrNotMergeable by the client.
func (c *Client) MergePR(ctx context.Context, repo string, number int, method string) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	if method == "" {
		method = "merge"
	}
	_, err = c.do(ctx, http.MethodPut, fmt.Sprintf("%s/pulls/%d/merge", p, number), mergePRRequest{MergeMethod: method}, nil)
	return err
}

// CommentPR adds an issue-style line comment to pull request number. GitHub
// REST: POST /repos/{owner}/{repo}/issues/{number}/comments (PR comments share
// the issues-comments endpoint in the GitHub REST API).
func (c *Client) CommentPR(ctx context.Context, repo string, number int, body string) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", p, number), commentRequest{Body: body}, nil)
	return err
}

// ReviewPR submits a review on pull request number with event ("APPROVE"
//|"REQUEST_CHANGES"|"COMMENT") and an optional body. GitHub REST:
// POST /repos/{owner}/{repo}/pulls/{number}/reviews.
func (c *Client) ReviewPR(ctx context.Context, repo string, number int, event, body string) error {
	p, err := repoPath(repo)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, fmt.Sprintf("%s/pulls/%d/reviews", p, number), reviewRequest{Event: event, Body: body}, nil)
	return err
}