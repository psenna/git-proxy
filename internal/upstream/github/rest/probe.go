package rest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/psenna/git-proxy/internal/port"
)

// Probe issues a GET to path, discards any response body, and returns nil on a
// 2xx or the mapped port sentinel otherwise (via do -> mapError). It is the
// thin primitive the startup preflight (internal/preflight) uses to classify a
// permission by status code alone — it never needs the payload.
func (c *Client) Probe(ctx context.Context, path string) error {
	_, err := c.do(ctx, http.MethodGet, path, nil, nil)
	return err
}

// RepoAPIPath returns the "repos/{owner}/{repo}" REST path for a proxy repo key
// (trailing ".git" stripped, split on the FIRST slash). Exported for the
// preflight prober, which assembles probe paths directly rather than through
// the PR/issue/check methods.
func RepoAPIPath(repo string) (string, error) { return repoPath(repo) }

// RepoInfo is the slice of GET /repos/{owner}/{repo} the preflight needs: the
// full name (to confirm the repo resolved) and the default branch (to retry a
// check-runs probe that 404s against HEAD).
type RepoInfo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

// RepoInfo fetches GET /repos/{owner}/{repo}.
func (c *Client) RepoInfo(ctx context.Context, repo string) (RepoInfo, error) {
	p, err := repoPath(repo)
	if err != nil {
		return RepoInfo{}, err
	}
	var out RepoInfo
	if _, err := c.do(ctx, http.MethodGet, p, nil, &out); err != nil {
		return RepoInfo{}, err
	}
	return out, nil
}

// repoName is the one field ListOwnerRepos keeps from a repo list entry.
type repoName struct {
	FullName string `json:"full_name"`
}

// ListOwnerRepos returns up to limit repo full-names owned by owner, most
// recently updated first. It tries the org endpoint
// (GET /orgs/{owner}/repos) and falls back to the user endpoint
// (GET /users/{owner}/repos) on a 404 — an owner may be a user, not an org.
// Only the first page is read (the preflight samples a single repo).
func (c *Client) ListOwnerRepos(ctx context.Context, owner string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 1
	}
	q := fmt.Sprintf("?per_page=%d&sort=updated", limit)
	var page []repoName
	_, err := c.do(ctx, http.MethodGet, "orgs/"+url.PathEscape(owner)+"/repos"+q, nil, &page)
	if errors.Is(err, port.ErrNotFound) {
		page = nil
		_, err = c.do(ctx, http.MethodGet, "users/"+url.PathEscape(owner)+"/repos"+q, nil, &page)
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(page))
	for _, r := range page {
		if r.FullName == "" {
			continue
		}
		out = append(out, r.FullName)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
