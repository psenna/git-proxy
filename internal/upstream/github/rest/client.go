// Package rest is a minimal, stdlib-only GitHub REST API client. It is the
// building block the GitHub SCM adapter (internal/upstream/github) uses to
// implement port.PRSupport for real: pull requests, reviews, and CI
// (check-runs / workflow-runs) state.
//
// It deliberately depends only on the standard library (net/http,
// encoding/json, reflect) plus internal/port for the sentinel errors it
// returns — no google/go-github — to keep the dependency surface lean and the
// build hermetic.
//
// No-leak contract: the client attaches the proxy's GitHub token ONLY on the
// proxy→GitHub leg as an Authorization: Bearer header. It never logs the token,
// never returns the upstream response body in an error (a 5xx body could echo
// request headers and leak the token), and the sentinel errors it returns carry
// only a generic message. Callers (the broker) map the port sentinels to HTTP
// statuses and generic reasons.
package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// maxPages bounds pagination so a misbehaving or hostile upstream cannot make
// the proxy follow Link headers forever. 10 pages × 100 per page = 1000 items,
// enough for any realistic PR/check list; the caller can page explicitly if more.
const maxPages = 10

// Client is a GitHub REST API client scoped to one base URL and one token. It is
// cheap to construct (no I/O at construction, mirroring the plain adapter) so
// callers may build one per repo/operation. The token is the proxy's held GitHub
// credential; it never leaves this struct except as the Bearer header on an
// outbound request to GitHub.
type Client struct {
	httpClient *http.Client
	baseURL    string // REST API root, no trailing slash (e.g. https://api.github.com)
	token      string // Bearer token; never logged
}

// New returns a REST client for the given base URL and token. baseURL may have a
// trailing slash; it is trimmed. The token is held only to be sent as a Bearer
// header; it is never returned in any error or logged.
func New(baseURL, token string) *Client {
	return &Client{
		httpClient: &http.Client{},
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      token,
	}
}

// do performs one GitHub REST request. It sets the Authorization, Accept, and
// X-GitHub-Api-Version headers; JSON-encodes body (if non-nil) for write methods;
// decodes a 2xx JSON response into out when out is non-nil; and maps any non-2xx
// status to a port sentinel via mapError. The returned *http.Response has its
// body drained and closed before return (callers may inspect headers but must
// not read Body). The response body is never echoed in an error.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) (*http.Response, error) {
	u := c.baseURL + "/" + strings.TrimLeft(path, "/")
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("rest: encode body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rest: %s %s: %w", method, path, err)
	}
	defer func() {
		// Drain and close so the connection can be reused and the body never
		// leaks into an error string. The drained bytes are discarded.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, c.mapError(resp)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("rest: decode response: %w", err)
		}
	}
	return resp, nil
}

// mapError translates a non-2xx GitHub response into a port sentinel. The
// returned error message is generic and contains NO response body content (a
// body could echo request headers and leak the token on some deployments). The
// rate-limit case is detected by status 429 OR status 403 with
// X-RateLimit-Remaining: 0, matching GitHub's documented behavior.
func (c *Client) mapError(resp *http.Response) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		return &port.RateLimitedError{RetryAfter: resp.Header.Get("Retry-After")}
	}
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return &port.RateLimitedError{RetryAfter: resp.Header.Get("Retry-After")}
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return port.ErrUnauthorized
	case http.StatusForbidden:
		return port.ErrForbidden
	case http.StatusNotFound:
		return port.ErrNotFound
	case http.StatusUnprocessableEntity:
		return port.ErrUnprocessable
	case http.StatusConflict:
		return port.ErrNotMergeable
	default:
		return fmt.Errorf("%w: status %d", port.ErrUpstream, resp.StatusCode)
	}
}

// listAll follows the GitHub pagination Link header (rel="next") up to maxPages,
// accumulating JSON-array results into out (a pointer to a slice of any element
// type). Each page is decoded into a fresh slice of the same element type and
// appended. PRs/checks lists that fit in one page (the common case) make a
// single request and stop.
func (c *Client) listAll(ctx context.Context, path string, out any) error {
	slicePtr := reflect.ValueOf(out)
	if slicePtr.Kind() != reflect.Ptr || slicePtr.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("rest: listAll: out must be a pointer to a slice")
	}
	slice := slicePtr.Elem()
	p := path
	for i := 0; i < maxPages; i++ {
		pageType := reflect.SliceOf(slice.Type().Elem())
		page := reflect.New(pageType).Interface()
		resp, err := c.do(ctx, http.MethodGet, p, nil, page)
		if err != nil {
			return err
		}
		slice = reflect.AppendSlice(slice, reflect.ValueOf(page).Elem())
		next, ok := parseNextLink(resp.Header.Get("Link"))
		if !ok {
			break
		}
		p = c.stripToPath(next)
	}
	slicePtr.Elem().Set(slice)
	return nil
}

// stripToPath turns a Link-header next URL (absolute or relative) into a path
// suitable for the next do() call: it removes the configured baseURL prefix if
// present and any leading slash so do() can re-prepend baseURL + "/".
func (c *Client) stripToPath(next string) string {
	if strings.HasPrefix(next, c.baseURL+"/") {
		return strings.TrimPrefix(next, c.baseURL+"/")
	}
	if strings.HasPrefix(next, c.baseURL) {
		return strings.TrimLeft(strings.TrimPrefix(next, c.baseURL), "/")
	}
	return strings.TrimLeft(next, "/")
}

// normalizeRepo converts the proxy's repo key (e.g. "owner/repo.git" or
// "team/sub/repo.git") into GitHub's REST {owner}/{repo} form by stripping a
// trailing ".git" and splitting on the FIRST slash. A value with no slash is
// rejected (the proxy's repo keys always carry an owner). This is the single
// place the proxy→GitHub repo-name translation happens.
func normalizeRepo(repo string) (owner, name string, err error) {
	repo = strings.TrimSuffix(repo, ".git")
	repo = strings.TrimPrefix(repo, "/")
	idx := strings.Index(repo, "/")
	if idx < 0 || repo == "" {
		return "", "", fmt.Errorf("rest: invalid repo %q: expected owner/name", repo)
	}
	return repo[:idx], repo[idx+1:], nil
}

// repoPath builds the /repos/{owner}/{repo} path segment from a proxy repo key,
// failing closed (returning the error) if the key is malformed. It centralizes
// normalizeRepo + fmt so every PR/check method is consistent.
func repoPath(repo string) (string, error) {
	owner, name, err := normalizeRepo(repo)
	if err != nil {
		return "", err
	}
	return "repos/" + owner + "/" + name, nil
}

// parseNextLink extracts the next-page URL from a GitHub Link header value, if
// present. Returns ok=false when there is no rel="next" link (end of list).
func parseNextLink(link string) (string, bool) {
	if link == "" {
		return "", false
	}
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		lt := strings.Index(part, "<")
		gt := strings.Index(part, ">")
		if lt < 0 || gt <= lt {
			continue
		}
		return part[lt+1 : gt], true
	}
	return "", false
}