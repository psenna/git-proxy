package broker

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// capturingPRSupport records the args of each call so tests can assert the
// agent's Bearer token is never forwarded (PRSupport methods take no token; the
// token never leaves the broker's authenticate call).
type capturingPRSupport struct {
	stubUpstream
	ensureHead, ensureBase, ensureTitle string
	mergeNumber                         int
	mergeMethod                         string
	commentNumber                       int
	commentBody                         string
	reviewNumber                        int
	reviewEvent, reviewBody             string
	checksRef                           string
	prErr                               error
	mergeErr                            error
	summary                             port.CheckSummary
}

func (c *capturingPRSupport) BranchProtection(context.Context, string, string) (port.BranchProtection, error) {
	return port.BranchProtection{}, port.ErrNotImplemented
}
func (c *capturingPRSupport) EnsurePR(_ context.Context, _ string, head, base, title string) (port.PR, error) {
	c.ensureHead, c.ensureBase, c.ensureTitle = head, base, title
	return port.PR{Number: 7, URL: "https://gh/pull/7"}, c.prErr
}
func (c *capturingPRSupport) GetPR(_ context.Context, _ string, _ int) (port.PRState, error) {
	return port.PRState{Number: 7, Title: "t", State: "open", Head: "feat", Base: "main", URL: "u"}, c.prErr
}
func (c *capturingPRSupport) ListPRs(_ context.Context, _ string, _ string) ([]port.PRState, error) {
	return []port.PRState{{Number: 7, State: "open"}}, c.prErr
}
func (c *capturingPRSupport) MergePR(_ context.Context, _ string, n int, m string) error {
	c.mergeNumber, c.mergeMethod = n, m
	return c.mergeErr
}
func (c *capturingPRSupport) CommentPR(_ context.Context, _ string, n int, body string) error {
	c.commentNumber, c.commentBody = n, body
	return c.prErr
}
func (c *capturingPRSupport) ReviewPR(_ context.Context, _ string, n int, event, body string) error {
	c.reviewNumber, c.reviewEvent, c.reviewBody = n, event, body
	return c.prErr
}
func (c *capturingPRSupport) Checks(_ context.Context, _ string, ref string) (port.CheckSummary, error) {
	c.checksRef = ref
	return c.summary, c.prErr
}

// newTestBroker boots a broker over a capturingPRSupport with a fixed agent
// token, returning the broker and an httptest server driving its mux.
func newTestBroker(t *testing.T, up *capturingPRSupport, cfg Config) (*Broker, *httptest.Server) {
	t.Helper()
	authn := fakeAuthenticator{tokens: map[string]string{"agent-token-1": "alice"}}
	b, err := New(nil, up, nil, nil, authn, &recordingSink{}, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(b.routes())
	t.Cleanup(srv.Close)
	return b, srv
}

func do(t *testing.T, srv *httptest.Server, method, path, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestCreatePR_HappyPath(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{MergeMethod: "squash"})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs", "agent-token-1", []byte(`{"head":"feat","base":"main","title":"t"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if up.ensureHead != "feat" || up.ensureBase != "main" || up.ensureTitle != "t" {
		t.Errorf("EnsurePR args = head=%q base=%q title=%q", up.ensureHead, up.ensureBase, up.ensureTitle)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"number":7`) || !strings.Contains(string(b), `"url":"https://gh/pull/7"`) {
		t.Errorf("body = %s", b)
	}
}

func TestGetPR_HappyPath(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"state":"open"`) {
		t.Errorf("body = %s", b)
	}
}

func TestListPRs_HappyPath(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs?state=open", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(strings.TrimSpace(string(b)), `[`) {
		t.Errorf("body = %s, want a JSON array", b)
	}
}

func TestMergePR_204AndDefaultMethod(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{MergeMethod: "squash"})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs/7/merge", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if up.mergeNumber != 7 || up.mergeMethod != "squash" {
		t.Errorf("MergePR(%d,%q), want (7,squash default)", up.mergeNumber, up.mergeMethod)
	}
}

func TestMergePR_MethodOverride(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{MergeMethod: "merge"})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs/7/merge", "agent-token-1", []byte(`{"method":"rebase"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if up.mergeMethod != "rebase" {
		t.Errorf("mergeMethod = %q, want rebase (override)", up.mergeMethod)
	}
}

// TestMergePR_MalformedBodyIs400 guards against a silent wrong-method merge: a
// truncated/malformed body must surface 400, not fall through to the configured
// default method. A merge is hard to reverse, so conflating "no body" (use the
// default) with "bad body" (reject) would silently merge with the wrong method.
func TestMergePR_MalformedBodyIs400(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{MergeMethod: "squash"})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs/7/merge", "agent-token-1", []byte(`{"method":"rebase"`)) // truncated JSON
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (malformed body must not fall back to default method)", resp.StatusCode)
	}
	if up.mergeNumber != 0 || up.mergeMethod != "" {
		t.Errorf("MergePR was called (%d,%q) — a malformed body must never reach MergePR", up.mergeNumber, up.mergeMethod)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "agent-token-1") {
		t.Errorf("error body leaks the agent token: %s", b)
	}
}

func TestCommentPR_HappyPath(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs/5/comments", "agent-token-1", []byte(`{"body":"lgtm"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if up.commentNumber != 5 || up.commentBody != "lgtm" {
		t.Errorf("CommentPR(%d,%q)", up.commentNumber, up.commentBody)
	}
}

func TestReviewPR_HappyPath(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs/5/reviews", "agent-token-1", []byte(`{"event":"APPROVE","body":"ship"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if up.reviewEvent != "APPROVE" || up.reviewBody != "ship" {
		t.Errorf("ReviewPR event=%q body=%q", up.reviewEvent, up.reviewBody)
	}
}

func TestChecks_HappyPath(t *testing.T) {
	up := &capturingPRSupport{summary: port.CheckSummary{Overall: "success", Checks: []port.CheckRun{{Name: "ci", Status: "completed", Conclusion: "success"}}}}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/checks/abc/def", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if up.checksRef != "abc/def" {
		t.Errorf("checksRef = %q, want abc/def ({ref...} preserved slashes)", up.checksRef)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"overall":"success"`) {
		t.Errorf("body = %s", b)
	}
}

func TestAuth_401NoAndBadBearer(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{})
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no bearer", ""},
		{"bad bearer", "wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs/7", tc.token, nil)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if resp.Header.Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", resp.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

func TestAuthz_403NotAllowlisted(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{AllowedAgents: []string{"bob"}})
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (alice not in allowlist [bob])", resp.StatusCode)
	}
}

func TestOpAllowlist_403(t *testing.T) {
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{AllowedOps: []string{"pr.get"}})
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs/7/merge", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (pr.merge not in allowed_ops)", resp.StatusCode)
	}
}

func TestSentinelToStatus(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		want    int
		method  string
		path    string
		body    []byte
	}{
		{"not found → 404", port.ErrNotFound, http.StatusNotFound, http.MethodGet, "/owner%2Frepo.git/prs/7", nil},
		{"upstream unauthorized → 502", port.ErrUnauthorized, http.StatusBadGateway, http.MethodGet, "/owner%2Frepo.git/prs/7", nil},
		{"forbidden → 403", port.ErrForbidden, http.StatusForbidden, http.MethodGet, "/owner%2Frepo.git/prs/7", nil},
		{"not mergeable → 409", port.ErrNotMergeable, http.StatusConflict, http.MethodPost, "/owner%2Frepo.git/prs/7/merge", nil},
		{"unprocessable → 422", port.ErrUnprocessable, http.StatusUnprocessableEntity, http.MethodPost, "/owner%2Frepo.git/prs", []byte(`{"head":"a","base":"b","title":"t"}`)},
		{"rate limited → 429", port.ErrRateLimited, http.StatusTooManyRequests, http.MethodGet, "/owner%2Frepo.git/prs/7", nil},
		{"upstream → 502", port.ErrUpstream, http.StatusBadGateway, http.MethodGet, "/owner%2Frepo.git/prs/7", nil},
		{"not implemented → 501", port.ErrNotImplemented, http.StatusNotImplemented, http.MethodGet, "/owner%2Frepo.git/prs/7", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := &capturingPRSupport{prErr: tc.err, mergeErr: tc.err}
			// mergeErr is what MergePR returns; prErr covers the rest.
			if strings.Contains(tc.path, "merge") {
				up.prErr = nil
			} else {
				up.mergeErr = nil
			}
			_, srv := newTestBroker(t, up, Config{})
			resp := do(t, srv, tc.method, tc.path, "agent-token-1", tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(b), `"error"`) {
				t.Errorf("body = %s, want an error JSON body", b)
			}
			// No-leak: the error body must not contain the agent token or any
			// upstream-looking detail beyond the generic reason.
			if strings.Contains(string(b), "agent-token-1") {
				t.Errorf("error body leaks the agent token: %s", b)
			}
		})
	}
}

func TestRateLimited_ForwardsRetryAfter(t *testing.T) {
	up := &capturingPRSupport{prErr: &port.RateLimitedError{RetryAfter: "120"}}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") != "120" {
		t.Errorf("Retry-After = %q, want 120 (forwarded from upstream)", resp.Header.Get("Retry-After"))
	}
}

func TestRateLimited_NoRetryAfterWhenAbsent(t *testing.T) {
	// A plain ErrRateLimited (no *RateLimitedError) → 429 with no invented Retry-After.
	up := &capturingPRSupport{prErr: port.ErrRateLimited}
	_, srv := newTestBroker(t, up, Config{})
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") != "" {
		t.Errorf("Retry-After = %q, want empty (never invented)", resp.Header.Get("Retry-After"))
	}
}

func TestAgentBearerNotForwardedToPRSupport(t *testing.T) {
	// The agent's Bearer token is consumed by authenticate and NEVER passed to
	// PRSupport (it has no token parameter). This is a structural no-leak
	// guarantee: the capturing stub has no field that could hold a token, so the
	// fact that EnsurePR succeeded with only head/base/title proves the token
	// was not forwarded. Cross-check via audit: no event carries the token.
	sink := &recordingSink{}
	up := &capturingPRSupport{}
	b, err := New(nil, up, nil, nil, fakeAuthenticator{tokens: map[string]string{"agent-token-1": "alice"}}, sink, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(b.routes())
	defer srv.Close()
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/prs", "agent-token-1", []byte(`{"head":"feat","base":"main","title":"t"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if up.ensureHead != "feat" || up.ensureBase != "main" || up.ensureTitle != "t" {
		t.Errorf("EnsurePR args = %q/%q/%q (token must not be among them)", up.ensureHead, up.ensureBase, up.ensureTitle)
	}
	for _, e := range sink.events {
		if strings.Contains(e.Agent, "agent-token-1") || strings.Contains(e.Repo, "agent-token-1") {
			t.Errorf("audit event leaks agent token: %+v", e)
		}
		for _, r := range e.Reasons {
			if strings.Contains(r, "agent-token-1") {
				t.Errorf("audit reason leaks agent token: %q", r)
			}
		}
	}
}

func TestRepoAliasResolved(t *testing.T) {
	up := &capturingPRSupport{}
	authn := fakeAuthenticator{tokens: map[string]string{"t": "alice"}}
	b, err := New(nil, up, nil, map[string]string{"alias": "owner/repo.git"}, authn, &recordingSink{}, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(b.routes())
	defer srv.Close()
	// "alias" has no slash, so it needs no encoding; the broker resolves it to
	// owner/repo.git before calling PRSupport.
	resp := do(t, srv, http.MethodGet, "/alias/prs/7", "t", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}