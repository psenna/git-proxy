package broker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// capturingIssueSupport implements port.Upstream (via stubUpstream) AND
// port.IssueSupport, recording each call's args so tests assert the broker
// reached the issue capability with the right args. The agent's Bearer is never
// an arg — the IssueSupport methods take no token; the proxy's provider token is
// attached only inside the adapter, never handed from the broker.
type capturingIssueSupport struct {
	stubUpstream
	createTitle, createBody string
	getNumber               int
	listState               string
	commentNumber           int
	commentBody             string
	closeNumber             int
	reopenNumber            int
	editNumber              int
	editTitle, editBody     string
	addLabelsNumber         int
	addLabels               []string
	removeLabelNumber       int
	removeLabel             string
	err                     error // returned by every method when set
}

func (c *capturingIssueSupport) CreateIssue(_ context.Context, _ string, title, body string) (port.Issue, error) {
	c.createTitle, c.createBody = title, body
	return port.Issue{Number: 11, URL: "https://gh/issues/11"}, c.err
}
func (c *capturingIssueSupport) GetIssue(_ context.Context, _ string, n int) (port.IssueState, error) {
	c.getNumber = n
	return port.IssueState{Number: 11, Title: "t", State: "open", Body: "b", URL: "https://gh/issues/11", Labels: []string{"bug"}}, c.err
}
func (c *capturingIssueSupport) ListIssues(_ context.Context, _ string, state string) ([]port.IssueState, error) {
	c.listState = state
	return []port.IssueState{{Number: 11, State: "open"}}, c.err
}
func (c *capturingIssueSupport) CommentIssue(_ context.Context, _ string, n int, body string) error {
	c.commentNumber, c.commentBody = n, body
	return c.err
}
func (c *capturingIssueSupport) CloseIssue(_ context.Context, _ string, n int) error {
	c.closeNumber = n
	return c.err
}
func (c *capturingIssueSupport) ReopenIssue(_ context.Context, _ string, n int) error {
	c.reopenNumber = n
	return c.err
}
func (c *capturingIssueSupport) EditIssue(_ context.Context, _ string, n int, title, body string) (port.IssueState, error) {
	c.editNumber, c.editTitle, c.editBody = n, title, body
	return port.IssueState{Number: 11, Title: title, State: "open", URL: "https://gh/issues/11"}, c.err
}
func (c *capturingIssueSupport) AddLabels(_ context.Context, _ string, n int, labels []string) ([]string, error) {
	c.addLabelsNumber, c.addLabels = n, labels
	return []string{"bug", "p1"}, c.err
}
func (c *capturingIssueSupport) RemoveLabel(_ context.Context, _ string, n int, label string) error {
	c.removeLabelNumber, c.removeLabel = n, label
	return c.err
}

// newTestBrokerIssues boots a broker with a capturingPRSupport SCM upstream and
// a capturingIssueSupport issue upstream (issues wired), driving its mux. The
// SCM upstream is the same capturingPRSupport the PR tests use; the issue
// upstream is the captured one.
func newTestBrokerIssues(t *testing.T, issueUp *capturingIssueSupport) (*Broker, *httptest.Server) {
	t.Helper()
	up := &capturingPRSupport{}
	authn := fakeAuthenticator{tokens: map[string]string{"agent-token-1": "alice"}}
	b, err := New(nil, up, issueUp, nil, authn, &recordingSink{}, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(b.routes())
	t.Cleanup(srv.Close)
	return b, srv
}

func TestNew_IssueSupportOptional(t *testing.T) {
	// issueUp implements IssueSupport → b.issues wired.
	b := mustNewIssues(t, stubPRSupport{}, &capturingIssueSupport{}, fakeAuthenticator{}, nil, Config{})
	if b.issues == nil {
		t.Fatal("issues = nil, want wired when issueUp implements IssueSupport")
	}
	// issueUp nil → issues nil, NO error (additive/opt-in, not startup-fatal).
	bn := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{})
	if bn.issues != nil {
		t.Fatal("issues = non-nil, want nil when no issue upstream")
	}
	// issueUp does NOT implement IssueSupport → issues nil, NO error.
	upstreamOnly := stubUpstream{} // port.Upstream only, no IssueSupport
	bo, err := New(nil, stubPRSupport{}, upstreamOnly, nil, fakeAuthenticator{}, nil, Config{})
	if err != nil {
		t.Fatalf("New with non-IssueSupport issueUp: %v", err)
	}
	if bo.issues != nil {
		t.Fatal("issues = non-nil, want nil when issueUp lacks IssueSupport (non-fatal)")
	}
}

func TestCreateIssue_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues", "agent-token-1", []byte(`{"title":"t","body":"b"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if is.createTitle != "t" || is.createBody != "b" {
		t.Errorf("CreateIssue args = title=%q body=%q", is.createTitle, is.createBody)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"number":11`) || !strings.Contains(string(b), `"url":"https://gh/issues/11"`) {
		t.Errorf("body = %s", b)
	}
}

func TestGetIssue_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/issues/11", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if is.getNumber != 11 {
		t.Errorf("GetIssue number = %d, want 11", is.getNumber)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"state":"open"`) || !strings.Contains(string(b), `"bug"`) {
		t.Errorf("body = %s", b)
	}
}

func TestListIssues_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodGet, "/owner%2Frepo.git/issues?state=open", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if is.listState != "open" {
		t.Errorf("ListIssues state = %q, want open", is.listState)
	}
}

func TestCommentIssue_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues/11/comments", "agent-token-1", []byte(`{"body":"note"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if is.commentNumber != 11 || is.commentBody != "note" {
		t.Errorf("CommentIssue = number=%d body=%q", is.commentNumber, is.commentBody)
	}
}

func TestCloseIssue_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues/11/close", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if is.closeNumber != 11 {
		t.Errorf("CloseIssue number = %d, want 11", is.closeNumber)
	}
}

func TestReopenIssue_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues/11/reopen", "agent-token-1", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if is.reopenNumber != 11 {
		t.Errorf("ReopenIssue number = %d, want 11", is.reopenNumber)
	}
}

func TestEditIssue_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues/11/edit", "agent-token-1", []byte(`{"title":"new"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// Empty body → "leave unchanged": the broker passes "" through, the adapter
	// omits it from the PATCH. Assert the title reached the capability.
	if is.editNumber != 11 || is.editTitle != "new" || is.editBody != "" {
		t.Errorf("EditIssue = number=%d title=%q body=%q", is.editNumber, is.editTitle, is.editBody)
	}
}

func TestAddLabels_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues/11/labels", "agent-token-1", []byte(`{"labels":["bug","p1"]}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if is.addLabelsNumber != 11 || len(is.addLabels) != 2 || is.addLabels[0] != "bug" {
		t.Errorf("AddLabels = number=%d labels=%v", is.addLabelsNumber, is.addLabels)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"bug"`) || !strings.Contains(string(b), `"p1"`) {
		t.Errorf("body = %s", b)
	}
}

func TestRemoveLabel_HappyPath(t *testing.T) {
	is := &capturingIssueSupport{}
	_, srv := newTestBrokerIssues(t, is)
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues/11/labels/remove", "agent-token-1", []byte(`{"label":"bug"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if is.removeLabelNumber != 11 || is.removeLabel != "bug" {
		t.Errorf("RemoveLabel = number=%d label=%q", is.removeLabelNumber, is.removeLabel)
	}
}

func TestIssueRoutes_501WhenIssuesNil(t *testing.T) {
	// newTestBroker wires no issue upstream → b.issues nil → issue routes 501
	// per-op (issues opt-in), while PR routes still work. 401 still gates first
	// (no/bad Bearer → 401, NOT 501), so check that too.
	up := &capturingPRSupport{}
	_, srv := newTestBroker(t, up, Config{})

	// No Bearer → 401 (auth gate runs before the 501; never leak "issues exist").
	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues", "", []byte(`{"title":"t"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no bearer: status = %d, want 401", resp.StatusCode)
	}

	// Valid bearer, issues nil → 501.
	resp2 := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues", "agent-token-1", []byte(`{"title":"t"}`))
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNotImplemented {
		t.Errorf("issues nil: status = %d, want 501", resp2.StatusCode)
	}
	b, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(b), "not implemented") {
		t.Errorf("body = %s, want 'not implemented' reason", b)
	}

	// A PR route still works with issues nil (PRSupport unaffected).
	resp3 := do(t, srv, http.MethodGet, "/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("PR route with issues nil: status = %d, want 200 (PRSupport unaffected)", resp3.StatusCode)
	}
}

func TestIssueRoutes_SentinelToStatus(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		want   int
		method string
		path   string
		body   []byte
	}{
		{"not found → 404", port.ErrNotFound, http.StatusNotFound, http.MethodGet, "/owner%2Frepo.git/issues/11", nil},
		{"upstream unauthorized → 502", port.ErrUnauthorized, http.StatusBadGateway, http.MethodGet, "/owner%2Frepo.git/issues/11", nil},
		{"forbidden → 403", port.ErrForbidden, http.StatusForbidden, http.MethodGet, "/owner%2Frepo.git/issues/11", nil},
		{"unprocessable → 422", port.ErrUnprocessable, http.StatusUnprocessableEntity, http.MethodPost, "/owner%2Frepo.git/issues", []byte(`{"title":"t"}`)},
		{"rate limited → 429", port.ErrRateLimited, http.StatusTooManyRequests, http.MethodGet, "/owner%2Frepo.git/issues/11", nil},
		{"upstream → 502", port.ErrUpstream, http.StatusBadGateway, http.MethodGet, "/owner%2Frepo.git/issues/11", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := &capturingIssueSupport{err: tc.err}
			_, srv := newTestBrokerIssues(t, is)
			resp := do(t, srv, tc.method, tc.path, "agent-token-1", tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(b), `"error"`) {
				t.Errorf("body = %s, want an error JSON body", b)
			}
			// No-leak: the error body must not contain the agent token.
			if strings.Contains(string(b), "agent-token-1") {
				t.Errorf("error body leaks the agent token: %s", b)
			}
		})
	}
}

func TestIssueRoutes_AgentBearerNotForwarded(t *testing.T) {
	// The IssueSupport methods take no token arg — the agent's Bearer never
	// reaches the capability. Assert the create was called (the broker reached
	// the issue upstream) and that no audit event carries the agent token.
	is := &capturingIssueSupport{}
	sink := &recordingSink{}
	up := &capturingPRSupport{}
	authn := fakeAuthenticator{tokens: map[string]string{"agent-token-1": "alice"}}
	b, err := New(nil, up, is, nil, authn, sink, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(b.routes())
	t.Cleanup(srv.Close)

	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues", "agent-token-1", []byte(`{"title":"t","body":"b"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if is.createTitle != "t" {
		t.Errorf("CreateIssue not reached: title=%q (the broker must call the issue capability)", is.createTitle)
	}
	for _, e := range sink.events {
		// Audit events carry generic agent name + repo + op + verdict only —
		// never the token. Reasons here are nil on the allow path.
		if strings.Contains(e.Agent, "agent-token-1") {
			t.Errorf("audit event leaks token in agent field: %+v", e)
		}
	}
}

func TestIssueRoutes_NotAllowlisted(t *testing.T) {
	// allowed_ops excludes issue.* → 403 even with issues wired + valid bearer.
	is := &capturingIssueSupport{}
	up := &capturingPRSupport{}
	authn := fakeAuthenticator{tokens: map[string]string{"agent-token-1": "alice"}}
	b, err := New(nil, up, is, nil, authn, &recordingSink{}, Config{AllowedOps: []string{"pr.get"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(b.routes())
	t.Cleanup(srv.Close)

	resp := do(t, srv, http.MethodPost, "/owner%2Frepo.git/issues", "agent-token-1", []byte(`{"title":"t"}`))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (issue.create not in allowed_ops)", resp.StatusCode)
	}
}