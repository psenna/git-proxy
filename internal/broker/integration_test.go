package broker

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/upstream"
	"github.com/psenna/git-proxy/internal/upstream/github"
)

// fakeGHVault is a CredentialStore holding one repo's GitHub token. The adapter
// reads CredentialsFor(repo).Token for the Bearer leg; the agent never sees it.
type fakeGHVault struct{ token string }

func (f fakeGHVault) CredentialsFor(_ string) (port.Credentials, bool) {
	return port.Credentials{Token: f.token}, true
}

// fakeGitHub is a recording GitHub REST server mounted under /api/v3 (the
// GHES REST root the adapter derives from a non-github.com upstream URL). It
// captures the Authorization header of every request so the test can prove the
// proxy token (ghp_test) reached GitHub and the agent token (agent-token-1)
// never did. It serves BOTH the PR surface (pulls) and the issue surface
// (issues), so the same fake backs the PR integration test (issue routes are
// never hit there) and the issue integration test (which drives all nine ops).
type fakeGitHub struct {
	mu           sync.Mutex
	auths        []string
	mergeErr     int    // HTTP status to return on PUT .../pulls/7/merge (0 = 200 OK)
	issueErr     int    // HTTP status to return on any issue endpoint (0 = success)
	removedLabel string // last label captured from DELETE .../issues/1/labels/{label}
}

func (f *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/repo/pulls", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":7,"title":"t","state":"open","head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"https://gh/pull/7"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"number":7,"state":"open","head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"u"}]`))
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/pulls/7", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_, _ = w.Write([]byte(`{"number":7,"title":"t","state":"open","mergeable":true,"head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"u"}`))
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/pulls/7/merge", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.mergeErr != 0 {
			w.WriteHeader(f.mergeErr)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	// Issue surface: POST/GET /issues (create/list), GET/PATCH /issues/1
	// (get/close/reopen/edit), POST /issues/1/comments, POST /issues/1/labels
	// (add), DELETE /issues/1/labels/{label} (remove — subtree handler, since
	// the label name is a path segment the rest client URL-encodes). The list
	// returns one real issue (number 1) plus one PR (number 2, pull_request
	// non-null) so the test can prove the rest client filters PRs out of the
	// issues list.
	mux.HandleFunc("/api/v3/repos/owner/repo/issues", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.issueErr != 0 {
			w.WriteHeader(f.issueErr)
			return
		}
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":1,"title":"t","state":"open","body":"b","html_url":"https://gh/issues/1","labels":[{"name":"bug"}]}`))
		default: // GET list
			_, _ = w.Write([]byte(`[{"number":1,"title":"t","state":"open","html_url":"https://gh/issues/1","labels":[{"name":"bug"}]},{"number":2,"title":"pr","state":"open","html_url":"https://gh/pull/2","pull_request":{"url":"https://gh/pull/2"}}]`))
		}
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/issues/1", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.issueErr != 0 {
			w.WriteHeader(f.issueErr)
			return
		}
		_, _ = w.Write([]byte(`{"number":1,"title":"t","state":"open","body":"b","html_url":"https://gh/issues/1","labels":[{"name":"bug"}]}`))
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.issueErr != 0 {
			w.WriteHeader(f.issueErr)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/issues/1/labels", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.issueErr != 0 {
			w.WriteHeader(f.issueErr)
			return
		}
		_, _ = w.Write([]byte(`[{"name":"bug"},{"name":"p1"}]`))
	})
	// Subtree (trailing slash) for label removal — matches .../labels/{label}
	// but NOT the exact .../labels (add) pattern, so the two coexist on the mux.
	mux.HandleFunc("/api/v3/repos/owner/repo/issues/1/labels/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.issueErr != 0 {
			w.WriteHeader(f.issueErr)
			return
		}
		f.mu.Lock()
		f.removedLabel = strings.TrimPrefix(r.URL.Path, "/api/v3/repos/owner/repo/issues/1/labels/")
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (f *fakeGitHub) record(r *http.Request) {
	f.mu.Lock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.mu.Unlock()
}

func (f *fakeGitHub) authsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]string, len(f.auths))
	copy(cp, f.auths)
	return cp
}

func (f *fakeGitHub) lastRemovedLabel() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.removedLabel
}

// bootBroker wires a real broker over the given SCM and issue upstreams and
// runs it on a free port, returning its base URL, the shared audit sink, and a
// cancel func. Shared by bootIntegration (issueUp=nil — issues disabled) and
// the issue integration test (issueUp=adapter — the same fake GitHub serves
// PRs and issues, the v1 GitHub case).
func bootBroker(t *testing.T, cfg Config, scmUp, issueUp port.Upstream) (brokerURL string, sink *recordingSink, cancel context.CancelFunc) {
	t.Helper()
	authn := token.New(map[string]string{
		"agent-token-1": "alice",
		"bob-token-2":   "bob",
	})
	sink = &recordingSink{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b, err := New(ln, scmUp, issueUp, map[string]string{"owner/repo.git": "owner/repo.git"}, authn, sink, cfg)
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-errCh
		_ = ln.Close()
	})
	return "http://" + ln.Addr().String(), sink, cancel
}

// bootIntegration stands up a fake GitHub + real github adapter + real broker
// and returns the broker's base URL plus the fake GitHub for assertions. The
// broker's audit sink is shared so the test can inspect broker events. Issues
// are NOT wired (issueUp=nil) — issue routes return 501 here.
func bootIntegration(t *testing.T, cfg Config) (brokerURL string, gh *fakeGitHub, sink *recordingSink, cancel context.CancelFunc) {
	t.Helper()
	gh = &fakeGitHub{}
	srv := httptest.NewServer(gh.handler())
	t.Cleanup(srv.Close)

	adapter := github.New(upstream.UpstreamConfig{
		Kind:            "github",
		URL:             srv.URL, // non-github.com host → rest.BaseURL derives <srv.URL>/api/v3 (GHES path)
		CredentialsStore: fakeGHVault{token: "ghp_test"},
	})

	brokerURL, sink, cancel = bootBroker(t, cfg, adapter, nil)
	return brokerURL, gh, sink, cancel
}

// bootIntegrationIssues is bootIntegration with the github adapter wired as
// BOTH the SCM upstream (PRSupport) and the issue upstream (IssueSupport) —
// the v1 GitHub case where one provider serves PRs and issues from the same
// fake server. The broker type-asserts PRSupport off scmUp and IssueSupport
// off issueUp; passing the same *Adapter satisfies both.
func bootIntegrationIssues(t *testing.T, cfg Config) (brokerURL string, gh *fakeGitHub, sink *recordingSink, cancel context.CancelFunc) {
	t.Helper()
	gh = &fakeGitHub{}
	srv := httptest.NewServer(gh.handler())
	t.Cleanup(srv.Close)

	adapter := github.New(upstream.UpstreamConfig{
		Kind:            "github",
		URL:             srv.URL,
		CredentialsStore: fakeGHVault{token: "ghp_test"},
	})

	brokerURL, sink, cancel = bootBroker(t, cfg, adapter, adapter)
	return brokerURL, gh, sink, cancel
}

func req(t *testing.T, method, url, bearer string, body []byte) *http.Response {
	t.Helper()
	var br io.Reader
	if body != nil {
		br = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, br)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, url, err)
	}
	return resp
}

func TestIntegration_BrokerEndToEnd(t *testing.T) {
	brokerURL, gh, sink, _ := bootIntegration(t, Config{MergeMethod: "merge"})

	// 1. Create PR → 201.
	resp := req(t, http.MethodPost, brokerURL+"/owner%2Frepo.git/prs", "agent-token-1", []byte(`{"head":"feat","base":"main","title":"t"}`))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"number":7`) {
		t.Errorf("create body = %s, want number 7", body)
	}

	// 2. Get PR → 200.
	resp = req(t, http.MethodGet, brokerURL+"/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200", resp.StatusCode)
	}

	// 3. Merge PR → 204 (broker returns No Content on a successful merge).
	resp = req(t, http.MethodPost, brokerURL+"/owner%2Frepo.git/prs/7/merge", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("merge status = %d, want 204", resp.StatusCode)
	}

	// No-leak: the proxy token (ghp_test) reached GitHub on every request; the
	// agent token (agent-token-1) never did.
	auths := gh.authsSeen()
	if len(auths) < 3 {
		t.Fatalf("fake GitHub saw %d requests, want >=3", len(auths))
	}
	for _, a := range auths {
		if a != "Bearer ghp_test" {
			t.Errorf("fake GitHub Authorization = %q, want Bearer ghp_test", a)
		}
		if strings.Contains(a, "agent-token-1") {
			t.Errorf("agent token leaked to GitHub: %q", a)
		}
	}

	// Audit: broker recorded an allow per op, Transport "broker", no token leak.
	if len(sink.events) < 3 {
		t.Fatalf("audit recorded %d events, want >=3", len(sink.events))
	}
	for i, e := range sink.events {
		if e.Transport != "broker" {
			t.Errorf("event %d Transport = %q, want broker", i, e.Transport)
		}
		if strings.Contains(e.Agent, "ghp_test") || strings.Contains(e.Repo, "ghp_test") {
			t.Errorf("audit event %d leaks proxy token: %+v", i, e)
		}
		for _, r := range e.Reasons {
			if strings.Contains(r, "ghp_test") || strings.Contains(r, "agent-token-1") {
				t.Errorf("audit event %d reason leaks a token: %q", i, r)
			}
		}
	}
}

func TestIntegration_Negatives(t *testing.T) {
	brokerURL, _, _, _ := bootIntegration(t, Config{})

	// No Bearer → 401.
	resp := req(t, http.MethodGet, brokerURL+"/owner%2Frepo.git/prs/7", "", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-bearer status = %d, want 401", resp.StatusCode)
	}

	// Bad Bearer → 401.
	resp = req(t, http.MethodGet, brokerURL+"/owner%2Frepo.git/prs/7", "wrong", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad-bearer status = %d, want 401", resp.StatusCode)
	}

	// Unallowlisted agent → 403 (bob-token-2 authenticates as "bob"; only alice
	// is permitted).
	brokerURL2, _, _, _ := bootIntegration(t, Config{AllowedAgents: []string{"alice"}})
	resp = req(t, http.MethodGet, brokerURL2+"/owner%2Frepo.git/prs/7", "bob-token-2", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unallowlisted status = %d, want 403", resp.StatusCode)
	}
}

func TestIntegration_GitHubConflictMapsToBroker409(t *testing.T) {
	brokerURL, gh, _, _ := bootIntegration(t, Config{})
	gh.mergeErr = http.StatusConflict // GitHub says not-mergeable (409)

	resp := req(t, http.MethodPost, brokerURL+"/owner%2Frepo.git/prs/7/merge", "agent-token-1", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (GitHub 409 → broker 409): %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"not mergeable"`) {
		t.Errorf("body = %s, want generic 'not mergeable' reason", body)
	}
}

// TestIntegration_IssueRoutesEndToEnd drives all nine issue routes through the
// real github adapter (wired as BOTH the SCM and the issue upstream) into a real
// broker with a real token.Authenticator. It proves the end-to-end wiring the
// per-route unit tests cannot: that the proxy's GitHub token (ghp_test) reaches
// GitHub on the issue leg, the agent token (agent-token-1) never does, the audit
// sink records broker events with no token in any field, and ListIssues filters
// PRs out of the issues list. The issue surface is the v1 GitHub case — one
// provider serving PRs and issues from the same upstream.
func TestIntegration_IssueRoutesEndToEnd(t *testing.T) {
	brokerURL, gh, sink, _ := bootIntegrationIssues(t, Config{})
	const enc = "owner%2Frepo.git"

	// 1. Create issue → 201 with number + url.
	resp := req(t, http.MethodPost, brokerURL+"/"+enc+"/issues", "agent-token-1", []byte(`{"title":"t","body":"b"}`))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"number":1`) || !strings.Contains(string(body), `"url":"https://gh/issues/1"`) {
		t.Errorf("create body = %s, want number 1 + url", body)
	}

	// 2. List issues → 200; the fake returns issue 1 + PR 2 (pull_request
	// non-null) — the rest client must filter the PR out, so the body has
	// number 1 and NOT number 2.
	resp = req(t, http.MethodGet, brokerURL+"/"+enc+"/issues?state=open", "agent-token-1", nil)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"number":1`) {
		t.Errorf("list body = %s, want issue number 1", body)
	}
	if strings.Contains(string(body), `"number":2`) {
		t.Errorf("list body = %s, want PR number 2 filtered out (issues only)", body)
	}

	// 3. Get issue → 200.
	resp = req(t, http.MethodGet, brokerURL+"/"+enc+"/issues/1", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200", resp.StatusCode)
	}

	// 4. Comment → 204.
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues/1/comments", "agent-token-1", []byte(`{"body":"note"}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("comment status = %d, want 204", resp.StatusCode)
	}

	// 5. Close → 204.
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues/1/close", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("close status = %d, want 204", resp.StatusCode)
	}

	// 6. Reopen → 204.
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues/1/reopen", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("reopen status = %d, want 204", resp.StatusCode)
	}

	// 7. Edit → 200.
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues/1/edit", "agent-token-1", []byte(`{"title":"new"}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edit status = %d, want 200", resp.StatusCode)
	}

	// 8. Add labels → 200 with the resulting label set.
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues/1/labels", "agent-token-1", []byte(`{"labels":["bug","p1"]}`))
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add labels status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"bug"`) || !strings.Contains(string(body), `"p1"`) {
		t.Errorf("add labels body = %s, want bug + p1", body)
	}

	// 9. Remove label → 204; the label travels in the broker JSON body and the
	// rest client URL-encodes it onto the DELETE path. Assert the fake saw the
	// (decoded) label on the path.
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues/1/labels/remove", "agent-token-1", []byte(`{"label":"bug"}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove label status = %d, want 204", resp.StatusCode)
	}
	if gh.lastRemovedLabel() != "bug" {
		t.Errorf("removed label = %q, want bug (rest client must put it on the DELETE path)", gh.lastRemovedLabel())
	}

	// No-leak: the proxy token (ghp_test) reached GitHub on every issue request;
	// the agent token (agent-token-1) never did. At least nine issue requests
	// were made (one per op, list excluded from the count floor only loosely).
	auths := gh.authsSeen()
	if len(auths) < 9 {
		t.Fatalf("fake GitHub saw %d requests, want >=9 (one per issue op)", len(auths))
	}
	for i, a := range auths {
		if a != "Bearer ghp_test" {
			t.Errorf("fake GitHub Authorization[%d] = %q, want Bearer ghp_test (proxy token only)", i, a)
		}
		if strings.Contains(a, "agent-token-1") {
			t.Errorf("agent token leaked to GitHub: %q", a)
		}
	}

	// Audit: broker recorded an allow per op, Transport "broker", no token in any
	// field (Agent/Repo/Reasons). The agent name is "alice" (never the token).
	if len(sink.events) < 9 {
		t.Fatalf("audit recorded %d events, want >=9", len(sink.events))
	}
	for i, e := range sink.events {
		if e.Transport != "broker" {
			t.Errorf("event %d Transport = %q, want broker", i, e.Transport)
		}
		if e.Agent != "alice" {
			t.Errorf("event %d Agent = %q, want alice (never the raw token)", i, e.Agent)
		}
		if strings.Contains(e.Agent, "ghp_test") || strings.Contains(e.Repo, "ghp_test") {
			t.Errorf("audit event %d leaks proxy token: %+v", i, e)
		}
		for _, r := range e.Reasons {
			if strings.Contains(r, "ghp_test") || strings.Contains(r, "agent-token-1") {
				t.Errorf("audit event %d reason leaks a token: %q", i, r)
			}
		}
	}
}

// TestIntegration_IssueNegatives covers the issue-routes failure paths the
// happy-path test does not: missing/bad Bearer → 401 (auth gates before the 501
// and before any upstream call), an unallowlisted agent → 403, a GitHub 422 →
// broker 422 (the sentinel→status mapping holds for issues), and — critically —
// with NO issue upstream wired, issue routes return 501 per-op while PR routes
// still work (issues are opt-in/additive, the PRSupport startup fail-closed is
// unaffected).
func TestIntegration_IssueNegatives(t *testing.T) {
	// No/bad Bearer → 401 (auth runs first; never leak "issues configured").
	brokerURL, _, _, _ := bootIntegrationIssues(t, Config{})
	const enc = "owner%2Frepo.git"
	resp := req(t, http.MethodPost, brokerURL+"/"+enc+"/issues", "", []byte(`{"title":"t"}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no bearer: issue create status = %d, want 401", resp.StatusCode)
	}
	resp = req(t, http.MethodPost, brokerURL+"/"+enc+"/issues", "wrong", []byte(`{"title":"t"}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad bearer: issue create status = %d, want 401", resp.StatusCode)
	}

	// Unallowlisted agent → 403 (bob-token-2 authenticates as "bob"; only alice
	// is permitted).
	brokerURL2, _, _, _ := bootIntegrationIssues(t, Config{AllowedAgents: []string{"alice"}})
	resp = req(t, http.MethodPost, brokerURL2+"/"+enc+"/issues", "bob-token-2", []byte(`{"title":"t"}`))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unallowlisted: issue create status = %d, want 403", resp.StatusCode)
	}

	// GitHub 422 → broker 422 (the sentinel→status mapping holds for issues;
	// the error body is a generic class string, no upstream content).
	brokerURL3, gh, _, _ := bootIntegrationIssues(t, Config{})
	gh.issueErr = http.StatusUnprocessableEntity
	resp = req(t, http.MethodPost, brokerURL3+"/"+enc+"/issues", "agent-token-1", []byte(`{"title":"t"}`))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("github 422: issue create status = %d, want 422: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"error"`) {
		t.Errorf("github 422: body = %s, want a JSON error body", body)
	}
	if strings.Contains(string(body), "ghp_test") || strings.Contains(string(body), "agent-token-1") {
		t.Errorf("github 422: body leaks a token: %s", body)
	}

	// No issue upstream → issue routes 501 per-op while PR routes still 200.
	// bootIntegration wires issues=nil (issues opt-in). A missing Bearer still
	// 401s first (auth gates before the 501), so use a valid Bearer here.
	brokerURL4, _, _, _ := bootIntegration(t, Config{})
	resp = req(t, http.MethodPost, brokerURL4+"/"+enc+"/issues", "agent-token-1", []byte(`{"title":"t"}`))
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("no issue upstream: issue create status = %d, want 501: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "not implemented") {
		t.Errorf("no issue upstream: body = %s, want 'not implemented' reason", body)
	}
	// PR route still works with issues disabled (PRSupport unaffected).
	resp = req(t, http.MethodGet, brokerURL4+"/"+enc+"/prs/7", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("no issue upstream: PR get status = %d, want 200 (PRSupport unaffected)", resp.StatusCode)
	}
}