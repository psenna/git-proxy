package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/upstream"
)

// TestSelfRegister_GitHubOnDefaultRegistry asserts the GitHub adapter
// self-registers as "github" on the upstream default registry via init().
func TestSelfRegister_GitHubOnDefaultRegistry(t *testing.T) {
	f, ok := upstream.Lookup("github")
	if !ok {
		t.Fatal(`upstream.Lookup("github"): want found (self-registered via init)`)
	}
	up, err := f(upstream.UpstreamConfig{URL: "https://github.com/owner/repo"})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if up == nil {
		t.Fatal("factory returned nil Upstream")
	}
}

// TestBuild_GitHubReturnsUpstreamAndPRSupport asserts Build with Kind "github"
// returns a port.Upstream that ALSO satisfies port.PRSupport (type-assert).
// This proves the GitHub skeleton implements both seams.
func TestBuild_GitHubReturnsUpstreamAndPRSupport(t *testing.T) {
	up, err := upstream.Build(upstream.UpstreamConfig{
		Kind: "github",
		URL:  "https://github.com/owner/repo",
	})
	if err != nil {
		t.Fatalf("Build github: %v", err)
	}
	if up == nil {
		t.Fatal("Build github: nil Upstream")
	}
	prs, ok := up.(port.PRSupport)
	if !ok {
		t.Fatal("Build github: Upstream does not satisfy port.PRSupport (type-assert failed)")
	}
	if prs == nil {
		t.Fatal("Build github: PRSupport is nil")
	}
}

// TestGitProtocol_DelegatesToPlain asserts the git-protocol methods DELEGATE to
// the plain HTTP transport (GitHub speaks smart-HTTP git at /info/refs,
// /git-upload-pack, /git-receive-pack — delegation is real, not a stub). A stub
// HTTP server stands in for GitHub: the GitHub adapter's ListRefs must reach
// it via the embedded plain upstream.
func TestGitProtocol_DelegatesToPlain(t *testing.T) {
	var hitPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	adapter := New(upstream.UpstreamConfig{Kind: "github", URL: srv.URL})
	refs, err := adapter.ListRefs(context.Background(), "test.git")
	if err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	defer func() { _ = refs.Body.Close() }()
	if hitPath != "/test.git/info/refs" {
		t.Fatalf("ListRefs hit %q, want /test.git/info/refs (delegation to plain)", hitPath)
	}
}

// TestPRSupport_BranchProtectionStillStub asserts BranchProtection remains a
// stub (the real REST call is a follow-up) while EnsurePR is now wired and fails
// closed with port.ErrUnauthorized when no token is configured for the repo
// (never anonymous).
func TestPRSupport_BranchProtectionStillStub(t *testing.T) {
	adapter := New(upstream.UpstreamConfig{Kind: "github", URL: "https://github.com/owner/repo"})
	prs, ok := interface{}(adapter).(port.PRSupport)
	if !ok {
		t.Fatal("adapter does not satisfy port.PRSupport")
	}
	if _, err := prs.BranchProtection(context.Background(), "owner/repo", "main"); !errors.Is(err, port.ErrNotImplemented) {
		t.Errorf("BranchProtection err = %v, want ErrNotImplemented", err)
	}
	// No token configured → fail closed, never an anonymous REST call.
	if _, err := prs.EnsurePR(context.Background(), "owner/repo", "feat", "main", "title"); !errors.Is(err, port.ErrUnauthorized) {
		t.Errorf("EnsurePR err = %v, want ErrUnauthorized (fail closed, no token)", err)
	}
}

// fakeVault is a minimal port.CredentialStore holding one repo's GitHub token.
type fakeVault struct {
	token string
}

func (f fakeVault) CredentialsFor(repo string) (port.Credentials, bool) {
	return port.Credentials{Token: f.token}, true
}

// TestPRSupport_RealCallsAttachTokenAndFailClosed boots a fake GitHub REST
// server and an adapter with a real token vault, then drives each PRSupport
// method end-to-end: it asserts the proxy's token (ghp_test) is sent as a
// Bearer header and the request paths use owner/repo (no .git), and that an
// unknown repo (no token) fails closed with ErrUnauthorized rather than calling
// GitHub anonymously.
func TestPRSupport_RealCallsAttachTokenAndFailClosed(t *testing.T) {
	const proxyToken = "ghp_test"
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		switch r.URL.Path {
		case "/api/v3/repos/owner/repo/pulls":
			if r.Method == http.MethodPost {
				_, _ = w.Write([]byte(`{"number":7,"title":"t","state":"open","head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"https://gh/pull/7"}`))
				return
			}
			_, _ = w.Write([]byte(`[{"number":7,"state":"open","head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"u"}]`))
			return
		case "/api/v3/repos/owner/repo/pulls/7":
			_, _ = w.Write([]byte(`{"number":7,"title":"t","state":"open","mergeable":true,"head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"u"}`))
			return
		case "/api/v3/repos/owner/repo/pulls/7/merge":
			w.WriteHeader(http.StatusOK)
			return
		case "/api/v3/repos/owner/repo/pulls/7/reviews":
			w.WriteHeader(http.StatusCreated)
			return
		case "/api/v3/repos/owner/repo/issues/7/comments":
			w.WriteHeader(http.StatusCreated)
			return
		case "/api/v3/repos/owner/repo/commits/abc/check-runs":
			_, _ = w.Write([]byte(`{"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}`))
			return
		case "/api/v3/repos/owner/repo/actions/runs":
			_, _ = w.Write([]byte(`{"workflow_runs":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	adapter := New(upstream.UpstreamConfig{Kind: "github", URL: srv.URL, CredentialsStore: fakeVault{token: proxyToken}})
	// Compile-time check that *Adapter satisfies port.PRSupport (panics at build
	// time if it ever stops conforming); avoids an unchecked type assertion.
	var prs port.PRSupport = adapter
	ctx := context.Background()

	pr, err := prs.EnsurePR(ctx, "owner/repo.git", "feat", "main", "t")
	if err != nil {
		t.Fatalf("EnsurePR: %v", err)
	}
	if pr.Number != 7 || pr.URL == "" {
		t.Errorf("EnsurePR PR = %+v", pr)
	}
	if gotAuth != "Bearer "+proxyToken {
		t.Errorf("EnsurePR auth = %q, want Bearer %q", gotAuth, proxyToken)
	}
	if gotPath != "/api/v3/repos/owner/repo/pulls" {
		t.Errorf("EnsurePR path = %q, want /api/v3/repos/owner/repo/pulls (no .git)", gotPath)
	}

	state, err := prs.GetPR(ctx, "owner/repo.git", 7)
	if err != nil {
		t.Fatalf("GetPR: %v", err)
	}
	if state.Number != 7 || state.Head != "feat" || state.Mergeable == nil || !*state.Mergeable {
		t.Errorf("GetPR state = %+v", state)
	}

	list, err := prs.ListPRs(ctx, "owner/repo.git", "open")
	if err != nil {
		t.Fatalf("ListPRs: %v", err)
	}
	if len(list) != 1 || list[0].Number != 7 {
		t.Errorf("ListPRs = %+v", list)
	}

	if err := prs.MergePR(ctx, "owner/repo.git", 7, "merge"); err != nil {
		t.Fatalf("MergePR: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("MergePR method = %q, want PUT", gotMethod)
	}

	if err := prs.CommentPR(ctx, "owner/repo.git", 7, "lgtm"); err != nil {
		t.Fatalf("CommentPR: %v", err)
	}
	if err := prs.ReviewPR(ctx, "owner/repo.git", 7, "APPROVE", "ship"); err != nil {
		t.Fatalf("ReviewPR: %v", err)
	}

	summary, err := prs.Checks(ctx, "owner/repo.git", "abc")
	if err != nil {
		t.Fatalf("Checks: %v", err)
	}
	if summary.Overall != "success" || len(summary.Checks) != 1 {
		t.Errorf("Checks summary = %+v", summary)
	}

	// Fail-closed: a repo with no token configured must NOT call GitHub
	// anonymously; it returns ErrUnauthorized before any request leaves.
	noTokenAdapter := New(upstream.UpstreamConfig{Kind: "github", URL: srv.URL, CredentialsStore: emptyVault{}})
	var unknownPRs port.PRSupport = noTokenAdapter
	if _, err := unknownPRs.EnsurePR(ctx, "owner/repo.git", "feat", "main", "t"); !errors.Is(err, port.ErrUnauthorized) {
		t.Errorf("EnsurePR with no token err = %v, want ErrUnauthorized", err)
	}
}

// emptyVault is a port.CredentialStore that has no credentials for any repo
// (CredentialsFor returns false), modelling "token not configured".
type emptyVault struct{}

func (emptyVault) CredentialsFor(repo string) (port.Credentials, bool) { return port.Credentials{}, false }

// TestBuild_GitHubReturnsIssueSupport asserts Build with Kind "github" returns
// a port.Upstream that ALSO satisfies port.IssueSupport — proving the GitHub
// adapter implements the issue seam, so it can be built separately as the
// issue_upstream and the broker can type-assert IssueSupport off it.
func TestBuild_GitHubReturnsIssueSupport(t *testing.T) {
	up, err := upstream.Build(upstream.UpstreamConfig{
		Kind: "github",
		URL:  "https://github.com/owner/repo",
	})
	if err != nil {
		t.Fatalf("Build github: %v", err)
	}
	is, ok := up.(port.IssueSupport)
	if !ok {
		t.Fatal("Build github: Upstream does not satisfy port.IssueSupport (type-assert failed)")
	}
	if is == nil {
		t.Fatal("Build github: IssueSupport is nil")
	}
}

// TestIssueSupport_RealCallsAttachTokenAndFailClosed boots a fake GitHub REST
// server and an adapter with a real token vault, then drives each IssueSupport
// method end-to-end through the REST client. It asserts the proxy's token
// (ghp_test) is sent as a Bearer header, the request paths use owner/repo (no
// .git), the rest→port mapping (Issue/IssueState with flat labels) is correct,
// and that a repo with no token fails closed with ErrUnauthorized rather than
// calling GitHub anonymously. The adapter is built as it would be for the
// issue_upstream — the same github adapter, used for issues.
func TestIssueSupport_RealCallsAttachTokenAndFailClosed(t *testing.T) {
	const proxyToken = "ghp_test"
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v3/repos/owner/repo/issues":
			_, _ = w.Write([]byte(`{"number":11,"title":"t","state":"open","body":"b","html_url":"https://gh/issues/11","labels":[]}`))
			return
		case "GET /api/v3/repos/owner/repo/issues/11":
			_, _ = w.Write([]byte(`{"number":11,"title":"t","state":"open","body":"b","html_url":"https://gh/issues/11","labels":[{"name":"bug"}]}`))
			return
		case "GET /api/v3/repos/owner/repo/issues":
			// One real issue + one PR (GitHub models every PR as an issue); the PR
			// carries a non-null pull_request object and must be filtered out.
			_, _ = w.Write([]byte(`[{"number":11,"state":"open","html_url":"u"},{"number":12,"state":"open","html_url":"p","pull_request":{"url":"x"}}]`))
			return
		case "POST /api/v3/repos/owner/repo/issues/11/comments":
			w.WriteHeader(http.StatusCreated)
			return
		case "PATCH /api/v3/repos/owner/repo/issues/11":
			_, _ = w.Write([]byte(`{"number":11,"title":"t","state":"open","body":"b","html_url":"https://gh/issues/11","labels":[{"name":"bug"},{"name":"p1"}]}`))
			return
		case "POST /api/v3/repos/owner/repo/issues/11/labels":
			_, _ = w.Write([]byte(`[{"name":"bug"},{"name":"p1"}]`))
			return
		case "DELETE /api/v3/repos/owner/repo/issues/11/labels/bug":
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	adapter := New(upstream.UpstreamConfig{Kind: "github", URL: srv.URL, CredentialsStore: fakeVault{token: proxyToken}})
	// Compile-time check that *Adapter satisfies port.IssueSupport (panics at
	// build time if it ever stops conforming); avoids an unchecked assertion.
	var is port.IssueSupport = adapter
	ctx := context.Background()

	issue, err := is.CreateIssue(ctx, "owner/repo.git", "t", "b")
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Number != 11 || issue.URL != "https://gh/issues/11" {
		t.Errorf("CreateIssue Issue = %+v", issue)
	}
	if gotAuth != "Bearer "+proxyToken {
		t.Errorf("CreateIssue auth = %q, want Bearer %q", gotAuth, proxyToken)
	}

	state, err := is.GetIssue(ctx, "owner/repo.git", 11)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if state.Number != 11 || state.Title != "t" || state.State != "open" || state.URL != "https://gh/issues/11" {
		t.Errorf("GetIssue IssueState = %+v", state)
	}
	if len(state.Labels) != 1 || state.Labels[0] != "bug" {
		t.Errorf("GetIssue Labels = %v, want [bug] (flat, from label objects)", state.Labels)
	}

	list, err := is.ListIssues(ctx, "owner/repo.git", "open")
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	// The PR (#12) must be filtered out; only the issue (#11) remains.
	if len(list) != 1 || list[0].Number != 11 {
		t.Errorf("ListIssues = %+v, want only [#11] (PR filtered)", list)
	}

	if err := is.CommentIssue(ctx, "owner/repo.git", 11, "note"); err != nil {
		t.Fatalf("CommentIssue: %v", err)
	}
	if err := is.CloseIssue(ctx, "owner/repo.git", 11); err != nil {
		t.Fatalf("CloseIssue: %v", err)
	}
	if err := is.ReopenIssue(ctx, "owner/repo.git", 11); err != nil {
		t.Fatalf("ReopenIssue: %v", err)
	}

	edited, err := is.EditIssue(ctx, "owner/repo.git", 11, "t", "")
	if err != nil {
		t.Fatalf("EditIssue: %v", err)
	}
	if edited.Number != 11 {
		t.Errorf("EditIssue IssueState = %+v", edited)
	}

	labels, err := is.AddLabels(ctx, "owner/repo.git", 11, []string{"bug", "p1"})
	if err != nil {
		t.Fatalf("AddLabels: %v", err)
	}
	if len(labels) != 2 || labels[0] != "bug" || labels[1] != "p1" {
		t.Errorf("AddLabels = %v, want [bug p1]", labels)
	}

	if err := is.RemoveLabel(ctx, "owner/repo.git", 11, "bug"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}

	// Fail-closed: a repo with no token configured must NOT call GitHub
	// anonymously; it returns ErrUnauthorized before any request leaves.
	noTokenAdapter := New(upstream.UpstreamConfig{Kind: "github", URL: srv.URL, CredentialsStore: emptyVault{}})
	var unknownIssues port.IssueSupport = noTokenAdapter
	if _, err := unknownIssues.CreateIssue(ctx, "owner/repo.git", "t", "b"); !errors.Is(err, port.ErrUnauthorized) {
		t.Errorf("CreateIssue with no token err = %v, want ErrUnauthorized", err)
	}
}