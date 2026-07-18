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