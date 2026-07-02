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

// TestPRSupport_StubsReturnErrNotImplemented asserts the PRSupport methods
// (BranchProtection, EnsurePR) return ErrNotImplemented — the v1 skeleton
// behaviour. The real GitHub REST calls are v2.
func TestPRSupport_StubsReturnErrNotImplemented(t *testing.T) {
	adapter := New(upstream.UpstreamConfig{Kind: "github", URL: "https://github.com/owner/repo"})
	prs, ok := interface{}(adapter).(port.PRSupport)
	if !ok {
		t.Fatal("adapter does not satisfy port.PRSupport")
	}
	if _, err := prs.BranchProtection(context.Background(), "owner/repo", "main"); !errors.Is(err, port.ErrNotImplemented) {
		t.Errorf("BranchProtection err = %v, want ErrNotImplemented", err)
	}
	if _, err := prs.EnsurePR(context.Background(), "owner/repo", "feat", "main", "title"); !errors.Is(err, port.ErrNotImplemented) {
		t.Errorf("EnsurePR err = %v, want ErrNotImplemented", err)
	}
}