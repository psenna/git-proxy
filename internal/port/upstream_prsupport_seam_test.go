package port

import (
	"context"
	"errors"
	"testing"
)

// TestPRSupport_SeamAndErrNotImplemented asserts the optional PRSupport
// capability sub-interface exists with minimal REAL signatures (not an empty
// interface that is trivially satisfied) and the ErrNotImplemented sentinel
// is defined. A skeleton adapter returning ErrNotImplemented must satisfy
// PRSupport so `var _ port.PRSupport = (*Adapter)(nil)` is a real compile
// check, not a no-op.
func TestPRSupport_SeamAndErrNotImplemented(t *testing.T) {
	// ErrNotImplemented is a non-nil sentinel error.
	if errNotImplemented == nil {
		t.Fatal("ErrNotImplemented is nil; want a non-nil sentinel")
	}
	if !errors.Is(errNotImplemented, ErrNotImplemented) {
		t.Fatal("ErrNotImplemented must satisfy errors.Is(ErrNotImplemented)")
	}

	// PRSupport is a non-empty interface: a stub implementing both methods by
	// returning ErrNotImplemented must satisfy it. An empty interface would
	// be trivially satisfied by anything — defeating the compile-check.
	var _ PRSupport = (*prSupportStub)(nil)

	// The stub's methods return ErrNotImplemented (the skeleton behavior).
	got := &prSupportStub{}
	if _, err := got.BranchProtection(context.Background(), "repo", "branch"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("BranchProtection err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.EnsurePR(context.Background(), "repo", "head", "base", "title"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("EnsurePR err = %v, want ErrNotImplemented", err)
	}
	// The v2 PR/CI capability methods are also part of the seam; a stub that
	// returns ErrNotImplemented for them satisfies PRSupport (proving the new
	// signatures are real, not no-ops) and models the "capability present but
	// not wired" case a partial adapter (e.g. a future GitLab adapter) hits.
	if _, err := got.GetPR(context.Background(), "repo", 1); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("GetPR err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.ListPRs(context.Background(), "repo", "open"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ListPRs err = %v, want ErrNotImplemented", err)
	}
	if err := got.MergePR(context.Background(), "repo", 1, "merge"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("MergePR err = %v, want ErrNotImplemented", err)
	}
	if err := got.CommentPR(context.Background(), "repo", 1, "body"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("CommentPR err = %v, want ErrNotImplemented", err)
	}
	if err := got.ReviewPR(context.Background(), "repo", 1, "COMMENT", "body"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ReviewPR err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.Checks(context.Background(), "repo", "ref"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Checks err = %v, want ErrNotImplemented", err)
	}
}

// errNotImplemented is a package-internal alias so this test can reference the
// sentinel before it is defined in upstream.go (TDD red). Once upstream.go
// defines ErrNotImplemented, this alias is the same variable.
var errNotImplemented = ErrNotImplemented

// prSupportStub is a minimal PRSupport implementation returning
// ErrNotImplemented from both methods, proving PRSupport has real (non-empty)
// signatures.
type prSupportStub struct{}

func (prSupportStub) BranchProtection(ctx context.Context, repo, branch string) (BranchProtection, error) {
	return BranchProtection{}, ErrNotImplemented
}

func (prSupportStub) EnsurePR(ctx context.Context, repo, head, base, title string) (PR, error) {
	return PR{}, ErrNotImplemented
}

func (prSupportStub) GetPR(ctx context.Context, repo string, number int) (PRState, error) {
	return PRState{}, ErrNotImplemented
}

func (prSupportStub) ListPRs(ctx context.Context, repo, state string) ([]PRState, error) {
	return nil, ErrNotImplemented
}

func (prSupportStub) MergePR(ctx context.Context, repo string, number int, method string) error {
	return ErrNotImplemented
}

func (prSupportStub) CommentPR(ctx context.Context, repo string, number int, body string) error {
	return ErrNotImplemented
}

func (prSupportStub) ReviewPR(ctx context.Context, repo string, number int, event, body string) error {
	return ErrNotImplemented
}

func (prSupportStub) Checks(ctx context.Context, repo, ref string) (CheckSummary, error) {
	return CheckSummary{}, ErrNotImplemented
}

// TestIssueSupport_SeamAndErrNotImplemented asserts the optional IssueSupport
// capability sub-interface exists with minimal REAL signatures (not an empty
// interface that is trivially satisfied) and a skeleton adapter returning
// ErrNotImplemented satisfies it — so `var _ port.IssueSupport = (*Adapter)(nil)`
// is a real compile check, not a no-op. It models the "capability present but not
// wired" case a partial adapter (e.g. one that implements PRs but not issues) hits;
// the broker maps that to HTTP 501 per-op.
func TestIssueSupport_SeamAndErrNotImplemented(t *testing.T) {
	// IssueSupport is a non-empty interface: a stub implementing every method by
	// returning ErrNotImplemented must satisfy it.
	var _ IssueSupport = (*issueSupportStub)(nil)

	got := &issueSupportStub{}
	if _, err := got.CreateIssue(context.Background(), "repo", "title", "body"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("CreateIssue err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.GetIssue(context.Background(), "repo", 1); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("GetIssue err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.ListIssues(context.Background(), "repo", "open"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ListIssues err = %v, want ErrNotImplemented", err)
	}
	if err := got.CommentIssue(context.Background(), "repo", 1, "body"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("CommentIssue err = %v, want ErrNotImplemented", err)
	}
	if err := got.CloseIssue(context.Background(), "repo", 1); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("CloseIssue err = %v, want ErrNotImplemented", err)
	}
	if err := got.ReopenIssue(context.Background(), "repo", 1); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ReopenIssue err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.EditIssue(context.Background(), "repo", 1, "title", "body"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("EditIssue err = %v, want ErrNotImplemented", err)
	}
	if _, err := got.AddLabels(context.Background(), "repo", 1, []string{"bug"}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("AddLabels err = %v, want ErrNotImplemented", err)
	}
	if err := got.RemoveLabel(context.Background(), "repo", 1, "bug"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("RemoveLabel err = %v, want ErrNotImplemented", err)
	}
}

// issueSupportStub is a minimal IssueSupport implementation returning
// ErrNotImplemented from every method, proving IssueSupport has real (non-empty)
// signatures.
type issueSupportStub struct{}

func (issueSupportStub) CreateIssue(ctx context.Context, repo, title, body string) (Issue, error) {
	return Issue{}, ErrNotImplemented
}

func (issueSupportStub) GetIssue(ctx context.Context, repo string, number int) (IssueState, error) {
	return IssueState{}, ErrNotImplemented
}

func (issueSupportStub) ListIssues(ctx context.Context, repo, state string) ([]IssueState, error) {
	return nil, ErrNotImplemented
}

func (issueSupportStub) CommentIssue(ctx context.Context, repo string, number int, body string) error {
	return ErrNotImplemented
}

func (issueSupportStub) CloseIssue(ctx context.Context, repo string, number int) error {
	return ErrNotImplemented
}

func (issueSupportStub) ReopenIssue(ctx context.Context, repo string, number int) error {
	return ErrNotImplemented
}

func (issueSupportStub) EditIssue(ctx context.Context, repo string, number int, title, body string) (IssueState, error) {
	return IssueState{}, ErrNotImplemented
}

func (issueSupportStub) AddLabels(ctx context.Context, repo string, number int, labels []string) ([]string, error) {
	return nil, ErrNotImplemented
}

func (issueSupportStub) RemoveLabel(ctx context.Context, repo string, number int, label string) error {
	return ErrNotImplemented
}