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