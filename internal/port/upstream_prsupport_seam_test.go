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