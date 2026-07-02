package port

import (
	"context"
	"errors"
	"io"
)

// Refs is the result of upstream ref discovery. For passthrough the body is
// streamed to the agent verbatim; later milestones parse it to enforce policy.
type Refs struct {
	Body        io.ReadCloser
	ContentType string
}

// Upstream is the proxy's handle on a single upstream git server. It is the
// SCM adapter seam: implementations talk to a plain git server (internal/
// upstream/plain), a GitHub repo (internal/upstream/github — skeleton), or a
// future GitLab/etc. adapter. Methods carry protocol bytes: passthrough
// implementations stream them untouched, while later milestones inspect and
// rewrite them to enforce policy.
//
// The proxy core depends ONLY on Upstream — never on the optional PRSupport
// sub-interface. An adapter that also speaks an SCM API (GitHub/GitLab)
// implements PRSupport in addition; code that wants to use it must type-assert
// (`if prs, ok := up.(PRSupport); ok { ... }`). This keeps the plain adapter
// unburdened and the core free of any SCM-specific assumption.
type Upstream interface {
	// ListRefs performs ref discovery (GET /info/refs) for repo, using the
	// git-upload-pack service advertisement. It is a convenience wrapper for
	// ListRefsService(ctx, repo, "git-upload-pack").
	ListRefs(ctx context.Context, repo string) (Refs, error)
	// ListRefsService fetches the ref advertisement for the given git service
	// ("git-upload-pack" | "git-receive-pack") as a raw smart-HTTP stream (with
	// the "# service=" preamble). The caller (e.g. the SSH frontend) fetches as
	// v0 — the implementation MUST NOT send a Git-Protocol: version=2 header so
	// the upstream returns v0 — and parses + re-emits. ListRefs delegates to
	// ListRefsService(ctx, repo, "git-upload-pack"). The returned Refs is
	// port-level (no gitproto type) to respect the port→gitproto import
	// direction; the SSH frontend imports gitproto to parse.
	ListRefsService(ctx context.Context, repo, service string) (Refs, error)
	// UploadPack forwards a git-upload-pack request body and returns the
	// server's response stream.
	UploadPack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error)
	// ReceivePack forwards a git-receive-pack request body and returns the
	// server's response stream.
	ReceivePack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error)
}

// PRSupport is an OPTIONAL capability sub-interface an Upstream MAY implement
// when the SCM provider exposes pull-request / branch-protection APIs (GitHub,
// GitLab). The proxy core NEVER depends on it: it is a seam for future
// integrations (e.g. a rule that requires a PR exists before pushing to a
// protected branch). Code that wants to use it must type-assert:
//
//	if prs, ok := up.(PRSupport); ok { ... }
//
// v1 ships the seam only: the method signatures are minimal real signatures
// (not an empty interface — an empty interface would be trivially satisfied by
// anything, defeating `var _ PRSupport = (*Adapter)(nil)` as a compile check).
// The GitHub skeleton (internal/upstream/github) implements both methods by
// returning ErrNotImplemented, with doc comments naming the real GitHub REST
// endpoints. The real implementations are v2.
type PRSupport interface {
	// BranchProtection fetches the branch-protection rules for branch on repo.
	// GitHub REST: GET /repos/{owner}/{repo}/branches/{branch}/protection.
	// v1 skeleton returns ErrNotImplemented.
	BranchProtection(ctx context.Context, repo, branch string) (BranchProtection, error)
	// EnsurePR creates a pull request on repo from head to base with title.
	// GitHub REST: POST /repos/{owner}/{repo}/pulls.
	// v1 skeleton returns ErrNotImplemented.
	EnsurePR(ctx context.Context, repo, head, base, title string) (PR, error)
}

// BranchProtection describes the protection rules on a branch. v1 ships the
// type only; the fields are filled in by the v2 GitHub REST implementation.
// The zero value is a usable placeholder for the skeleton.
type BranchProtection struct {
	// Protected reports whether the branch is protected.
	Protected bool
	// RequiredStatusChecks lists the status checks that must pass before a
	// push (GitHub "required_status_checks").
	RequiredStatusChecks []string
	// RequiredApprovals is the number of approving reviews required
	// (GitHub "required_pull_request_reviews").
	RequiredApprovals int
}

// PR describes a pull request created via EnsurePR. v1 ships the type only;
// the fields are filled in by the v2 GitHub REST implementation.
type PR struct {
	// Number is the GitHub PR number.
	Number int
	// URL is the HTML URL of the PR.
	URL string
}

// ErrNotImplemented is returned by capability stubs that are defined but not
// yet implemented. It lets a skeleton adapter (e.g. the v1 GitHub adapter)
// compile + register while signalling "not full v1 functionality" (issue #14):
// the git-protocol methods are real (delegated to plain HTTP), while the
// SCM-specific capabilities return this sentinel. Code that type-asserts to
// PRSupport must treat ErrNotImplemented as "capability present but not
// wired" — distinct from a type-assertion failure (capability absent).
var ErrNotImplemented = errors.New("git-proxy: capability not implemented")