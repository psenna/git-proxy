package port

import (
	"context"
	"io"
)

// Refs is the result of upstream ref discovery. For passthrough the body is
// streamed to the agent verbatim; later milestones parse it to enforce policy.
type Refs struct {
	Body        io.ReadCloser
	ContentType string
}

// Upstream is the proxy's handle on a single upstream git server. Methods carry
// protocol bytes: passthrough implementations stream them untouched, while
// later milestones inspect and rewrite them to enforce policy.
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
