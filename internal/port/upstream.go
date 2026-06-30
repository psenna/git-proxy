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
	// ListRefs performs ref discovery (GET /info/refs) for repo.
	ListRefs(ctx context.Context, repo string) (Refs, error)
	// UploadPack forwards a git-upload-pack request body and returns the
	// server's response stream.
	UploadPack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error)
	// ReceivePack forwards a git-receive-pack request body and returns the
	// server's response stream.
	ReceivePack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error)
}
