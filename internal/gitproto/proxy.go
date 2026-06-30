// Package gitproto orchestrates git smart-HTTP protocol streams between the
// agent and the upstream. The Proxy owns an port.Upstream and streams protocol
// bytes through without inspection: passthrough. Later milestones insert ref
// and pack inspection at this layer.
package gitproto

import (
	"context"
	"fmt"
	"io"

	"github.com/psenna/git-proxy/internal/port"
)

// Proxy streams git protocol operations from an agent-facing body to an
// upstream and copies the upstream response back to the agent.
type Proxy struct {
	up port.Upstream
}

// New returns a Proxy that forwards through up.
func New(up port.Upstream) *Proxy {
	return &Proxy{up: up}
}

// UploadPack streams a git-upload-pack (fetch/clone) exchange: body is the
// agent's request, w receives the upstream's pack report.
func (p *Proxy) UploadPack(ctx context.Context, repo string, body io.Reader, w io.Writer) error {
	rc, err := p.up.UploadPack(ctx, repo, body)
	if err != nil {
		return fmt.Errorf("gitproto: upload-pack: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return stream(rc, w)
}

// ReceivePack streams a git-receive-pack (push) exchange: body is the agent's
// pack, w receives the upstream's ref-update report.
func (p *Proxy) ReceivePack(ctx context.Context, repo string, body io.Reader, w io.Writer) error {
	rc, err := p.up.ReceivePack(ctx, repo, body)
	if err != nil {
		return fmt.Errorf("gitproto: receive-pack: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return stream(rc, w)
}

// stream copies the upstream response body to the agent writer. Flushing, if
// the writer supports it, is the caller's responsibility.
func stream(rc io.Reader, w io.Writer) error {
	if _, err := io.Copy(w, rc); err != nil {
		return fmt.Errorf("gitproto: stream: %w", err)
	}
	return nil
}