// Package gitproto orchestrates git smart-HTTP protocol streams between the
// agent and the upstream. The Proxy owns a port.Upstream and parses the
// upload-pack and receive-pack state machines as they flow through, then
// forwards the bytes verbatim: parse-and-forward. No policy is applied yet; the
// parsed structures are the inspection seam later milestones (push
// enforcement, read protection) build on.
package gitproto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/port"
)

// Proxy parses git protocol operations flowing from an agent-facing body to an
// upstream and copies the upstream response back to the agent. It is
// behaviorally passthrough: bytes are forwarded untouched.
type Proxy struct {
	up port.Upstream
}

// New returns a Proxy that forwards through up.
func New(up port.Upstream) *Proxy {
	return &Proxy{up: up}
}

// UploadPack handles a git-upload-pack (fetch/clone) exchange. The agent's
// request body (want/have negotiation) is parsed for the inspection seam and
// forwarded to the upstream; the upstream's response is parsed and forwarded
// byte-exact to the agent.
func (p *Proxy) UploadPack(ctx context.Context, repo string, body io.Reader, w io.Writer) error {
	buf, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("gitproto: read upload-pack request: %w", err)
	}
	// Parse the request for the inspection seam. Failures are non-fatal:
	// passthrough must not break on an unparseable request, and no policy is
	// applied yet.
	if _, perr := ParseUploadPackRequest(bytes.NewReader(buf)); perr != nil {
		log.Printf("gitproto: upload-pack request parse: %v", perr)
	}
	rc, err := p.up.UploadPack(ctx, repo, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("gitproto: upload-pack: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return forwardStream(rc, w)
}

// ReceivePack handles a git-receive-pack (push) exchange. The agent's request
// body (ref-update commands + packfile) is parsed for the inspection seam and
// forwarded to the upstream; the upstream's response is parsed and forwarded
// byte-exact to the agent.
func (p *Proxy) ReceivePack(ctx context.Context, repo string, body io.Reader, w io.Writer) error {
	buf, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("gitproto: read receive-pack request: %w", err)
	}
	if _, perr := ParseReceivePackRequest(bytes.NewReader(buf)); perr != nil {
		log.Printf("gitproto: receive-pack request parse: %v", perr)
	}
	rc, err := p.up.ReceivePack(ctx, repo, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("gitproto: receive-pack: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return forwardStream(rc, w)
}

// forwardStream copies the upstream response to the agent writer using
// structured pkt-line parsing: each pkt-line is read via the codec and its raw
// bytes are written through verbatim, preserving byte-exact passthrough. When
// the scanner reaches a non-pkt-line section (the packfile body of a non-
// sideband upload-pack response), it switches to raw copy for the remainder.
func forwardStream(rc io.Reader, w io.Writer) error {
	s := pktline.NewScanner(rc)
	for s.Scan() {
		if _, err := w.Write(s.Raw()); err != nil {
			return fmt.Errorf("gitproto: forward pkt-line: %w", err)
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("gitproto: scan response: %w", err)
	}
	// A Raw marker means the scanner read bytes that are not a pkt-line prefix
	// (typically the PACK magic of a packfile). Forward those bytes and copy the
	// rest of the stream raw, byte-exact.
	if s.Marker() == pktline.Raw {
		if _, err := w.Write(s.Pending()); err != nil {
			return fmt.Errorf("gitproto: forward raw head: %w", err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			return fmt.Errorf("gitproto: forward raw body: %w", err)
		}
	}
	return nil
}
