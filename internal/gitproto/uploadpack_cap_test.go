package gitproto_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/pathmatch"
	"github.com/psenna/git-proxy/internal/port"
)

// recordingUploadPackUpstream is a port.Upstream that records whether
// UploadPack was called (i.e. the proxy forwarded an upload-pack request to the
// upstream) and what body it received. It returns a minimal empty v0 response.
// It is used to prove fail-closed: on an oversized upload-pack request the
// proxy must NOT forward (UploadPack must not be called).
type recordingUploadPackUpstream struct {
	called   bool
	forwarded []byte
}

func (r *recordingUploadPackUpstream) ListRefs(ctx context.Context, repo string) (port.Refs, error) {
	return port.Refs{}, nil
}
func (r *recordingUploadPackUpstream) ListRefsService(ctx context.Context, repo, service string) (port.Refs, error) {
	return port.Refs{}, nil
}
func (r *recordingUploadPackUpstream) UploadPack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error) {
	r.called = true
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	r.forwarded = b
	// A minimal v0 upload-pack response: a NAK pkt-line + flush.
	var buf bytes.Buffer
	buf.WriteString("0008NAK\n")
	buf.WriteString("0000")
	return io.NopCloser(&buf), nil
}
func (r *recordingUploadPackUpstream) ReceivePack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error) {
	return nil, errors.New("not used")
}

// TestProxyUploadPack_PassthroughCapsOversizedRequest verifies the passthrough
// branch of Proxy.UploadPack fail-closes on an oversized upload-pack request:
// it returns an error and does NOT forward the (truncated) request to the
// upstream. This is the DoS hardening the review flagged for the HTTP path —
// the same class as the SSH framer unbounded-buffer issue. Upload-pack REQUESTS
// are always tiny (the packfile is in the response); a request exceeding 1 MiB
// is a rogue/stream-truncated request and must be denied.
func TestProxyUploadPack_PassthroughCapsOversizedRequest(t *testing.T) {
	up := &recordingUploadPackUpstream{}
	proxy := gitproto.New(up) // passthrough (no read-deny, no enforcement)

	// Build an upload-pack request body exceeding the cap, with no `done`.
	sha := strings.Repeat("a", 40)
	one := encodeUploadPackPktLine(t, fmt.Sprintf("want %s\n", sha))
	target := gitproto.MaxUploadPackRequestBytes + 1<<19
	var body []byte
	for int64(len(body)) < target {
		body = append(body, one...)
	}

	var out bytes.Buffer
	err := proxy.UploadPack(context.Background(), "repo.git", bytes.NewReader(body), &out)
	if err == nil {
		t.Fatalf("UploadPack returned nil error for an oversized request (passthrough not fail-closed)")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error does not surface the cap reason: %v", err)
	}
	if up.called {
		t.Fatalf("FAIL-CLOSED VIOLATION: proxy forwarded the oversized/truncated upload-pack request to the upstream (passthrough branch must deny, not forward)")
	}
}

// TestProxyUploadPack_ReadProtectedCapsOversizedRequest verifies the
// read-protected branch of Proxy.UploadPack also fail-closes on an oversized
// request: it returns an error and does NOT assemble/serve a packfile from a
// truncated request. Both branches must be capped (fail-closed either way).
func TestProxyUploadPack_ReadProtectedCapsOversizedRequest(t *testing.T) {
	// A read-protected proxy with no mirror opener: any read-protected fetch
	// would already deny for lack of a mirror, but the size cap must fire
	// BEFORE the mirror-opener check so a rogue oversized request never reaches
	// object assembly. We assert the error is the size-cap error (not the
	// mirror-unavailable one), proving the cap runs first on both branches.
	up := &recordingUploadPackUpstream{}
	proxy := gitproto.New(up)
	proxy.SetReadDeny(nopMatcher()) // read protection ON (matcher non-nil), no opener

	sha := strings.Repeat("a", 40)
	one := encodeUploadPackPktLine(t, fmt.Sprintf("want %s\n", sha))
	target := gitproto.MaxUploadPackRequestBytes + 1<<19
	var body []byte
	for int64(len(body)) < target {
		body = append(body, one...)
	}

	var out bytes.Buffer
	err := proxy.UploadPack(context.Background(), "repo.git", bytes.NewReader(body), &out)
	if err == nil {
		t.Fatalf("UploadPack returned nil error for an oversized read-protected request (not fail-closed)")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error does not surface the cap reason (cap must fire before mirror check): %v", err)
	}
	if up.called {
		t.Fatalf("FAIL-CLOSED VIOLATION: proxy forwarded the oversized read-protected request to the upstream")
	}
}

// TestProxyUploadPack_SmallRequestForwarded verifies a real (tiny) upload-pack
// request under the cap is forwarded normally in passthrough mode — the cap
// must not break legitimate fetches.
func TestProxyUploadPack_SmallRequestForwarded(t *testing.T) {
	up := &recordingUploadPackUpstream{}
	proxy := gitproto.New(up)

	sha := strings.Repeat("a", 40)
	var body []byte
	body = append(body, encodeUploadPackPktLine(t, fmt.Sprintf("want %s ofs-delta\n", sha))...)
	body = append(body, []byte("0000")...) // flush
	body = append(body, encodeUploadPackPktLine(t, "done\n")...)
	body = append(body, []byte("0000")...) // flush

	var out bytes.Buffer
	if err := proxy.UploadPack(context.Background(), "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("UploadPack small request: unexpected error: %v", err)
	}
	if !up.called {
		t.Fatalf("proxy did not forward the small upload-pack request (passthrough broken)")
	}
	if !bytes.Equal(up.forwarded, body) {
		t.Fatalf("forwarded bytes do not match request: got %d want %d", len(up.forwarded), len(body))
	}
}

// encodeUploadPackPktLine encodes a pkt-line data payload (4-byte hex length
// prefix + payload) as a git client sends it.
func encodeUploadPackPktLine(t *testing.T, payload string) []byte {
	t.Helper()
	n := len(payload) + 4
	return []byte(fmt.Sprintf("%04x%s", n, payload))
}

// nopMatcher returns a pathmatch.Matcher that reports read protection as ON
// (non-nil) without matching any realistic path — built via the public pathmatch
// API so the proxy sees readDenyMatcher != nil (read protection ON).
func nopMatcher() *pathmatch.Matcher {
	// A pattern that matches nothing in the test repo (no "nonexistent/**"
	// path will appear). The matcher being non-nil is what switches UploadPack
	// into the read-protected branch.
	return pathmatch.New([]string{"nonexistent/**"})
}