package gitproto_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/gitx"
	_ "github.com/psenna/git-proxy/internal/policy/rules" // register rules
	"github.com/psenna/git-proxy/internal/port"
)

// fakeUpstream records the body the proxy forwards and returns a canned
// receive-pack response (unpack ok + ok ref + flush) so the proxy can stream it
// back to the agent. It implements port.Upstream.
type fakeUpstream struct {
	forwarded []byte
	resp      []byte
}

func (f *fakeUpstream) ListRefs(ctx context.Context, repo string) (port.Refs, error) {
	return port.Refs{}, nil
}
func (f *fakeUpstream) ListRefsService(ctx context.Context, repo, service string) (port.Refs, error) {
	return port.Refs{}, nil
}
func (f *fakeUpstream) UploadPack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error) {
	return nil, nil
}
func (f *fakeUpstream) ReceivePack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error) {
	b, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	f.forwarded = b
	return io.NopCloser(bytes.NewReader(f.resp)), nil
}

// fakeCredStore is a port.CredentialStore that always returns the same creds,
// used to embed upstream credentials in a mirror's fetch URL for the
// creds-isolation deny-reason test.
type fakeCredStore struct {
	username, password string
}

func (f fakeCredStore) CredentialsFor(repo string) (port.Credentials, bool) {
	return port.Credentials{Username: f.username, Password: f.password}, true
}

// testBareRoot is set by tests so the mirror opener can find the upstream bare
// repo the mirror clones from.
var testBareRoot string

// cannedReceivePackResponse returns a valid report-status the fake upstream
// streams back to the proxy on an allowed push.
func cannedReceivePackResponse(t *testing.T, ref string) []byte {
	t.Helper()
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	if err := e.EncodeString("unpack ok\n"); err != nil {
		t.Fatalf("encode unpack: %v", err)
	}
	if err := e.EncodeString("ok " + ref + "\n"); err != nil {
		t.Fatalf("encode ok: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return buf.Bytes()
}

// testMirrorOpener opens a mirror against testBareRoot/repo.git, rooted in a
// fresh temp dir per call (no caching needed for unit tests).
func testMirrorOpener(t *testing.T) gitproto.MirrorOpener {
	t.Helper()
	return func(ctx context.Context, repo string) (*gitx.Mirror, error) {
		return gitx.Open(ctx, "file://"+testBareRoot, repo, t.TempDir(), nil)
	}
}

// TestProxyReceivePack_AllowForwardsOriginalBytes wires an engine that allows a
// create to refs/heads/feat/x; the proxy must forward the original buffered
// request bytes verbatim to the upstream and stream the upstream response back.
func TestProxyReceivePack_AllowForwardsOriginalBytes(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	ref := "refs/heads/feat/x"
	// Build the packfile for the create's new SHA.
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	// Seed the bare upstream the mirror clones.
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	body := buildPushRequestWithNew(t, ref, tip, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28) // 256 MiB

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if !bytes.Equal(up.forwarded, body) {
		t.Fatalf("upstream received %d bytes, want original %d (byte-exact forward)", len(up.forwarded), len(body))
	}
	if !bytes.Contains(out.Bytes(), []byte("ok "+ref)) {
		t.Fatalf("proxy response missing upstream ok line; got %x", out.Bytes())
	}
}

// TestProxyReceivePack_DenyWritesReportStatusNoForward wires an engine that
// denies (empty branch_pattern allow list); the proxy must NOT forward to the
// upstream and must write a report-status deny the client can parse.
func TestProxyReceivePack_DenyWritesReportStatusNoForward(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	ref := "refs/heads/main"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	body := buildPushRequestWithNew(t, ref, tip, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": nil}, // empty allow list denies all
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != 0 {
		t.Fatalf("upstream received %d bytes on a denied push; want 0 (upstream must be untouched)", len(up.forwarded))
	}
	if !bytes.Contains(out.Bytes(), []byte("unpack ok")) {
		t.Fatalf("deny response missing unpack ok; got %x", out.Bytes())
	}
	if !bytes.Contains(out.Bytes(), []byte("ng "+ref+" ")) {
		t.Fatalf("deny response missing ng line for %s; got %x", ref, out.Bytes())
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("0000")) {
		t.Fatalf("deny response not flush-terminated; got %x", out.Bytes())
	}
}

// TestProxyReceivePack_DenySideband64kMuxed advertises side-band-64k and asserts
// the report-status deny is multiplexed over sideband channel 1 (each Data
// pkt-line payload begins with 0x01) and the sideband stream is terminated by an
// outer flush-pkt 0000. This pins the muxing format independent of real git
// (proxy_enforce_test.go otherwise only advertises report-status, leaving the
// side-band branch covered by the integration test alone).
func TestProxyReceivePack_DenySideband64kMuxed(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	ref := "refs/heads/main"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	// Build the request advertising BOTH report-status and side-band-64k.
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	line := strings.Repeat("0", 40) + " " + tip + " " + ref + "\x00report-status side-band-64k\n"
	if err := e.EncodeString(line); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if pack != nil {
		buf.Write(pack)
	}
	body := buf.Bytes()

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": nil}, // empty allow list denies all
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != 0 {
		t.Fatalf("upstream received %d bytes on a denied push; want 0", len(up.forwarded))
	}

	// Parse the outer pkt-line stream. Every Data frame must be sideband
	// channel 1 (payload[0] == 0x01); the demuxed content is the report-status.
	// The stream ends with exactly one outer flush-pkt.
	s := pktline.NewScanner(bytes.NewReader(out.Bytes()))
	var demuxed bytes.Buffer
	sawData, flushCount := false, 0
	for s.Scan() {
		switch s.Marker() {
		case pktline.Data:
			sawData = true
			payload := s.Bytes()
			if len(payload) == 0 || payload[0] != 0x01 {
				t.Fatalf("sideband frame not channel-1 (0x01); got %x", payload)
			}
			demuxed.Write(payload[1:])
		case pktline.Flush:
			flushCount++
		default:
			t.Fatalf("unexpected pkt-line marker %v in sideband deny output", s.Marker())
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan sideband deny output: %v", err)
	}
	if !sawData {
		t.Fatalf("no sideband data frames in output; got %x", out.Bytes())
	}
	if flushCount != 1 {
		t.Fatalf("expected exactly one outer flush-pkt, got %d; output %x", flushCount, out.Bytes())
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("0000")) {
		t.Fatalf("sideband output not terminated by outer flush-pkt 0000; got %x", out.Bytes())
	}
	// The demuxed (channel-1) content is the report-status: unpack ok + ng ref.
	if !bytes.Contains(demuxed.Bytes(), []byte("unpack ok")) {
		t.Fatalf("demuxed report-status missing unpack ok; got %x", demuxed.Bytes())
	}
	if !bytes.Contains(demuxed.Bytes(), []byte("ng "+ref+" ")) {
		t.Fatalf("demuxed report-status missing ng line for %s; got %x", ref, demuxed.Bytes())
	}
}

// TestProxyReceivePack_OversizeDenies asserts a body exceeding the packfile
// byte cap is denied (fail-closed, no OOM) and not forwarded.
func TestProxyReceivePack_OversizeDenies(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	ref := "refs/heads/feat/x"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	body := buildPushRequestWithNew(t, ref, tip, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	// Cap below the body size so the push is rejected as oversized.
	proxy.SetEnforcement(eng, testMirrorOpener(t), int64(len(body)-1))

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != 0 {
		t.Fatalf("oversized push was forwarded (%d bytes); want 0", len(up.forwarded))
	}
	if !bytes.Contains(out.Bytes(), []byte("ng "+ref+" ")) {
		t.Fatalf("oversize deny response missing ng line; got %x", out.Bytes())
	}
}

// TestProxyReceivePack_PassthroughWhenNoEngine asserts that without enforcement
// wiring the proxy forwards verbatim (existing behavior preserved).
func TestProxyReceivePack_PassthroughWhenNoEngine(t *testing.T) {
	ctx := context.Background()
	body := []byte("raw-bytes-through")
	up := &fakeUpstream{resp: []byte("resp")}
	proxy := gitproto.New(up) // no SetEnforcement → passthrough

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if !bytes.Equal(up.forwarded, body) {
		t.Fatalf("passthrough forwarded %q, want %q", up.forwarded, body)
	}
	if !bytes.Equal(out.Bytes(), []byte("resp")) {
		t.Fatalf("passthrough response = %q, want %q", out.Bytes(), "resp")
	}
}

// buildPushRequestWithNew is like buildPushRequest but takes the new SHA
// explicitly (so the create command points at a real object).
func buildPushRequestWithNew(t *testing.T, ref, newSHA string, pack []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	line := strings.Repeat("0", 40) + " " + newSHA + " " + ref + "\x00report-status\n"
	if err := e.EncodeString(line); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if pack != nil {
		buf.Write(pack)
	}
	return buf.Bytes()
}

// countingReader counts the bytes consumed from an underlying reader, so a test
// can assert the proxy stopped reading early (LimitedReader) rather than
// buffering an entire oversized body.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestProxyReceivePack_OversizeLimitedRead streams a body far larger than the
// configured cap through a fake upstream and asserts the proxy:
//   - denies the push fail-closed (report-status ng line),
//   - does NOT forward to the fake upstream,
//   - does NOT open the inspection mirror (the size check fires first), and
//   - stops reading after at most max+1 bytes (LimitedReader), so a malicious
//     huge body cannot force a huge allocation before rejection.
func TestProxyReceivePack_OversizeLimitedRead(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	ref := "refs/heads/feat/x"
	// Build a parseable create request (header + flush, no pack) then append a
	// padding much larger than the cap. The header is small (~120 bytes) so it
	// fits within cap+1 and the request still parses when truncated.
	header := buildPushRequestWithNew(t, ref, strings.Repeat("1", 40), nil)
	const capBytes int64 = 1024
	padding := bytes.Repeat([]byte("X"), 4<<20) // 4 MiB
	fullBody := append(header, padding...)

	// The mirror opener must never be called: the oversize deny fires first.
	openerCalled := false
	opener := func(ctx context.Context, repo string) (*gitx.Mirror, error) {
		openerCalled = true
		return nil, fmt.Errorf("mirror opener must not be called on oversize deny")
	}

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, opener, capBytes)

	cr := &countingReader{r: bytes.NewReader(fullBody)}
	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", cr, &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("ng "+ref+" ")) {
		t.Fatalf("oversize deny response missing ng line; got %x", out.Bytes())
	}
	if len(up.forwarded) != 0 {
		t.Fatalf("oversized push was forwarded (%d bytes); want 0", len(up.forwarded))
	}
	if openerCalled {
		t.Fatal("mirror opener was called on an oversized push; the size check must fire first")
	}
	// The LimitedReader must have stopped reading at cap+1 bytes, not consumed
	// the whole 4 MiB body.
	if cr.n > capBytes+1 {
		t.Fatalf("proxy read %d bytes from the body; want at most cap+1=%d (LimitedReader must cap the read)", cr.n, capBytes+1)
	}
	if cr.n >= int64(len(fullBody)) {
		t.Fatalf("proxy read the entire %d-byte body; want it to stop early", len(fullBody))
	}
}

// TestProxyReceivePack_DenyReasonExcludesUpstreamCreds forces a mirror-open
// failure against an unreachable credentialed upstream URL and asserts the
// agent-facing report-status deny reason contains NEITHER the upstream username
// NOR the password. This pins the binding invariant: the agent never sees
// upstream credentials. The full error (with any redacted stderr) is logged
// server-side only.
func TestProxyReceivePack_DenyReasonExcludesUpstreamCreds(t *testing.T) {
	gitBinary(t)
	// Bound the real git clone attempt so a hung connection cannot stall CI;
	// connection-refused on 127.0.0.1:1 returns near-instantly in practice.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const (
		upstreamUser = "ci-leak-bot"
		upstreamPass = "do-not-leak-upstream-PW-xyz"
	)
	ref := "refs/heads/feat/x"
	// Minimal parseable create command (no pack); the mirror open fails before
	// any pack inspection, so the new SHA need not exist.
	body := buildPushRequestWithNew(t, ref, strings.Repeat("1", 40), nil)

	// Mirror opener points at an unreachable HTTP endpoint with embedded creds.
	// gitx.Open will attempt `git clone --mirror` and fail; git echoes the URL
	// (redacting only the password) into stderr. The proxy must surface a GENERIC
	// reason and never the credentialed URL.
	credOpener := func(ctx context.Context, repo string) (*gitx.Mirror, error) {
		return gitx.Open(ctx, "http://127.0.0.1:1", repo, t.TempDir(),
			fakeCredStore{username: upstreamUser, password: upstreamPass})
	}

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, credOpener, 1<<28)

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	// The deny path must have fired (mirror open failed → report-status deny).
	if !bytes.Contains(out.Bytes(), []byte("ng "+ref+" ")) {
		t.Fatalf("expected report-status deny for %s; got %x", ref, out.Bytes())
	}
	// The agent-facing bytes must not contain the upstream username or password.
	if bytes.Contains(out.Bytes(), []byte(upstreamUser)) {
		t.Errorf("agent-facing deny response LEAKED upstream username %q:\n%s", upstreamUser, out.Bytes())
	}
	if bytes.Contains(out.Bytes(), []byte(upstreamPass)) {
		t.Errorf("agent-facing deny response LEAKED upstream password %q:\n%s", upstreamPass, out.Bytes())
	}
	// No forward to the upstream on a denied push.
	if len(up.forwarded) != 0 {
		t.Errorf("upstream received %d bytes on a denied push; want 0", len(up.forwarded))
	}
}