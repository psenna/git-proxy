package gitproto_test

import (
	"bytes"
	"context"
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