package integration

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/port"
)

// authFailedMarker returns true if git's clone output indicates an
// authentication rejection (401). Git's wording for a Bearer 401 is
// "Authentication failed" / "unauthorized"; we also accept a literal "401".
// When GIT_TERMINAL_PROMPT=0 is set (as the harness does), git cannot prompt
// for credentials to retry, so it prints "could not read Username" — that only
// happens in response to a 401, so it counts as an auth rejection too.
func authFailedMarker(out string) bool {
	return strings.Contains(out, "401") ||
		strings.Contains(out, "Authentication failed") ||
		strings.Contains(out, "unauthorized") ||
		strings.Contains(out, "could not read Username")
}

// upstreamSecret is a distinctive upstream password placed in the vault. The
// creds-isolation assertions check this string never reaches the agent's git
// config or environment.
const upstreamSecret = "upstream-do-not-leak-PW"

// vaultCreds is the credential map written to the proxy's vault for the
// authenticated tests.
func vaultCreds(repo string) map[string]port.Credentials {
	return map[string]port.Credentials{
		repo: {Username: "ci-bot", Password: upstreamSecret},
	}
}

// TestAuth_NoTokenRejected starts the proxy with auth enabled and attempts a
// real `git clone` without presenting a token. The proxy must reject the
// request with 401 (fail closed); the clone must fail.
func TestAuth_NoTokenRejected(t *testing.T) {
	h := StartWithAuth(t, "test.git", "agent-token-1", vaultCreds("test.git"))
	// Drop the token so the git client sends no Authorization header.
	h.Token = ""

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("clone without token unexpectedly succeeded; want 401 rejection")
	}
	if !authFailedMarker(string(out)) {
		t.Fatalf("clone without token: expected 401 in output, got:\n%s", out)
	}
}

// TestAuth_ValidTokenClonesPushesFetches starts the proxy with auth enabled and
// a valid token, then exercises clone/push/fetch through a real git client.
// All three must succeed.
func TestAuth_ValidTokenClonesPushesFetches(t *testing.T) {
	h := StartWithAuth(t, "test.git", "agent-token-1", vaultCreds("test.git"))

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)

	// README from the seed must be present.
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Fatalf("README.md missing from clone: %v", err)
	}

	// Push a new commit through the proxy.
	mustRun(t, "git", "-C", dst, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", dst, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dst, "feature.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write feature.txt: %v", err)
	}
	mustRun(t, "git", "-C", dst, "add", "feature.txt")
	mustRun(t, "git", "-C", dst, "commit", "-q", "-m", "add feature")
	before := h.UpstreamRef(t, "refs/heads/main")
	h.RunGit(t, dst, "push", "-q", "origin", "main")
	after := h.UpstreamRef(t, "refs/heads/main")
	if before == after {
		t.Fatalf("push through authenticated proxy did not update upstream main")
	}

	// Fetch through the proxy after advancing upstream out-of-band.
	work := t.TempDir()
	mustRun(t, "git", "clone", "-q", "file://"+h.BarePath, work)
	mustRun(t, "git", "-C", work, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "fetched.txt"), []byte("fetched\n"), 0o644); err != nil {
		t.Fatalf("write fetched.txt: %v", err)
	}
	mustRun(t, "git", "-C", work, "add", "fetched.txt")
	mustRun(t, "git", "-C", work, "commit", "-q", "-m", "advance upstream")
	mustRun(t, "git", "-C", work, "push", "-q", "origin", "main")
	upstreamTip := h.UpstreamRef(t, "refs/heads/main")
	h.RunGit(t, dst, "fetch", "-q", "origin")
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != upstreamTip {
		t.Fatalf("fetch through proxy: origin/main = %s, upstream tip = %s", got, upstreamTip)
	}

	assertCredsIsolated(t, h, dst)
}

// TestAuth_InvalidTokenRejected presents a token the proxy does not know. The
// clone must be rejected (401).
func TestAuth_InvalidTokenRejected(t *testing.T) {
	h := StartWithAuth(t, "test.git", "agent-token-1", vaultCreds("test.git"))
	h.Token = "this-token-is-wrong"

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("clone with invalid token unexpectedly succeeded; want 401 rejection")
	}
	if !authFailedMarker(string(out)) {
		t.Fatalf("clone with invalid token: expected 401 in output, got:\n%s", out)
	}
}

// assertCredsIsolated verifies the upstream vault credentials never reach the
// agent. The proxy holds the vault and attaches it only on the proxy→upstream
// leg (proven by TestUpstream_AttachesVaultCreds); the agent only ever holds its
// own bearer token.
//
// The real, falsifiable check below drives the proxy→client leg directly: it
// issues authenticated requests to the proxy's /info/refs and /git-upload-pack
// endpoints and asserts the upstream secret appears NOWHERE in the bytes the
// proxy returns to the client (response body AND headers). If the proxy ever
// leaked the credential into a response — by forwarding an upstream header that
// echoed it, by including it in an error message, or by any other path — this
// assertion would fail.
func assertCredsIsolated(t *testing.T, h *Harness, cloneDir string) {
	t.Helper()

	// 1. Ref advertisement (proxy→client for /info/refs). The body is the
	//    upload-pack ref advertisement; it must not contain the secret.
	infoRefsBody := proxyGetBody(t, h, "/test.git/info/refs?service=git-upload-pack")
	if bytes.Contains(infoRefsBody, []byte(upstreamSecret)) {
		t.Errorf("proxy→client /info/refs response body contains upstream secret:\n%s", infoRefsBody)
	}

	// 2. Upload-pack stream (proxy→client for /git-upload-pack). Build a real
	//    upload-pack request with the upstream tip as the want, POST it through
	//    the proxy, and assert the packfile/stream the client receives carries
	//    no secret. This exercises the full client→proxy→upstream→proxy→client
	//    round trip with Basic auth attached on the proxy→upstream leg only.
	want := h.UpstreamRef(t, "refs/heads/main")
	uploadPackBody := proxyUploadPackBody(t, h, want)
	if bytes.Contains(uploadPackBody, []byte(upstreamSecret)) {
		t.Errorf("proxy→client /git-upload-pack response body contains upstream secret:\n%s", uploadPackBody)
	}

	// The clone's git config must not contain the upstream password. (The
	// insteadOf rewrite and the extraHeader hold the agent token and the proxy
	// URL — never the upstream creds.)
	cfgPath := filepath.Join(cloneDir, ".git", "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read clone config: %v", err)
	}
	if strings.Contains(string(b), upstreamSecret) {
		t.Errorf("clone git config contains upstream secret:\n%s", b)
	}
	// The vault file itself must live outside the clone dir (the agent has no
	// filesystem path to it).
	if h.VaultPath != "" && strings.HasPrefix(h.VaultPath, cloneDir) {
		t.Errorf("vault file %s is inside the clone dir %s", h.VaultPath, cloneDir)
	}
	// Sanity: the agent token is NOT the upstream password (they are distinct).
	if h.Token == upstreamSecret {
		t.Error("agent token equals upstream password; secrets are not distinct")
	}
}

// proxyGetBody issues an authenticated GET to the proxy for repoPath and returns
// the full response body. It fails the test if the proxy does not return 200.
func proxyGetBody(t *testing.T, h *Harness, repoPath string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.ProxyURL+"/"+repoPath, nil)
	if err != nil {
		t.Fatalf("build GET %s: %v", repoPath, err)
	}
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", repoPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read GET %s body: %v", repoPath, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200; body:\n%s", repoPath, resp.StatusCode, body)
	}
	// The response headers are also proxy→client bytes; check them too.
	for k, vs := range resp.Header {
		for _, v := range vs {
			if strings.Contains(v, upstreamSecret) {
				t.Errorf("proxy→client /info/refs response header %s contains upstream secret: %q", k, v)
			}
		}
	}
	return body
}

// proxyUploadPackBody issues an authenticated upload-pack POST to the proxy for
// "test.git", asking for the given want SHA, and returns the full response body
// the proxy streams back to the client (NAK + packfile). It fails the test if
// the proxy does not return 200.
func proxyUploadPackBody(t *testing.T, h *Harness, want string) []byte {
	t.Helper()
	// Build a protocol-v0 upload-pack request: a single want (carrying
	// capabilities), a flush, a done, and a final flush.
	var reqBody bytes.Buffer
	enc := pktline.NewEncoder(&reqBody)
	if err := enc.EncodeString("want " + want + " ofs-delta no-progress side-band-64k\n"); err != nil {
		t.Fatalf("encode want: %v", err)
	}
	if err := enc.Flush(); err != nil {
		t.Fatalf("flush after wants: %v", err)
	}
	if err := enc.EncodeString("done\n"); err != nil {
		t.Fatalf("encode done: %v", err)
	}
	if err := enc.Flush(); err != nil {
		t.Fatalf("flush after done: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, h.ProxyURL+"/test.git/git-upload-pack", &reqBody)
	if err != nil {
		t.Fatalf("build upload-pack POST: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST git-upload-pack: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read upload-pack body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST git-upload-pack: status = %d, want 200; body:\n%s", resp.StatusCode, body)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			if strings.Contains(v, upstreamSecret) {
				t.Errorf("proxy→client upload-pack response header %s contains upstream secret: %q", k, v)
			}
		}
	}
	return body
}
