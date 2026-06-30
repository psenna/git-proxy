package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// assertCredsIsolated verifies the upstream vault credentials never reached the
// agent's git environment or the clone's git config. The proxy holds the vault;
// the agent only ever holds its own bearer token.
func assertCredsIsolated(t *testing.T, h *Harness, cloneDir string) {
	t.Helper()
	// The agent's git process env must not contain the upstream password.
	// h.Git builds the env from os.Environ(); the only proxy-derived secret it
	// carries is the agent token (http.extraHeader). Re-run a no-op git command
	// and inspect the env we would have passed.
	cmd := h.Git(cloneDir, "config", "--get", "user.name")
	for _, env := range cmd.Env {
		if strings.Contains(env, upstreamSecret) {
			t.Errorf("agent process env contains upstream secret: %q", env)
		}
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
