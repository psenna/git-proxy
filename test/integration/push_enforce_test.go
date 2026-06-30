package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
)

// policyHistoryProtect returns a PolicyConfig that enables history_protect on
// the given protected refs (all agents/repos).
func policyHistoryProtect(refs ...string) config.PolicyConfig {
	return config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"history_protect": {
				Enabled: true,
				Params:  map[string]any{"refs": refs},
			},
		},
	}
}

// policyBranchPattern returns a PolicyConfig that enables branch_pattern with
// the given allow patterns (all agents/repos).
func policyBranchPattern(allow ...string) config.PolicyConfig {
	return config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"branch_pattern": {
				Enabled: true,
				Params:  map[string]any{"allow": allow},
			},
		},
	}
}

// TestPushEnforce_ForcePushProtectedBlocked seeds the upstream, starts the proxy
// with history_protect on refs/heads/main, then attempts a real force-push that
// rewrites main. The push must be rejected (git non-zero exit) with the policy
// reason visible in the client stderr, and the upstream ref must be unchanged.
func TestPushEnforce_ForcePushProtectedBlocked(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyHistoryProtect("refs/heads/main"))

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)
	mustRun(t, "git", "-C", dst, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", dst, "config", "user.name", "Test")

	// Advance main with a FF commit and push it (allowed: fast-forward).
	if err := os.WriteFile(filepath.Join(dst, "ff.txt"), []byte("ff\n"), 0o644); err != nil {
		t.Fatalf("write ff.txt: %v", err)
	}
	mustRun(t, "git", "-C", dst, "add", "ff.txt")
	mustRun(t, "git", "-C", dst, "commit", "-q", "-m", "ff commit")
	h.RunGit(t, dst, "push", "-q", "origin", "main")
	afterFF := h.UpstreamRef(t, "refs/heads/main")

	// Rewrite main history: reset to the seed and make a divergent commit, so
	// the next push is a non-fast-forward (force-push) to a protected ref.
	mustRun(t, "git", "-C", dst, "reset", "--hard", "HEAD~1")
	if err := os.WriteFile(filepath.Join(dst, "divergent.txt"), []byte("div\n"), 0o644); err != nil {
		t.Fatalf("write divergent.txt: %v", err)
	}
	mustRun(t, "git", "-C", dst, "add", "divergent.txt")
	mustRun(t, "git", "-C", dst, "commit", "-q", "-m", "divergent commit")

	cmd := h.Git(dst, "push", "--force", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("force-push to protected ref unexpectedly succeeded; want rejection")
	}
	if !strings.Contains(string(out), "force-push") {
		t.Fatalf("force-push rejection output missing reason; got:\n%s", out)
	}
	// Upstream must be unchanged: still at the FF commit.
	if got := h.UpstreamRef(t, "refs/heads/main"); got != afterFF {
		t.Fatalf("upstream main changed after denied force-push: %s, want %s", got, afterFF)
	}
}

// TestPushEnforce_PushToMainBlockedFeatAllowed starts the proxy with
// branch_pattern allowing only refs/heads/feat/*. A push to main is blocked;
// a push to refs/heads/feat/x is allowed and reaches upstream.
func TestPushEnforce_PushToMainBlockedFeatAllowed(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyBranchPattern("refs/heads/feat/*"))

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)
	mustRun(t, "git", "-C", dst, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", dst, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dst, "work.txt"), []byte("w\n"), 0o644); err != nil {
		t.Fatalf("write work.txt: %v", err)
	}
	mustRun(t, "git", "-C", dst, "add", "work.txt")
	mustRun(t, "git", "-C", dst, "commit", "-q", "-m", "work commit")

	// Push to main: blocked by branch_pattern (main does not match feat/*).
	mainBefore := h.UpstreamRef(t, "refs/heads/main")
	cmd := h.Git(dst, "push", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push to main unexpectedly succeeded; want rejection by branch_pattern")
	}
	if !strings.Contains(string(out), "main") {
		t.Fatalf("push-to-main rejection output missing ref; got:\n%s", out)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != mainBefore {
		t.Fatalf("upstream main changed after denied push: %s, want %s", got, mainBefore)
	}

	// Push to feat/x: allowed by branch_pattern; reaches upstream.
	mustRun(t, "git", "-C", dst, "branch", "-m", "feat/x")
	h.RunGit(t, dst, "push", "-q", "origin", "feat/x")
	got := h.UpstreamRef(t, "refs/heads/feat/x")
	want := revParse(t, dst, "HEAD")
	if got != want {
		t.Fatalf("feat/x push did not reach upstream: upstream=%s, pushed=%s", got, want)
	}
}