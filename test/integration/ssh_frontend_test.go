package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/policy"
)

// TestSSH_ClonePassthrough verifies a real `git clone ssh://agent@host:port/repo`
// succeeds through the proxy in passthrough mode (no policy rules). The clone
// fetches the seed commit and the working tree matches the upstream.
func TestSSH_ClonePassthrough(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	sh := StartSSH(t, "ssh-test.git", "agent-1", config.PolicyConfig{})
	work := t.TempDir()
	sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-test.git", "clone")
	clone := filepath.Join(work, "clone")
	// The clone should contain the seed README.md.
	if _, err := os.Stat(filepath.Join(clone, "README.md")); err != nil {
		t.Fatalf("clone missing README.md: %v", err)
	}
	// And HEAD should match the upstream main.
	if got := revParse(t, clone, "HEAD"); got != sh.UpstreamRef(t, "refs/heads/main") {
		t.Errorf("clone HEAD = %s, upstream main = %s", got, sh.UpstreamRef(t, "refs/heads/main"))
	}
}

// TestSSH_PushPolicyForcePushBlocked verifies that a force-push to a protected
// ref is blocked by the history_protect rule over SSH: the push is rejected
// with a reason visible to the client, and the upstream is left unchanged.
func TestSSH_PushPolicyForcePushBlocked(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	pol := policyHistoryProtect("refs/heads/main")
	sh := StartSSH(t, "ssh-push.git", "agent-1", pol)
	work := t.TempDir()
	sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-push.git", "clone")
	clone := filepath.Join(work, "clone")
	mustRunGit(t, clone, "config", "user.email", "test@example.com")
	mustRunGit(t, clone, "config", "user.name", "Test")

	// Rewrite history on main: amend the seed commit (a non-fast-forward
	// rewrite) so history_protect must block the force-push.
	mustRunGit(t, clone, "commit", "--amend", "--allow-empty", "-q", "-m", "rewrite")
	upstreamBefore := sh.UpstreamRef(t, "refs/heads/main")

	// Force-push main: must be rejected by history_protect.
	cmd := sh.GitSSH(clone, "push", "-f", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("force-push over SSH succeeded; history_protect should have blocked it")
	}
	if !strings.Contains(string(out), "history") && !strings.Contains(string(out), "protected") && !strings.Contains(string(out), "rejected") && !strings.Contains(string(out), "denied") {
		t.Fatalf("force-push output does not show a policy rejection:\n%s", out)
	}
	// Upstream MUST be unchanged (push did not reach it).
	if got := sh.UpstreamRef(t, "refs/heads/main"); got != upstreamBefore {
		t.Fatalf("upstream main changed after blocked force-push: %s -> %s", upstreamBefore, got)
	}
}

// TestSSH_PushCleanFFReachesUpstream verifies that a clean fast-forward push
// over SSH is forwarded to the upstream (policy allows it — history_protect
// blocks force/rewrite, not FF).
func TestSSH_PushCleanFFReachesUpstream(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	pol := policyHistoryProtect("refs/heads/main")
	sh := StartSSH(t, "ssh-ff.git", "agent-1", pol)
	work := t.TempDir()
	sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-ff.git", "clone")
	clone := filepath.Join(work, "clone")
	mustRunGit(t, clone, "config", "user.email", "test@example.com")
	mustRunGit(t, clone, "config", "user.name", "Test")

	// Add a NEW commit on top of main (fast-forward, no rewrite).
	if err := os.WriteFile(filepath.Join(clone, "new.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	mustRunGit(t, clone, "add", "new.txt")
	mustRunGit(t, clone, "commit", "-q", "-m", "ff commit")
	newHead := revParse(t, clone, "HEAD")

	// Push main: should be a fast-forward and reach the upstream.
	sh.RunGitSSH(t, clone, "push", "origin", "main")
	if got := sh.UpstreamRef(t, "refs/heads/main"); got != newHead {
		t.Fatalf("upstream main = %s, want pushed HEAD %s (FF push did not reach upstream)", got, newHead)
	}
}

// TestSSH_UnknownKeyCloneFails verifies fail-closed key auth: a clone with an
// unknown client key is rejected (auth denied — no session, no advertisement).
func TestSSH_UnknownKeyCloneFails(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	sh := StartSSH(t, "ssh-auth.git", "agent-1", config.PolicyConfig{})
	// Generate a DIFFERENT client key not in the authorized set.
	unknownKeyPath, _ := writeClientKey(t)
	work := t.TempDir()
	sshCmd := "ssh -i " + unknownKeyPath + " -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
	cmd := exec.Command("git",
		"-c", "url.ssh://agent-1@"+sh.SSHProxyAddr+".insteadOf="+sh.h.UpstreamURL,
		"-c", "core.sshCommand="+sshCmd,
		"clone", sh.h.UpstreamURL+"/ssh-auth.git", filepath.Join(work, "clone"),
	)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("clone with unknown key succeeded; SSH key auth should have rejected it (fail closed)")
	}
	// The failure must be an auth denial, not a different error. Git surfaces
	// "Permission denied" for SSH auth failures.
	if !strings.Contains(string(out), "Permission denied") && !strings.Contains(string(out), "denied") {
		t.Fatalf("unknown-key clone did not report an auth denial:\n%s", out)
	}
}

// gitAvailable reports whether the git binary is usable.
func gitAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	return true
}

// mustRunGit runs a git command in dir and fails the test on error (no proxy).
func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// Ensure policy import is used (rule registry init side effect).
var _ = policy.FirstDeny