package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/credentials/repomatch"
)

// TestSSH_DenyByDefault asserts the SSH git leg is deny-by-default (mirrors
// the HTTP frontend's TestFrontend_DenyByDefault over a real SSH handshake +
// git client). Three cases:
//
//   - deny_unconfigured_read: creds=nil, publicRepos=nil → an authenticated
//     git-upload-pack of the repo is rejected with the fixed generic reason
//     and a non-zero exit, and the upstream is NOT contacted (deny fires
//     before the ref advertisement fetch — fail-closed, no-leak).
//   - allow_public_read_anonymous: publicRepos matches the repo, creds=nil →
//     an anonymous read clone succeeds (the upstream is contacted with no
//     credential attached).
//   - deny_public_push_no_creds: publicRepos matches the repo, creds=nil → a
//     push is rejected (push always requires a credential, even for a
//     public_repos repo); the upstream is not contacted for the push.
//
// The repo name is chosen distinct for each deny case so a leaked repo path in
// the deny reason (if a regression introduced one) would be caught by the
// per-case no-leak assertion (the repo path must not appear in the deny output)
// in addition to the generic-reason check.
func TestSSH_DenyByDefault(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}

	// Case 1: no creds, no public_repos → deny read, upstream not contacted.
	t.Run("deny_unconfigured_read", func(t *testing.T) {
		sh := StartSSHWithAccess(t, "ssh-deny.git", "agent-1", config.PolicyConfig{}, nil, nil)
		work := t.TempDir()
		cmd := sh.GitSSH(work, "clone", sh.h.UpstreamURL+"/ssh-deny.git", "clone")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("clone succeeded; deny-by-default should reject an unconfigured repo (no creds, no public_repos)")
		}
		if !strings.Contains(string(out), "repository not served by this proxy") {
			t.Errorf("clone output does not contain the fixed generic deny reason:\n%s", out)
		}
		// No-leak: the denied repo path must not be echoed back in the deny output.
		if strings.Contains(string(out), "ssh-deny.git") {
			t.Errorf("deny output leaked repo path %q:\n%s", "ssh-deny.git", out)
		}
		// Fail-closed: the deny check fires before writeAdvertisement (the first
		// upstream contact), so a denied read must not reach the upstream.
		if hits := sh.UpstreamHits(); hits != 0 {
			t.Errorf("upstream contacted %d time(s); deny must fire before any upstream contact", hits)
		}
	})

	// Case 2: publicRepos matches the repo, creds=nil → anonymous read allowed.
	// The upstream IS contacted (the clone proceeds), and the proxy→upstream
	// leg attaches no credential (plainUpstream uses nil creds).
	t.Run("allow_public_read_anonymous", func(t *testing.T) {
		public, err := repomatch.NewBoolMatcher([]string{"ssh-pub.git"})
		if err != nil {
			t.Fatalf("NewBoolMatcher: %v", err)
		}
		sh := StartSSHWithAccess(t, "ssh-pub.git", "agent-1", config.PolicyConfig{}, nil, public)
		work := t.TempDir()
		sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-pub.git", "clone")
		clone := filepath.Join(work, "clone")
		if _, err := os.Stat(filepath.Join(clone, "README.md")); err != nil {
			t.Fatalf("clone missing README.md: %v", err)
		}
		if hits := sh.UpstreamHits(); hits == 0 {
			t.Errorf("upstream not contacted; public_repos read should reach the upstream")
		}
	})

	// Case 3: publicRepos matches the repo, creds=nil → push denied (push
	// always requires a credential, even for a public_repos repo).
	t.Run("deny_public_push_no_creds", func(t *testing.T) {
		public, err := repomatch.NewBoolMatcher([]string{"ssh-pubpush.git"})
		if err != nil {
			t.Fatalf("NewBoolMatcher: %v", err)
		}
		sh := StartSSHWithAccess(t, "ssh-pubpush.git", "agent-1", config.PolicyConfig{}, nil, public)
		work := t.TempDir()
		// Clone succeeds (public read) so we have a worktree to push from.
		sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-pubpush.git", "clone")
		clone := filepath.Join(work, "clone")
		mustRunGit(t, clone, "config", "user.email", "test@example.com")
		mustRunGit(t, clone, "config", "user.name", "Test")
		if err := os.WriteFile(filepath.Join(clone, "new.txt"), []byte("new\n"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		mustRunGit(t, clone, "add", "new.txt")
		mustRunGit(t, clone, "commit", "-q", "-m", "deny test commit")

		hitsBefore := sh.UpstreamHits()
		cmd := sh.GitSSH(clone, "push", "origin", "main")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("push succeeded; a public_repos repo with no creds must deny push")
		}
		if !strings.Contains(string(out), "repository not served by this proxy") {
			t.Errorf("push output does not contain the fixed generic deny reason:\n%s", out)
		}
		// No-leak: the denied repo path must not be echoed back in the deny output.
		if strings.Contains(string(out), "ssh-pubpush.git") {
			t.Errorf("deny output leaked repo path %q:\n%s", "ssh-pubpush.git", out)
		}
		// The push itself must not reach the upstream. (The clone already
		// contacted the upstream; assert the push added no further hits.)
		if got, want := sh.UpstreamHits(), hitsBefore; got != want {
			t.Errorf("upstream contacted during denied push: hits before=%d after=%d (push must not reach upstream)", want, got)
		}
	})
}
