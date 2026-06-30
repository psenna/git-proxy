package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
)

// policyCommitMessage enables commit_message with the given required prefixes.
func policyCommitMessage(prefixes ...string) config.PolicyConfig {
	return config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"commit_message": {
				Enabled: true,
				Params:  map[string]any{"require_prefix": prefixes},
			},
		},
	}
}

// policyPathACL enables path_acl with the given deny patterns.
func policyPathACL(deny ...string) config.PolicyConfig {
	return config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"path_acl": {
				Enabled: true,
				Params:  map[string]any{"deny": deny},
			},
		},
	}
}

// policySecretScan enables secret_scan with built-in defaults (default-on).
func policySecretScan() config.PolicyConfig {
	return config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"secret_scan": {Enabled: true},
		},
	}
}

// cloneForPush clones the upstream through the proxy and configures the working
// copy for commits, returning the working-copy path.
func cloneForPush(t *testing.T, h *Harness) string {
	t.Helper()
	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)
	mustRun(t, "git", "-C", dst, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", dst, "config", "user.name", "Test")
	return dst
}

// commitFile stages a new file at path with content and commits it with msg.
func commitFile(t *testing.T, dst, path, content, msg string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, path)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dst, path), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	mustRun(t, "git", "-C", dst, "add", path)
	mustRun(t, "git", "-C", dst, "commit", "-q", "-m", msg)
}

// TestPushRules_BadCommitMessageBlocked pushes a commit whose subject lacks the
// required prefix. The push must be rejected with the commit_message reason
// visible, and the upstream ref must be unchanged.
func TestPushRules_BadCommitMessageBlocked(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyCommitMessage("feat:", "fix:"))
	dst := cloneForPush(t, h)
	commitFile(t, dst, "work.txt", "w\n", "bad subject no prefix")

	before := h.UpstreamRef(t, "refs/heads/main")
	cmd := h.Git(dst, "push", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push with bad commit message unexpectedly succeeded")
	}
	if !strings.Contains(string(out), "required prefix") {
		t.Fatalf("rejection output missing commit_message reason; got:\n%s", out)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != before {
		t.Fatalf("upstream main changed after denied push: %s, want %s", got, before)
	}
}

// TestPushRules_DeniedPathBlocked pushes a commit that touches a denied path.
// The push must be rejected with the path_acl reason, upstream unchanged.
func TestPushRules_DeniedPathBlocked(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyPathACL("secrets/**"))
	dst := cloneForPush(t, h)
	// Use a conforming subject so only path_acl would block.
	commitFile(t, dst, "secrets/api.key", "secret-content\n", "feat: add secret")

	before := h.UpstreamRef(t, "refs/heads/main")
	cmd := h.Git(dst, "push", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push touching denied path unexpectedly succeeded")
	}
	if !strings.Contains(string(out), "secrets/api.key") {
		t.Fatalf("rejection output missing denied path; got:\n%s", out)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != before {
		t.Fatalf("upstream main changed after denied push: %s, want %s", got, before)
	}
}

// TestPushRules_SecretBlobBlocked pushes a commit whose blob contains an AWS
// access key id. secret_scan (default-on) must reject it; the secret value
// must NOT appear in the client-visible output; upstream unchanged.
func TestPushRules_SecretBlobBlocked(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policySecretScan())
	dst := cloneForPush(t, h)
	secret := "AKIAIOSFODNN7EXAMPLE"
	commitFile(t, dst, "config/aws.yml", "key: "+secret+"\n", "feat: add aws config")

	before := h.UpstreamRef(t, "refs/heads/main")
	cmd := h.Git(dst, "push", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push containing a secret unexpectedly succeeded")
	}
	if !strings.Contains(string(out), "secret") {
		t.Fatalf("rejection output missing secret_scan signal; got:\n%s", out)
	}
	if strings.Contains(string(out), secret) {
		t.Errorf("client output leaks the secret value %q:\n%s", secret, out)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != before {
		t.Fatalf("upstream main changed after denied push: %s, want %s", got, before)
	}
}

// TestPushRules_CleanPushAllowed pushes a conforming commit with no secrets and
// no denied paths; it must be allowed and reach upstream.
func TestPushRules_CleanPushAllowed(t *testing.T) {
	h := StartWithPolicy(t, "test.git", config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"commit_message": {Enabled: true, Params: map[string]any{"require_prefix": []string{"feat:"}}},
			"path_acl":       {Enabled: true, Params: map[string]any{"deny": []string{"secrets/**"}}},
			"secret_scan":    {Enabled: true},
		},
	})
	dst := cloneForPush(t, h)
	commitFile(t, dst, "src/app.go", "package main\n", "feat: add app")

	h.RunGit(t, dst, "push", "-q", "origin", "main")
	got := h.UpstreamRef(t, "refs/heads/main")
	want := revParse(t, dst, "HEAD")
	if got != want {
		t.Fatalf("clean push did not reach upstream: upstream=%s, pushed=%s", got, want)
	}
}