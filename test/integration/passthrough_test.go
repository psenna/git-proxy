package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPassthroughClone exercises a real `git clone` through the proxy. The git
// client targets the upstream URL; the insteadOf rewrite routes it to the
// proxy, which reverse-proxies the smart-HTTP streams to the upstream.
func TestPassthroughClone(t *testing.T) {
	h := Start(t, "test.git")

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)

	// The seed commit's README.md must be present in the clone.
	if _, err := os.Stat(filepath.Join(dst, "README.md")); err != nil {
		t.Fatalf("README.md missing from clone: %v", err)
	}
	// The clone's HEAD must match the upstream's main.
	got := revParse(t, dst, "HEAD")
	want := h.UpstreamRef(t, "refs/heads/main")
	if got != want {
		t.Fatalf("clone HEAD = %s, upstream main = %s", got, want)
	}
}

// TestPassthroughPush clones through the proxy, makes a new commit, pushes it
// back through the proxy, and verifies the upstream bare repo reflects the push.
func TestPassthroughPush(t *testing.T) {
	h := Start(t, "test.git")

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)
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
		t.Fatalf("push through the proxy did not update upstream main: still %s", after)
	}
	// The pushed commit must be the one we just made.
	if after != revParse(t, dst, "HEAD") {
		t.Fatalf("upstream main = %s, pushed HEAD = %s", after, revParse(t, dst, "HEAD"))
	}
}

// TestPassthroughFetch clones through the proxy, advances upstream out-of-band,
// then fetches through the proxy and confirms the new commit arrives.
func TestPassthroughFetch(t *testing.T) {
	h := Start(t, "test.git")

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)

	// Advance upstream directly (file://), bypassing the proxy.
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

	// Fetch through the proxy and verify the new tip arrives.
	h.RunGit(t, dst, "fetch", "-q", "origin")
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != upstreamTip {
		t.Fatalf("fetch through proxy: origin/main = %s, upstream tip = %s", got, upstreamTip)
	}
}

// revParse returns `git rev-parse <ref>` run in dir.
func revParse(t *testing.T, dir, ref string) string {
	t.Helper()
	return strings.TrimSpace(mustOutput(t, "git", "-C", dir, "rev-parse", ref))
}
