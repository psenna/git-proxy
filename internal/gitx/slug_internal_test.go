package gitx

import "testing"

// TestRepoSlug verifies the slug is filesystem-safe, deterministic, and
// collision-resistant: distinct repo paths (including the a/b vs a-b case that
// a plain "/"->"-" replace would collide) map to distinct, stable directories.
func TestRepoSlug(t *testing.T) {
	if got := repoSlug(""); got != "default" {
		t.Errorf("repoSlug(\"\") = %q, want \"default\"", got)
	}
	// Deterministic: same input -> same slug.
	first := repoSlug("org/team/repo.git")
	second := repoSlug("org/team/repo.git")
	if first != second {
		t.Errorf("repoSlug is not deterministic: %q vs %q", first, second)
	}
	// Collision resistance: "a/b" and "a-b" must not collide.
	if repoSlug("a/b") == repoSlug("a-b") {
		t.Errorf("repoSlug collision: a/b and a-b both map to %q", repoSlug("a/b"))
	}
	// Filesystem-safe: no "/" remains.
	for _, repo := range []string{"a/b", "org/team/repo.git", "deep/nested/path"} {
		if s := repoSlug(repo); containsSlash(s) {
			t.Errorf("repoSlug(%q) = %q contains a path separator", repo, s)
		}
	}
}

func containsSlash(s string) bool {
	for _, r := range s {
		if r == '/' {
			return true
		}
	}
	return false
}