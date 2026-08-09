package integration

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRepro_MirrorSelfHealing verifies that a read-protected fetch through the
// proxy self-heals when the mirror's object store is corrupt. It deletes the
// mirror's pack files (simulating a corrupted object store), then issues a git
// fetch through the proxy. The proxy detects the "bad object" error, repairs
// the mirror (re-clones from upstream), retries the fetch, and the client
// succeeds — no manual intervention needed. This is the end-to-end reproduction
// for issue #69.
func TestRepro_MirrorSelfHealing(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	// Clone through the enforce path. Checkout aborts on the withheld secret
	// blob (expected); the repo + refs are still created.
	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "--filter=blob:none", h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	// Find the mirror directory (the only subdirectory under MirrorRoot).
	entries, err := os.ReadDir(h.MirrorRoot)
	if err != nil {
		t.Fatalf("read mirror root: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no mirror directories found in MirrorRoot")
	}
	mirrorDir := filepath.Join(h.MirrorRoot, entries[0].Name())

	// Corrupt the mirror by deleting all pack files in the objects/pack
	// directory. This makes rev-list fail with "bad object" — a corruption
	// error that triggers self-healing.
	packDir := filepath.Join(mirrorDir, "objects", "pack")
	packs, err := filepath.Glob(filepath.Join(packDir, "*.pack"))
	if err != nil {
		t.Fatalf("glob pack files: %v", err)
	}
	for _, p := range packs {
		t.Logf("removing pack file %s to simulate corruption", filepath.Base(p))
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove pack %s: %v", p, err)
		}
	}
	// Also remove the .idx and .rev files so git can't fall back on them.
	for _, pat := range []string{"*.idx", "*.rev"} {
		files, err := filepath.Glob(filepath.Join(packDir, pat))
		if err != nil {
			t.Fatalf("glob %s: %v", pat, err)
		}
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				t.Fatalf("remove %s: %v", f, err)
			}
		}
	}

	// Advance upstream with a new non-secret file so the fetch has new objects.
	newTip := advanceUpstreamNewFile(t, h, "newfile.txt", "new content\n")

	// THE REPRO: fetch through the enforce path. The mirror is corrupt (missing
	// pack files), but the proxy should self-heal (Repair + retry) and the fetch
	// should succeed.
	fetchCmd := h.Git(dst, "fetch", "origin", "main")
	if out, err := fetchCmd.CombinedOutput(); err != nil {
		t.Fatalf("fetch through self-healing proxy failed:\n%s", out)
	}

	// The new tip must have arrived.
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != newTip {
		t.Fatalf("after fetch: origin/main = %s, upstream tip = %s", got, newTip)
	}
}