package integration

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestRepro_UnknownHaveFetchDoesNot502 is the end-to-end reproduction for issue
// #75: a git client whose advertised haves include a commit UNKNOWN to the
// inspection mirror (a stale local branch referencing a commit the upstream no
// longer has) must NOT turn a fetch into a 502. A real git upload-pack treats an
// unknown have as "not common ground" and continues; the proxy must do the same
// (filter haves to those present in the mirror before building `--not`), and
// must NOT trigger a wasted mirror Repair (re-clone) that cannot help.
func TestRepro_UnknownHaveFetchDoesNot502(t *testing.T) {
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

	// Find the mirror directory (the only subdirectory under MirrorRoot) and
	// snapshot its inode. A Repair (RemoveAll + re-clone) replaces the directory
	// and yields a NEW inode, so an unchanged inode proves no wasted Repair.
	entries, err := os.ReadDir(h.MirrorRoot)
	if err != nil {
		t.Fatalf("read mirror root: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no mirror directories found in MirrorRoot")
	}
	mirrorDir := filepath.Join(h.MirrorRoot, entries[0].Name())
	beforeInode := dirInode(t, mirrorDir)

	// Build a throwaway repo with one commit that is NOT in upstream, then fetch
	// it into the clone as a local branch. The clone now advertises a have the
	// upstream/mirror does not have — the exact shape that broke the fetch with
	// `fatal: bad object <sha>` / HTTP 502 before the fix.
	stale := t.TempDir()
	mustRun(t, "git", "init", "-q", "-b", "main", stale)
	mustRun(t, "git", "-C", stale, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", stale, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(stale, "stale.txt"), []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("write stale.txt: %v", err)
	}
	mustRun(t, "git", "-C", stale, "add", "stale.txt")
	mustRun(t, "git", "-C", stale, "commit", "-q", "-m", "stale commit (unknown to upstream)")
	staleTip := strings.TrimSpace(mustOutput(t, "git", "-C", stale, "rev-parse", "HEAD"))
	t.Logf("stale commit (not in upstream/mirror): %s", staleTip)

	// Fetch the stale commit into the clone as a local branch (direct file://
	// fetch, bypassing the proxy — the proxy must never see this object).
	mustRun(t, "git", "-C", dst, "fetch", "-q", "file://"+stale, "main:refs/heads/stale")
	if got := revParse(t, dst, "refs/heads/stale"); got != staleTip {
		t.Fatalf("stale branch in clone = %s, want %s", got, staleTip)
	}

	// Advance upstream with a new non-secret file so the fetch has new objects.
	newTip := advanceUpstreamNewFile(t, h, "newfile.txt", "new content\n")

	// THE REPRO: fetch through the enforce path. The client advertises the stale
	// commit as a have; the proxy must tolerate it (non-common ground) and serve
	// the new objects — no "bad object", no 502, no wasted Repair.
	fetchCmd := h.Git(dst, "fetch", "origin", "main")
	out, err := fetchCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fetch through proxy with an unknown have failed (issue #75 repro):\n%s", out)
	}
	if strings.Contains(string(out), "bad object") {
		t.Errorf("fetch output contains 'bad object' (the unknown-have rev-list failure signature):\n%s", out)
	}

	// The new tip must have arrived.
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != newTip {
		t.Fatalf("after fetch: origin/main = %s, upstream tip = %s", got, newTip)
	}

	// The mirror must NOT have been repaired (no RemoveAll + re-clone): the
	// unknown have is a client-side object, so a Repair cannot help and would be
	// wasted work.
	afterInode := dirInode(t, mirrorDir)
	if beforeInode != afterInode {
		t.Errorf("mirror dir inode changed from %d to %d; a Repair (RemoveAll+reclone) was triggered — the unknown have must NOT cause a wasted re-clone", beforeInode, afterInode)
	}
}

// dirInode returns the inode of dir (used to detect a mirror Repair, which
// RemoveAll + re-clones the mirror directory and therefore changes its inode).
func dirInode(t *testing.T, dir string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	return st.Ino
}
