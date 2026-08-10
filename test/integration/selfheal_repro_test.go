package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepro_MirrorSelfHealing_MissingAncestorObject reproduces the exact
// scenario from issues #69/#71: the mirror is missing a SINGLE ancestor object
// (not all objects), the tip commit IS present, so `git fetch` (Refresh) sends
// "have <tip>" and the server sends nothing — the missing ancestor is NOT
// re-downloaded. A full clone (no haves) then walks the full history via
// `git rev-list --objects <tip>`, hits the missing ancestor tree, and fails
// with "fatal: bad tree object". The proxy must self-heal (Repair + retry) so
// the clone still receives its packfile.
//
// This is the scenario the existing TestRepro_MirrorSelfHealing does NOT cover:
// that test deletes ALL pack files (every object missing), so `git fetch`
// re-downloads everything and self-healing is never exercised. Here only one
// ancestor tree object is removed; the tip and most of the graph survive, so
// Refresh is a genuine no-op and the corruption persists until self-healing
// repairs the mirror.
//
// The root cause this test pins down: git emits type-specific "bad tree object"
// (not the generic "bad object") when a tree is missing, and the original
// IsCorruptionError only matched "bad object" — so the self-healing wrapper
// never triggered and the fetch failed with HTTP 502.
func TestRepro_MirrorSelfHealing_MissingAncestorObject(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	// First clone through the enforce path to populate the mirror. Checkout
	// aborts on the withheld secret blob (expected); the repo + refs are still
	// created.
	clone1 := t.TempDir()
	dst1 := filepath.Join(clone1, "repo")
	if out, err := h.Git(clone1, "clone", "--filter=blob:none", h.UpstreamURL+"/test.git", dst1).CombinedOutput(); err != nil {
		t.Logf("first clone exit (expected — denied blob withheld at checkout): %v\n%s", err, out)
	}

	// Locate the mirror directory (the only subdirectory under MirrorRoot).
	entries, err := os.ReadDir(h.MirrorRoot)
	if err != nil {
		t.Fatalf("read mirror root: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no mirror directories found in MirrorRoot")
	}
	mirrorDir := filepath.Join(h.MirrorRoot, entries[0].Name())

	// Convert the mirror's packed objects to loose objects so a SINGLE object
	// can be deleted. `git unpack-objects` SKIPS objects that already exist in
	// a pack, so the pack must be removed BEFORE unpacking from the saved data.
	packDir := filepath.Join(mirrorDir, "objects", "pack")
	packs, err := filepath.Glob(filepath.Join(packDir, "*.pack"))
	if err != nil {
		t.Fatalf("glob pack files: %v", err)
	}
	if len(packs) == 0 {
		t.Fatal("no pack files found in mirror — expected a packed clone")
	}
	type packData struct {
		name string
		data []byte
	}
	var allPacks []packData
	for _, pack := range packs {
		data, rerr := os.ReadFile(pack)
		if rerr != nil {
			t.Fatalf("read pack %s: %v", pack, rerr)
		}
		allPacks = append(allPacks, packData{name: filepath.Base(pack), data: data})
	}
	for _, pat := range []string{"*.pack", "*.idx", "*.rev"} {
		files, _ := filepath.Glob(filepath.Join(packDir, pat))
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				t.Fatalf("remove %s: %v", f, err)
			}
		}
	}
	for _, pd := range allPacks {
		cmd := exec.Command("git", "-C", mirrorDir, "unpack-objects", "-q")
		cmd.Stdin = strings.NewReader(string(pd.data))
		if out, uerr := cmd.CombinedOutput(); uerr != nil {
			t.Fatalf("unpack-objects %s: %v\n%s", pd.name, uerr, out)
		}
	}

	// Delete the root tree of the FIRST (seed) commit — an ancestor of the tip.
	// The tip commit stays present, so Refresh's "have <tip>" negotiation is a
	// no-op and the missing ancestor persists. This is the exact "one missing
	// ancestor" scenario from the bug report.
	firstCommit := strings.TrimSpace(mustOutput(t, "git", "-C", mirrorDir, "rev-list", "--max-parents=0", "HEAD"))
	if firstCommit == "" {
		t.Fatal("could not find root commit in mirror")
	}
	commitObj := mustOutput(t, "git", "-C", mirrorDir, "cat-file", "-p", firstCommit)
	var treeOID string
	for _, line := range strings.Split(commitObj, "\n") {
		if strings.HasPrefix(line, "tree ") {
			treeOID = strings.TrimPrefix(line, "tree ")
			break
		}
	}
	if treeOID == "" {
		t.Fatalf("could not extract tree OID from commit %s", firstCommit)
	}
	loosePath := filepath.Join(mirrorDir, "objects", treeOID[:2], treeOID[2:])
	if _, serr := os.Stat(loosePath); serr != nil {
		t.Fatalf("loose object %s not found: %v", loosePath, serr)
	}
	if err := os.Remove(loosePath); err != nil {
		t.Fatalf("remove loose object %s: %v", loosePath, err)
	}

	// Prove the corruption is real AND that Refresh does NOT heal it (this is
	// what makes this test genuinely exercise self-healing, unlike the existing
	// test that deletes all packs). rev-list must fail; git fetch must succeed
	// (no-op); rev-list must STILL fail after fetch.
	if _, revErr := exec.Command("git", "-C", mirrorDir, "rev-list", "--objects", "HEAD").CombinedOutput(); revErr == nil {
		t.Fatal("post-corruption rev-list unexpectedly succeeded — corruption did not take effect")
	}
	if fetchOut, fetchErr := exec.Command("git", "-C", mirrorDir, "fetch", "--quiet", "origin").CombinedOutput(); fetchErr != nil {
		t.Fatalf("post-corruption fetch failed (expected to succeed as no-op): %v\n%s", fetchErr, fetchOut)
	}
	if _, revErr := exec.Command("git", "-C", mirrorDir, "rev-list", "--objects", "HEAD").CombinedOutput(); revErr == nil {
		t.Fatal("post-fetch rev-list unexpectedly succeeded — Refresh healed the corruption; this test does not exercise self-healing")
	}

	// THE REPRO: a brand-new full clone (no haves) through the enforce path.
	// WantedObjects must fail with "bad tree object" and the proxy must
	// self-heal (Repair + retry) so the clone receives its packfile.
	clone2 := t.TempDir()
	dst2 := filepath.Join(clone2, "repo")
	out, err := h.Git(clone2, "clone", "--filter=blob:none", h.UpstreamURL+"/test.git", dst2).CombinedOutput()
	if err != nil {
		// Checkout may fail on the withheld secret blob — that is expected and
		// NOT a self-healing failure. But a fetch-level failure (502 / bad
		// object) means self-healing did not work: no packfile, no refs.
		t.Logf("second clone exit: %v\n%s", err, out)
	}

	// The decisive assertion: origin/main must exist, proving the packfile was
	// delivered (the fetch succeeded after self-healing). If self-healing did
	// NOT trigger, the proxy returned 502 before any packfile was sent, the
	// clone failed at the fetch stage, and refs/remotes/origin/main does not
	// exist.
	got := revParse(t, dst2, "refs/remotes/origin/main")
	want := h.UpstreamRef(t, "refs/heads/main")
	if got != want {
		t.Fatalf("after self-healing clone: origin/main = %q, want upstream tip %q (fetch did not deliver the packfile — self-healing failed)\nclone output:\n%s",
			got, want, out)
	}
}
