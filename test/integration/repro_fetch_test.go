package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// advanceUpstreamNewFile advances the upstream bare repo (via file://, bypassing
// the proxy) with one new NON-secret file, so a subsequent fetch has something
// new to receive. It returns the new upstream tip SHA. Used by repro tests that
// need a real incremental fetch (new objects) without re-seeding secrets.
func advanceUpstreamNewFile(t *testing.T, h *Harness, name, content string) string {
	t.Helper()
	work := t.TempDir()
	mustRun(t, "git", "clone", "-q", "file://"+h.BarePath, work)
	mustRun(t, "git", "-C", work, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	mustRun(t, "git", "-C", work, "add", name)
	mustRun(t, "git", "-C", work, "commit", "-q", "-m", "add "+name)
	mustRun(t, "git", "-C", work, "push", "-q", "origin", "main")
	return h.UpstreamRef(t, "refs/heads/main")
}

// seedManyCommits advances the upstream bare repo (via file://, bypassing the
// proxy) with n distinct NON-secret files, one per commit. The point is to grow
// the repo past git's stateless first-flush threshold (16 haves) so a subsequent
// incremental `git fetch` advertises ≥16 haves and sends a preliminary no-`done`
// negotiation round — the round that exposed issue #64
// (`expected ACK/NAK, got '?PACK'`). 40 sits comfortably above 16 (and above a
// possible 32 threshold in newer git), with margin. Returns the new upstream tip.
func seedManyCommits(t *testing.T, h *Harness, n int) string {
	t.Helper()
	work := t.TempDir()
	mustRun(t, "git", "clone", "-q", "file://"+h.BarePath, work)
	mustRun(t, "git", "-C", work, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", work, "config", "user.name", "Test")
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("file-%d.txt", i)
		if err := os.WriteFile(filepath.Join(work, name), []byte(fmt.Sprintf("content %d\n", i)), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		mustRun(t, "git", "-C", work, "add", name)
		mustRun(t, "git", "-C", work, "commit", "-q", "-m", "add "+name)
	}
	// Consolidate the n new loose objects into a single pack before the file://
	// push, and push --no-thin so the receiver gets a self-contained pack. The
	// bare upstream has gc.auto=0 (objects stay loose), and on CI's overlayfs a
	// thin-pack push of many fresh loose objects intermittently failed with
	// `remote unpack failed: eof before pack header` / `unable to read <oid>` on
	// the sender. Repacking cuts send-pack's loose-object reads to one pack, and
	// --no-thin removes the receiver's thin-pack base resolution entirely.
	mustRun(t, "git", "-C", work, "repack", "-a", "-d", "-q")
	mustRun(t, "git", "-C", work, "push", "--no-thin", "-q", "origin", "main")
	return h.UpstreamRef(t, "refs/heads/main")
}

// TestRepro_PartialCloneThenPlainFetch is the faithful reproduction of the
// ai-sandbox agent's reported failure: a read-protected repo (read.deny:
// secrets/**) cloned with --filter=blob:none, then advanced upstream, then a
// plain `git fetch origin main` (NO --depth) through the enforce path. The user
// reported this failing with `fatal: git fetch-pack: expected ACK/NAK, got
// '?PACK'`. This test pins whether the enforce path actually serves a fetch the
// real git client accepts, or whether it reproduces the user's error.
func TestRepro_PartialCloneThenPlainFetch(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h) // README + docs/guide.md + secrets/secret.txt
	// Grow the repo past git's stateless first-flush threshold (16 haves) so the
	// incremental fetch below advertises ≥16 haves and sends a preliminary
	// no-`done` negotiation round — the round that exposed issue #64
	// (`expected ACK/NAK, got '?PACK'`). 40 sits comfortably above 16 (and above a
	// possible 32 threshold in newer git), with margin. Without this the repro
	// passes vacuously (≤16 haves → single `done` round).
	seedManyCommits(t, h, 40)

	// Partial clone through the enforce path. Checkout aborts on the withheld
	// secret blob (expected); the repo + refs are still created.
	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "--filter=blob:none", h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	// Advance upstream with a NEW non-secret file → next fetch has new objects.
	newTip := advanceUpstreamNewFile(t, h, "newfile.txt", "new content\n")

	// THE REPRO: plain incremental fetch (haves present), no --depth.
	fetchCmd := h.Git(dst, "fetch", "origin", "main")
	if out, err := fetchCmd.CombinedOutput(); err != nil {
		t.Fatalf("plain fetch through enforce path failed (the user's reported bug):\n%s", out)
	}

	// The new tip must have arrived.
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != newTip {
		t.Fatalf("after fetch: origin/main = %s, upstream tip = %s", got, newTip)
	}
}

// TestRepro_ShallowFetch verifies the shallow/`deepen` support in the enforce
// path: after a `--filter=blob:none` clone of a read-protected repo, advancing
// upstream, a `git fetch --depth=1 origin main` through the enforce path
// SUCCEEDS (stateless deepen is a multi-round negotiation — a preliminary
// `want+deepen` round without `done` that expects ONLY the shallow preamble,
// then a final `done` round carrying the pack). This was the user's reported
// bug (`expected shallow/unshallow, got NAK`, then `expected shallow list`)
// before shallow support was implemented.
func TestRepro_ShallowFetch(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "--filter=blob:none", h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	newTip := advanceUpstreamNewFile(t, h, "shallow.txt", "shallow content\n")
	t.Logf("upstream tip after advance: %s", newTip)

	shallowCmd := h.Git(dst, "fetch", "--depth=1", "origin", "main")
	if out, err := shallowCmd.CombinedOutput(); err != nil {
		t.Fatalf("shallow fetch --depth=1 through enforce path failed:\n%s", out)
	}

	// The new tip must have arrived at the shallow cut.
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != newTip {
		t.Fatalf("after shallow fetch: origin/main = %s, upstream tip = %s", got, newTip)
	}
}

// TestRepro_ShallowClone verifies `git clone --filter=blob:none --depth=1`
// through the enforce path succeeds (a shallow PARTIAL clone — the realistic
// agent shape, since a shallow clone that withholds a denied blob still needs
// --filter to tolerate the missing blob), the clone is cut to depth 1, and the
// denied-path blob remains withheld from the shallow clone's object store
// (read protection holds for shallow clones too). The checkout aborts on the
// withheld secret blob (expected, same as the non-shallow partial clone); the
// repo + refs are still created and that is what we verify.
func TestRepro_ShallowClone(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	tip := h.UpstreamRef(t, "refs/heads/main")
	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:secrets/secret.txt"))

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "--filter=blob:none", "--depth=1", h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	// The shallow clone points at the upstream tip and is cut to depth 1.
	got := revParse(t, dst, "refs/remotes/origin/main")
	if got != tip {
		t.Fatalf("shallow clone: origin/main = %s, upstream tip = %s", got, tip)
	}
	out, err := exec.Command("git", "-C", dst, "rev-list", "--all", "--count").Output()
	if err != nil {
		t.Fatalf("rev-list --count in shallow clone: %v", err)
	}
	count := strings.TrimSpace(string(out))
	if count != "1" {
		t.Fatalf("shallow clone is not depth-1 (rev-list --all --count = %s, want 1)", count)
	}
	// The denied-path blob must be ABSENT from the shallow clone's local object
	// store (withheld from the shallow pack; the on-demand fetch for it is
	// denied). Inspect with --batch-all-objects so no promisor/on-demand fetch
	// is triggered.
	if presentObjectOIDs(t, dst)[secretOID] {
		t.Fatalf("DENY LEAK: denied secret blob %s is present in the shallow clone's object store (shallow pack withholding failed)", secretOID)
	}
}