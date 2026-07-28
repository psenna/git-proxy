package gitx_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/gitx"
)

// These tests exercise the inspection mirror against a real git binary and a
// real temporary bare repository — no mocks. They require `git` on PATH.

// gitBinary skips the test if git is unavailable.
func gitBinary(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not found on PATH: %v", err)
	}
}

// makeSourceRepo creates a non-bare git repo at dir with a linear history of n
// commits, each touching a distinct file. It returns the SHAs in order (oldest
// first): tips[i] is the commit at step i+1.
func makeSourceRepo(t *testing.T, dir string, n int) []string {
	t.Helper()
	mustGit(t, "", "init", "-q", "-b", "main", dir)
	mustGit(t, dir, "config", "user.email", "test@example.com")
	mustGit(t, dir, "config", "user.name", "Test")
	tips := make([]string, 0, n)
	for i := 0; i < n; i++ {
		file := filepath.Join(dir, "file"+itoa(i)+".txt")
		if err := os.WriteFile(file, []byte("content "+itoa(i)+"\n"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		mustGit(t, dir, "add", "file"+itoa(i)+".txt")
		mustGit(t, dir, "commit", "-q", "-m", "commit "+itoa(i))
		tips = append(tips, revParseHead(t, dir))
	}
	return tips
}

func itoa(i int) string {
	return strings.TrimSpace(string(rune('0'+i)))
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func revParseHead(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// makeBareUpstream creates a bare repo at barePath, seeded by pushing the
// source repo's main branch over file://.
func makeBareUpstream(t *testing.T, barePath, sourceDir string) {
	t.Helper()
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", barePath)
	mustGit(t, sourceDir, "push", "-q", "file://"+barePath, "main")
}

// makePackfile builds a packfile containing the objects reachable from tip in
// sourceDir and returns its bytes.
func makePackfile(t *testing.T, sourceDir, tip string) []byte {
	t.Helper()
	// Create a packfile via `git pack-objects --stdout` containing the objects
	// reachable from tip.
	cmd := exec.Command("git", "-C", sourceDir, "pack-objects", "--stdout")
	cmd.Stdin = strings.NewReader(tip + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	// If pack-objects produced nothing (e.g. everything already packed and
	// thin), retry with --revs and an explicit want. Fallback: use `git
	// repack` output.
	if out.Len() == 0 {
		cmd = exec.Command("git", "-C", sourceDir, "pack-objects", "--stdout", "--revs")
		cmd.Stdin = strings.NewReader("--" + tip + "\n")
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("pack-objects --revs: %v", err)
		}
	}
	if out.Len() == 0 {
		t.Fatalf("pack-objects produced no bytes for tip %s", tip)
	}
	return out.Bytes()
}

// TestMirrorOpenRefreshIngestIsAncestor exercises the full mirror lifecycle
// against a real git binary: open (clone), refresh after upstream advances,
// ingest a pushed packfile, and walk ancestry for FF/non-FF/create/delete.
func TestMirrorOpenRefreshIngestIsAncestor(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	tips := makeSourceRepo(t, source, 3) // A(0) -> B(1) -> C(2)
	A, B, C := tips[0], tips[1], tips[2]

	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	root := t.TempDir()
	m, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// After open, the mirror has the upstream tip (C). A is an ancestor of C;
	// C is not an ancestor of A.
	if ok, err := m.IsAncestor(ctx, A, C); err != nil || !ok {
		t.Fatalf("IsAncestor(A,C) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := m.IsAncestor(ctx, C, A); err != nil || ok {
		t.Fatalf("IsAncestor(C,A) = (%v, %v), want (false, nil)", ok, err)
	}

	// Create and delete are not force-pushes: return (false, nil).
	if ok, err := m.IsAncestor(ctx, "", C); err != nil || ok {
		t.Fatalf("IsAncestor(\"\",C) = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := m.IsAncestor(ctx, C, ""); err != nil || ok {
		t.Fatalf("IsAncestor(C,\"\") = (%v, %v), want (false, nil)", ok, err)
	}

	// Refresh after advancing upstream out-of-band: add a commit D on a new
	// root and push it. The mirror must see D after Refresh.
	work := t.TempDir()
	mustGit(t, "", "clone", "-q", "file://"+bare, work)
	mustGit(t, work, "config", "user.email", "test@example.com")
	mustGit(t, work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "new.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write new.txt: %v", err)
	}
	mustGit(t, work, "add", "new.txt")
	mustGit(t, work, "commit", "-q", "-m", "advance to D")
	D := revParseHead(t, work)
	mustGit(t, work, "push", "-q", "origin", "main")

	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// Now D is present; A is an ancestor of D (linear history A->B->C->D).
	if ok, err := m.IsAncestor(ctx, A, D); err != nil || !ok {
		t.Fatalf("after Refresh IsAncestor(A,D) = (%v, %v), want (true, nil)", ok, err)
	}

	// Ingest a packfile containing C's objects into the mirror. C is already
	// present, so ingest a pack of an unrelated branch to prove objects land.
	// Build a divergent commit E (rewrite of B) in a fresh worktree and pack it.
	diverge := t.TempDir()
	mustGit(t, "", "clone", "-q", "file://"+bare, diverge)
	mustGit(t, diverge, "config", "user.email", "test@example.com")
	mustGit(t, diverge, "config", "user.name", "Test")
	mustGit(t, diverge, "checkout", "-q", "-b", "topic", B)
	if err := os.WriteFile(filepath.Join(diverge, "topic.txt"), []byte("topic\n"), 0o644); err != nil {
		t.Fatalf("write topic.txt: %v", err)
	}
	mustGit(t, diverge, "add", "topic.txt")
	mustGit(t, diverge, "commit", "-q", "-m", "topic commit E")
	E := revParseHead(t, diverge)

	pack := makePackfile(t, diverge, E)
	if err := m.IngestPackfile(ctx, bytes.NewReader(pack)); err != nil {
		t.Fatalf("IngestPackfile: %v", err)
	}
	// After ingest, E's objects are in the mirror. B is an ancestor of E
	// (topic was branched from B); D is NOT an ancestor of E (divergent).
	if ok, err := m.IsAncestor(ctx, B, E); err != nil || !ok {
		t.Fatalf("after Ingest IsAncestor(B,E) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := m.IsAncestor(ctx, D, E); err != nil || ok {
		t.Fatalf("after Ingest IsAncestor(D,E) = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestMirrorOpenCachedReopen verifies Open is idempotent: reopening an existing
// mirror directory does not re-clone and still yields a usable mirror.
func TestMirrorOpenCachedReopen(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	makeSourceRepo(t, source, 1)
	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	root := t.TempDir()
	m1, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	tip := revParseHead(t, source)
	if ok, err := m1.IsAncestor(ctx, tip, tip); err != nil || !ok {
		t.Fatalf("IsAncestor(tip,tip) = (%v, %v), want (true, nil)", ok, err)
	}
	m2, err := gitx.Open(ctx, "file://"+bare, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	if ok, err := m2.IsAncestor(ctx, tip, tip); err != nil || !ok {
		t.Fatalf("reopen IsAncestor(tip,tip) = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestMirror_ConcurrentRefreshIngestIsAncestorNoLockError spawns N goroutines
// that each Refresh, IngestPackfile, and IsAncestor through the SAME mirror
// concurrently — the shared-bare-dir scenario of concurrent pushes to one repo.
// Without per-mirror serialization the git fetch (ref locks) and index-pack
// invocations race and can surface spurious "cannot lock ref" errors on
// legitimate pushes. With the internal mutex, every git invocation is serialized
// and all goroutines complete cleanly.
func TestMirror_ConcurrentRefreshIngestIsAncestorNoLockError(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Base commit A on the upstream.
	source := t.TempDir()
	tips := makeSourceRepo(t, source, 1)
	A := tips[0]
	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	root := t.TempDir()
	m, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Build N divergent commits B_i (each a child of A on its own branch) and a
	// packfile for each, so concurrent IngestPackfile calls write distinct packs
	// (realistic concurrent-push shape, no identical-pack filename collision).
	const n = 8
	type prepared struct {
		tip  string
		pack []byte
	}
	preps := make([]prepared, n)
	for i := 0; i < n; i++ {
		w := t.TempDir()
		mustGit(t, "", "clone", "-q", "file://"+bare, w)
		mustGit(t, w, "config", "user.email", "test@example.com")
		mustGit(t, w, "config", "user.name", "Test")
		mustGit(t, w, "checkout", "-q", "-b", fmt.Sprintf("topic-%d", i), A)
		if err := os.WriteFile(filepath.Join(w, fmt.Sprintf("topic-%d.txt", i)), []byte(fmt.Sprintf("topic %d\n", i)), 0o644); err != nil {
			t.Fatalf("write topic file: %v", err)
		}
		mustGit(t, w, "add", fmt.Sprintf("topic-%d.txt", i))
		mustGit(t, w, "commit", "-q", "-m", fmt.Sprintf("topic commit %d", i))
		preps[i] = prepared{tip: revParseHead(t, w), pack: makePackfile(t, w, revParseHead(t, w))}
	}

	var wg sync.WaitGroup
	type result struct {
		ok  bool
		err error
	}
	errs := make([]error, n)
	ancestry := make([]result, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.Refresh(ctx); err != nil {
				errs[i] = fmt.Errorf("Refresh: %w", err)
				return
			}
			if err := m.IngestPackfile(ctx, bytes.NewReader(preps[i].pack)); err != nil {
				errs[i] = fmt.Errorf("IngestPackfile: %w", err)
				return
			}
			ok, err := m.IsAncestor(ctx, A, preps[i].tip)
			ancestry[i] = result{ok: ok, err: err}
			if err != nil {
				errs[i] = fmt.Errorf("IsAncestor: %w", err)
			}
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e == nil {
			continue
		}
		if strings.Contains(e.Error(), "lock") {
			t.Errorf("goroutine %d hit a ref-lock race (must be serialized): %v", i, e)
		} else {
			t.Errorf("goroutine %d unexpected error: %v", i, e)
		}
	}
	for i, r := range ancestry {
		if r.err != nil || !r.ok {
			t.Errorf("goroutine %d IsAncestor(A,B_i) = (%v, %v), want (true, nil); B_i objects must be present after ingest", i, r.ok, r.err)
		}
	}
}
// makeThinPackfile builds a THIN packfile: objects reachable from `want` but
// NOT from `not`, with deltas allowed against the excluded `not` objects (which
// the receiver is assumed to already have). This is what `git push` over HTTP
// actually sends — unlike makePackfile, which builds a self-contained full pack.
func makeThinPackfile(t *testing.T, dir, want, not string) []byte {
	t.Helper()
	cmd := exec.Command("git", "-C", dir,
		"-c", "pack.window=100", "-c", "pack.depth=50",
		"pack-objects", "--stdout", "--thin", "--revs")
	cmd.Stdin = strings.NewReader(want + "\n^" + not + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pack-objects --thin --revs: %v", err)
	}
	if out.Len() == 0 {
		t.Fatalf("pack-objects --thin produced no bytes for want=%s not=%s", want, not)
	}
	return out.Bytes()
}

// TestMirrorIngestThinPack verifies IngestPackfile can ingest a THIN pack — the
// kind `git push` over HTTP sends — whose deltas reference bases the mirror
// already has. Before --fix-thin was added to index-pack, this failed with
// "fatal: pack has N unresolved deltas" and every follow-up branch push was
// rejected with an opaque "inspection failed" (the first push of a branch
// happened to send a non-thin pack and passed; subsequent pushes were thin and
// failed). See internal/gitproto/proxy.go "inspection failed".
func TestMirrorIngestThinPack(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// A large base blob so the tip's small modification deltas against it —
	// delta creation must be deterministic for the thin-pack condition to
	// reproduce (tiny one-line files don't always produce deltas).
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	base := strings.Repeat("base content line\n", 400)
	if err := os.WriteFile(filepath.Join(source, "big.txt"), []byte(base), 0o644); err != nil {
		t.Fatalf("write big.txt: %v", err)
	}
	mustGit(t, source, "add", "big.txt")
	mustGit(t, source, "commit", "-q", "-m", "base B")
	B := revParseHead(t, source)

	// Upstream (bare) has only B — push B before creating the tip.
	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	// Tip T: small append to big.txt, committed on main, NOT pushed upstream.
	tip := base + "extra line at end\n"
	if err := os.WriteFile(filepath.Join(source, "big.txt"), []byte(tip), 0o644); err != nil {
		t.Fatalf("write big.txt tip: %v", err)
	}
	mustGit(t, source, "add", "big.txt")
	mustGit(t, source, "commit", "-q", "-m", "tip T")
	T := revParseHead(t, source)

	// Thin pack of T excluding B — exactly what a client push of T sends.
	pack := makeThinPackfile(t, source, T, B)

	// Sanity guard: confirm the pack is genuinely thin/dependent (a delta base
	// is omitted) by failing to index it standalone in an empty bare repo. If
	// git instead produced a self-contained pack, the regression can't be
	// reproduced here — skip rather than pass vacuously.
	emptyBare := t.TempDir()
	mustGit(t, "", "init", "--bare", "-q", emptyBare)
	standalone := exec.Command("git", "-C", emptyBare, "index-pack", "--stdin")
	standalone.Stdin = bytes.NewReader(pack)
	if err := standalone.Run(); err == nil {
		t.Skip("git produced a self-contained pack (no delta against B); cannot reproduce thin-pack regression")
	}

	// Mirror holds B (cloned + Refreshed from the upstream); T is absent.
	root := t.TempDir()
	m, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Without --fix-thin this returned "fatal: pack has N unresolved deltas".
	if err := m.IngestPackfile(ctx, bytes.NewReader(pack)); err != nil {
		t.Fatalf("IngestPackfile(thin pack) = %v; index-pack must run with --fix-thin", err)
	}
	if ok, err := m.IsAncestor(ctx, B, T); err != nil || !ok {
		t.Fatalf("after Ingest thin pack, IsAncestor(B,T) = (%v, %v), want (true, nil)", ok, err)
	}
}
