package gitx_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitx"
)

// TestOidpath_Resolve verifies the OID->path resolver: given a blob OID the
// mirror knows, Resolve returns at least one path that references it. This is
// the skeleton Task 10's on-demand blob-denial path will use to map a requested
// OID back to a path the read deny matcher can evaluate. Task 9 does not call
// Resolve directly (it uses the rev-list --objects paths from WantedObjects);
// this test pins the skeleton contract so Task 10 can build on it.
func TestOidpath_Resolve(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Source repo with a.txt and sub/c.txt so we can resolve a nested path too.
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	writeFile(t, source, "sub/c.txt", "gamma\n")
	mustGit(t, source, "add", "a.txt", "sub/c.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a and sub/c")

	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	root := t.TempDir()
	m, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Locate the a.txt blob OID via rev-list --objects, then Resolve it.
	objs, err := m.WantedObjects(ctx, []string{"HEAD"}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	var aOID, cOID string
	for _, op := range objs {
		switch op.Path {
		case "a.txt":
			aOID = op.OID
		case "sub/c.txt":
			cOID = op.OID
		}
	}
	if aOID == "" || cOID == "" {
		t.Fatalf("missing a.txt/sub/c.txt OIDs in %+v", objs)
	}

	paths, err := gitx.Resolve(ctx, m, aOID)
	if err != nil {
		t.Fatalf("Resolve a.txt: %v", err)
	}
	if !contains(paths, "a.txt") {
		t.Errorf("Resolve(aOID) = %v, want to include a.txt", paths)
	}

	paths, err = gitx.Resolve(ctx, m, cOID)
	if err != nil {
		t.Fatalf("Resolve c.txt: %v", err)
	}
	if !contains(paths, "sub/c.txt") {
		t.Errorf("Resolve(cOID) = %v, want to include sub/c.txt", paths)
	}

	// An OID the mirror does not know resolves to no paths (empty, no error).
	unknown := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	paths, err = gitx.Resolve(ctx, m, unknown)
	if err != nil {
		t.Fatalf("Resolve unknown: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("Resolve(unknown) = %v, want empty", paths)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestOidpath_Resolve_MultiPath verifies the multi-path contract: a blob
// reachable at MULTIPLE paths (same content in three files: a.txt, b.txt,
// sub/c.txt) resolves to ALL three paths, not just the first one rev-list
// encounters. This is the security-critical correctness property for the
// on-demand deny path: if ANY path referencing the blob is denied, the proxy
// must deny the blob, so Resolve MUST return every path. `git rev-list
// --objects --all` dedupes by OID and would return only ONE path (the gap),
// so this test pins the tree-walk implementation.
func TestOidpath_Resolve_MultiPath(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	// Same content in three files → one blob OID reachable at three paths.
	const shared = "shared-content-line\n"
	writeFile(t, source, "a.txt", shared)
	writeFile(t, source, "b.txt", shared)
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	writeFile(t, source, "sub/c.txt", shared)
	mustGit(t, source, "add", "a.txt", "b.txt", "sub/c.txt")
	mustGit(t, source, "commit", "-q", "-m", "add shared content at three paths")

	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	root := t.TempDir()
	m, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	sharedOID := strings.TrimSpace(mustOutputRevParse(t, source, "HEAD:a.txt"))
	if aB := strings.TrimSpace(mustOutputRevParse(t, source, "HEAD:b.txt")); aB != sharedOID {
		t.Fatalf("setup: a.txt and b.txt must share an OID; got a=%s b=%s", sharedOID, aB)
	}
	if cOID := strings.TrimSpace(mustOutputRevParse(t, source, "HEAD:sub/c.txt")); cOID != sharedOID {
		t.Fatalf("setup: sub/c.txt must share the OID; got %s", cOID)
	}

	paths, err := gitx.Resolve(ctx, m, sharedOID)
	if err != nil {
		t.Fatalf("Resolve shared OID: %v", err)
	}
	for _, want := range []string{"a.txt", "b.txt", "sub/c.txt"} {
		if !contains(paths, want) {
			t.Errorf("Resolve(sharedOID) = %v, want to include %q (multi-path: ALL paths must be returned)", paths, want)
		}
	}
	if len(paths) != 3 {
		t.Errorf("Resolve(sharedOID) returned %d paths %v, want exactly 3 (no dupes, no missing)", len(paths), paths)
	}
}

// TestOidpath_Resolve_NoPath_OrphanBlob verifies a blob the mirror has in its
// object store but that is NOT referenced by any tree (an orphan/dangling
// blob) resolves to an empty (non-nil) slice with no error. The on-demand deny
// path treats a blob with no resolvable path as DENIED (fail-closed), but the
// Resolve contract itself returns empty, no error.
func TestOidpath_Resolve_NoPath_OrphanBlob(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")

	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	makeBareUpstream(t, bare, source)

	root := t.TempDir()
	m, err := gitx.Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Write an orphan blob directly into the MIRROR's object store (not into any
	// tree) via `git hash-object -w --stdin`. It is present in the store but
	// unreferenced by any tree, so no path resolves.
	cmd := exec.Command("git", "-C", m.Dir(), "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("orphan-blob-not-in-any-tree\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hash-object -w into mirror: %v", err)
	}
	orphanOID := strings.TrimSpace(string(out))

	// Sanity: the orphan blob IS present in the mirror's object store.
	if err := exec.Command("git", "-C", m.Dir(), "cat-file", "-e", orphanOID).Run(); err != nil {
		t.Fatalf("orphan blob %s not present in mirror store: %v", orphanOID, err)
	}

	paths, err := gitx.Resolve(ctx, m, orphanOID)
	if err != nil {
		t.Fatalf("Resolve orphan blob: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("Resolve(orphan blob present in store but unreferenced) = %v, want empty (no path)", paths)
	}
}

// mustOutputRevParse runs `git -C dir rev-parse ref` and returns trimmed stdout.
func mustOutputRevParse(t *testing.T, dir string, ref string) string {
	t.Helper()
	args := []string{"rev-parse"}
	if dir != "" {
		args = append([]string{"-C", dir}, args...)
	}
	args = append(args, ref)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}