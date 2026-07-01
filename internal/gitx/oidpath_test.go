package gitx_test

import (
	"context"
	"os"
	"path/filepath"
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