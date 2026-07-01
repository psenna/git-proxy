package gitx_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitx"
)

// TestMirror_WantedObjects exercises the rev-list --objects wrapper: it returns
// the commit and root tree (no path) plus the blobs (with their paths) reachable
// from the wanted tip and excluding the haves. Used by the read-protection path
// to enumerate the object set the proxy must pack (and withhold denied blobs
// from).
func TestMirror_WantedObjects(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Source repo with two files in the first commit (A), then a second commit (B)
	// adding a nested file under a subdirectory so the root tree and a subtree both
	// appear.
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	writeFile(t, source, "b.txt", "beta\n")
	mustGit(t, source, "add", "a.txt", "b.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a and b")
	A := revParseHead(t, source)
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	writeFile(t, source, "sub/c.txt", "gamma\n")
	mustGit(t, source, "add", "sub/c.txt")
	mustGit(t, source, "commit", "-q", "-m", "add sub/c")
	B := revParseHead(t, source)

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

	// Wanted set for [B] excluding nothing: commit B, root tree of B, the sub
	// tree, and the three blobs (a.txt, b.txt, sub/c.txt).
	objs, err := m.WantedObjects(ctx, []string{B}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	byPath := map[string]string{} // path -> oid ("" for commits/root trees)
	oids := map[string]bool{}
	for _, op := range objs {
		byPath[op.Path] = op.OID
		oids[op.OID] = true
	}
	if !oids[B] {
		t.Errorf("WantedObjects missing commit %s; got %+v", B, objs)
	}
	if byPath["a.txt"] == "" {
		t.Errorf("WantedObjects missing a.txt blob entry; got %+v", objs)
	}
	if byPath["b.txt"] == "" {
		t.Errorf("WantedObjects missing b.txt blob entry; got %+v", objs)
	}
	if byPath["sub/c.txt"] == "" {
		t.Errorf("WantedObjects missing sub/c.txt blob entry; got %+v", objs)
	}
	// The root tree of B has an empty path (commits and the root tree are emitted
	// without a path). The sub tree (sub/) is emitted with path "sub".
	if byPath[""] == "" {
		t.Errorf("WantedObjects missing root-tree/commit entry; got %+v", objs)
	}
	if byPath["sub"] == "" {
		t.Errorf("WantedObjects missing sub tree entry; got %+v", objs)
	}

	// Excluding A: B's objects minus those already reachable from A. Commit A,
	// A's root tree, and the a.txt/b.txt blobs are all reachable from A, so they
	// must be excluded. The new commit B, B's root tree, the sub tree, and c.txt
	// are new.
	objs, err = m.WantedObjects(ctx, []string{B}, []string{A})
	if err != nil {
		t.Fatalf("WantedObjects with haves: %v", err)
	}
	byPath = map[string]string{}
	oids = map[string]bool{}
	for _, op := range objs {
		byPath[op.Path] = op.OID
		oids[op.OID] = true
	}
	if !oids[B] {
		t.Errorf("WantedObjects(B not A) missing commit B; got %+v", objs)
	}
	if byPath["sub/c.txt"] == "" {
		t.Errorf("WantedObjects(B not A) missing c.txt; got %+v", objs)
	}
	if byPath["a.txt"] != "" {
		t.Errorf("WantedObjects(B not A) should exclude a.txt (reachable from A); got %+v", objs)
	}
	if byPath["b.txt"] != "" {
		t.Errorf("WantedObjects(B not A) should exclude b.txt (reachable from A); got %+v", objs)
	}
}

// TestMirror_PackObjects exercises the explicit-OID pack-objects wrapper used by
// the read-protection path to assemble a filtered packfile. It must:
//   - produce a valid pack (PACK magic) for the given OID list,
//   - honor the thin flag (thin pack has a different shape but is still valid),
//   - genuinely omit a blob OID excluded from the input list, so a withheld
//     denied blob is absent from the served packfile.
func TestMirror_PackObjects(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	writeFile(t, source, "b.txt", "beta\n")
	mustGit(t, source, "add", "a.txt", "b.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a and b")
	tip := revParseHead(t, source)

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

	objs, err := m.WantedObjects(ctx, []string{tip}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	allOIDs := make([]string, 0, len(objs))
	for _, op := range objs {
		allOIDs = append(allOIDs, op.OID)
	}

	// Full (non-thin) pack: must be a valid PACK stream and contain every object.
	pack, err := m.PackObjects(ctx, allOIDs, false)
	if err != nil {
		t.Fatalf("PackObjects non-thin: %v", err)
	}
	if !bytes.HasPrefix(pack, []byte("PACK")) {
		t.Fatalf("non-thin pack missing PACK magic; got %x", pack[:8])
	}
	gotOIDs := indexPack(t, m.Dir(), pack)
	want := oidSet(allOIDs)
	if !oidSetEqual2(gotOIDs, want) {
		t.Fatalf("non-thin pack object set = %v, want %v", sortedKeys(gotOIDs), sortedKeys(want))
	}

	// Thin pack: still a valid PACK stream. A thin pack references objects not
	// present in the pack (deltas against a base the receiver is expected to
	// have); for a self-contained want set it is allowed to be identical to the
	// non-thin pack. We only assert it parses as a pack here.
	thin, err := m.PackObjects(ctx, allOIDs, true)
	if err != nil {
		t.Fatalf("PackObjects thin: %v", err)
	}
	if !bytes.HasPrefix(thin, []byte("PACK")) {
		t.Fatalf("thin pack missing PACK magic; got %x", thin[:8])
	}

	// Withhold a blob: drop a.txt's OID from the input and assert the resulting
	// pack does NOT contain it, while the remaining objects are still present.
	// This is the core read-protection guarantee.
	var aOID, bOID string
	for _, op := range objs {
		switch op.Path {
		case "a.txt":
			aOID = op.OID
		case "b.txt":
			bOID = op.OID
		}
	}
	if aOID == "" || bOID == "" {
		t.Fatalf("could not locate a.txt/b.txt OIDs in %+v", objs)
	}
	allowed := make([]string, 0, len(allOIDs)-1)
	for _, oid := range allOIDs {
		if oid == aOID {
			continue
		}
		allowed = append(allowed, oid)
	}
	filtered, err := m.PackObjects(ctx, allowed, false)
	if err != nil {
		t.Fatalf("PackObjects filtered: %v", err)
	}
	if !bytes.HasPrefix(filtered, []byte("PACK")) {
		t.Fatalf("filtered pack missing PACK magic; got %x", filtered[:8])
	}
	gotFiltered := indexPack(t, m.Dir(), filtered)
	if gotFiltered[aOID] {
		t.Errorf("filtered pack MUST NOT contain withheld a.txt blob %s; got %v", aOID, sortedKeys(gotFiltered))
	}
	if !gotFiltered[bOID] {
		t.Errorf("filtered pack missing b.txt blob %s; got %v", bOID, sortedKeys(gotFiltered))
	}
}

// indexPack writes pack to a temp .pack file and runs `git index-pack` (then
// `verify-pack -v`) to recover the set of object OIDs the pack carries. The
// mirror dir already has the objects, so index-pack will not need to fetch any
// thin-pack bases. Returns the set of OIDs the pack contains.
func indexPack(t *testing.T, mirrorDir string, pack []byte) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	packPath := filepath.Join(dir, "test.pack")
	if err := os.WriteFile(packPath, pack, 0o600); err != nil {
		t.Fatalf("write test pack: %v", err)
	}
	// index-pack replaces the trailing .pack with .idx for the output idx path.
	cmd := exec.Command("git", "-C", mirrorDir, "index-pack", packPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("index-pack: %v\n%s", err, out)
	}
	idx := strings.TrimSuffix(packPath, ".pack") + ".idx"
	out, err := exec.Command("git", "-C", mirrorDir, "verify-pack", "-v", idx).CombinedOutput()
	if err != nil {
		t.Fatalf("verify-pack: %v\n%s", err, out)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 1 && len(f[0]) == 40 && isHex40(f[0]) {
			set[f[0]] = true
		}
	}
	return set
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func oidSet(oids []string) map[string]bool {
	set := map[string]bool{}
	for _, o := range oids {
		set[o] = true
	}
	return set
}

func oidSetEqual2(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}