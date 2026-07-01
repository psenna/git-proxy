package gitx

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestOidpath_Resolve_TreesOnly verifies the security-critical "trees-only"
// property: Resolve returns the path(s) for a blob OID even when the BLOB
// ITSELF IS ABSENT from the mirror's object store, as long as a reachable tree
// references it. This matters because the proxy serves a filtered packfile
// (withholding denied blobs); the inspection mirror is a full clone today, so
// the blob is normally present, but Resolve must NOT depend on the blob being
// cat-file-able — it walks trees, and tree entries carry the blob's OID +
// name without needing the blob bytes.
//
// The skeleton's `git rev-list --objects --all` FAILS (exit 128, "missing blob
// object") when a referenced blob is absent, so this test is the red→green
// evidence for the ls-tree-based implementation: rev-list errors, ls-tree
// succeeds by reading the tree only.
//
// The test constructs a bare repo with a tree that references an absent blob
// (built via `git hash-object -w --literally -t tree`, since `git mktree`
// refuses to create trees pointing at absent objects), commits it so it is
// reachable from a ref, then resolves the absent blob's OID through a Mirror
// pointed at the bare dir.
func TestOidpath_Resolve_TreesOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not found on PATH: %v", err)
	}
	ctx := context.Background()

	bare := t.TempDir()
	if out, err := exec.Command("git", "init", "--bare", "-q", "-b", "main", bare).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}

	// The blob OID for "hello\n" — written NOWHERE into the object store.
	blobOID := "ce013625030ba8dba906f756967f9e9ca394464a"

	// Build a tree object by hand that references the absent blob at "f.txt".
	// Tree entry binary: "<mode> <name>\0<20-byte-sha>". `git hash-object -w
	// --literally -t tree` accepts the raw bytes without validating that the
	// referenced objects exist (mktree validates and rejects; --literally does
	// not).
	treeBin := t.TempDir() + "/tree.bin"
	entry := append([]byte("100644 f.txt\x00"), hexToBytes(t, blobOID)...)
	if err := os.WriteFile(treeBin, entry, 0o600); err != nil {
		t.Fatalf("write tree.bin: %v", err)
	}
	treeOID := strings.TrimSpace(mustOutput2(t, bare, "hash-object", "-w", "--literally", "-t", "tree", treeBin))

	// Confirm the blob is ABSENT and the tree is PRESENT in the bare repo.
	if err := exec.Command("git", "-C", bare, "cat-file", "-e", blobOID).Run(); err == nil {
		t.Fatalf("setup invariant: blob %s should be ABSENT but cat-file -e succeeded", blobOID)
	}
	if err := exec.Command("git", "-C", bare, "cat-file", "-e", treeOID).Run(); err != nil {
		t.Fatalf("setup invariant: tree %s should be PRESENT but cat-file -e failed: %v", treeOID, err)
	}

	// Commit the tree so it is reachable from a ref (log --all --format=%T needs
	// at least one ref pointing at a commit).
	commit := strings.TrimSpace(mustOutput2(t, bare,
		"-c", "user.email=t@t", "-c", "user.name=t", "commit-tree", treeOID))
	if out, err := exec.Command("git", "-C", bare, "update-ref", "refs/heads/main", commit).CombinedOutput(); err != nil {
		t.Fatalf("update-ref: %v\n%s", err, out)
	}

	// Mirror pointed directly at the bare dir (constructed internally since the
	// dir/upstreamURL fields are unexported). The mutex zero-value is ready to
	// use; upstreamURL is unused by Resolve.
	m := &Mirror{dir: bare}

	paths, err := Resolve(ctx, m, blobOID)
	if err != nil {
		t.Fatalf("Resolve absent-blob OID: %v (rev-list --objects would error here; ls-tree must not)", err)
	}
	if len(paths) != 1 || paths[0] != "f.txt" {
		t.Errorf("Resolve(absent blob referenced by tree) = %v, want [f.txt] (resolved from tree alone, blob not present)", paths)
	}
}

// hexToBytes decodes a hex string to raw bytes (fails the test on bad input).
//
//nolint:unused // kept for the trees-only test's tree-object construction
func hexToBytes(t *testing.T, hex string) []byte {
	t.Helper()
	if len(hex)%2 != 0 {
		t.Fatalf("hexToBytes: odd length %d for %q", len(hex), hex)
	}
	out := make([]byte, len(hex)/2)
	for i := 0; i < len(out); i++ {
		hi := hexDigit2(hex[2*i])
		lo := hexDigit2(hex[2*i+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexDigit2(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		panic("bad hex digit")
	}
}

// mustOutput2 runs `git -C bare <args...>` and returns trimmed stdout, failing
// the test on error. (Named mustOutput2 to avoid clashing with the gitx_test
// mustOutput helper in the external test package — different package, but kept
// distinct for clarity.)
func mustOutput2(t *testing.T, bare string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", bare}, args...)
	out, err := exec.Command("git", full...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("git %s: %v\n%s", strings.Join(full, " "), err, ee.Stderr)
		}
		t.Fatalf("git %s: %v", strings.Join(full, " "), err)
	}
	return string(out)
}