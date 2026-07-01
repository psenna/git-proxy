package gitx

import (
	"context"
	"fmt"
	"strings"
)

// Resolve returns the set of paths at which oid appears across ALL objects
// reachable from any ref in the mirror. For a blob this is every file path the
// blob is reachable at (a blob with identical content at three files yields
// three paths); for a tree it is the directory path(s) (empty for a root tree).
// An OID the mirror does not know — or a blob present in the object store but
// referenced by no tree — resolves to an empty (non-nil) slice with no error.
//
// This is the OID->path resolution Task 10's on-demand blob-denial path uses to
// map a requested blob OID back to a path the read deny matcher can evaluate.
// Task 9 does NOT call Resolve directly: the read-protection withholding works
// over the wanted set, where WantedObjects already yields (oid, path) pairs
// from a single scoped `git rev-list --objects <wants> --not <haves>` invocation
// (rev-list --objects dedupes by OID and prints only the FIRST path per object,
// which is fine for the full-clone withholding path because it inspects the
// wanted set, not a single blob's full path history). Task 10's on-demand path
// resolves a single blob OID that may be reachable at many paths across many
// commits, so it needs ALL paths — hence this dedicated tree-walk resolver.
//
// Implementation (v1 choice — flagged for reviewer):
//
//   - Enumerate every DISTINCT root tree reachable from any ref via
//     `git log --all --format=%T` (one git invocation, O(commits) output).
//   - For each distinct root tree, `git ls-tree -r --format='%(objectname)
//     %(path)' <tree>` recursively lists every blob in that tree with its full
//     path; lines whose OID matches oid contribute their path. Paths are
//     deduped across root trees.
//
// Why not `git rev-list --objects --all` (the skeleton)? rev-list --objects
// dedupes by OID and prints only ONE path per object, so a blob reachable at
// multiple paths (the security-critical case: ANY denied path must deny the
// blob) would under-report. It also exits 128 ("missing blob object") when a
// referenced blob is ABSENT from the object store, breaking trees-only
// resolution; ls-tree reads the tree (always kept) and prints the entry's OID
// and path WITHOUT cat-file'ing the blob, so it resolves from trees alone.
//
// Perf characteristic (documented v1): O(distinct-root-trees) git ls-tree
// invocations, each listing all blobs in one root tree. Distinct root trees ≤
// commits (often far fewer, since only commits that changed the tree produce a
// new root tree). For a large repo this is more work than a single rev-list,
// but it is CORRECT for multi-path and robust to absent blobs — both required
// by the on-demand deny path. A cached OID->paths index is the explicit v1.md
// later optimization; v1 keeps it correct and simple.
//
// The per-mirror mutex is held for serialization with Refresh/IngestPackfile.
func Resolve(ctx context.Context, m *Mirror, oid string) ([]string, error) {
	if oid == "" {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Enumerate every distinct root tree reachable from any ref. `git log --all
	// --format=%T` lists the root tree (%T) of every reachable commit; an empty
	// repo (no refs) produces no output and exits 0, yielding an empty result.
	out, err := runGit(ctx, m.dir, "log", "--all", "--format=%T")
	if err != nil {
		return nil, fmt.Errorf("gitx: resolve %s: enumerate root trees: %w", oid, err)
	}
	rootTrees := dedupStrings(splitCleanLines(out))

	// For each distinct root tree, recursively list every blob with its full
	// path and collect paths whose blob OID matches. `ls-tree -r` lists only
	// leaf blobs (not intermediate tree objects), so each line is a blob entry
	// reachable from that root tree. A blob reachable at multiple paths within
	// the same tree (same content in two files) appears once per path; a blob
	// renamed across commits appears under each commit's tree; both are
	// captured and deduped here.
	seen := make(map[string]struct{})
	var paths []string
	for _, tree := range rootTrees {
		out, err := runGit(ctx, m.dir, "ls-tree", "-r", "--format=%(objectname) %(path)", tree)
		if err != nil {
			return nil, fmt.Errorf("gitx: resolve %s: ls-tree %s: %w", oid, tree, err)
		}
		for _, line := range splitCleanLines(out) {
			sp := strings.IndexByte(line, ' ')
			if sp < 0 {
				continue // malformed line (should not happen for ls-tree -r)
			}
			if line[:sp] != oid {
				continue
			}
			// Path is everything after the first space, so paths containing
			// spaces are preserved. (Paths containing newlines cannot occur in
			// git's line-based ls-tree output; this matches the line-based
			// limitation of WantedObjects/parseObjectPaths.)
			p := line[sp+1:]
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// dedupStrings returns the first-seen-ordered, deduplicated copy of in. Empty
// strings are skipped. Used by Resolve to dedupe the root-tree list so the
// same tree (shared across many commits) is walked once.
func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}