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
	idx, err := buildBlobPathIndex(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("gitx: resolve %s: %w", oid, err)
	}
	return idx[oid], nil
}

// ResolveMany is the bulk form of Resolve: it returns the full set of paths
// for EACH of oids in a single tree walk, rather than one walk per oid. This
// matters for the full-clone read-protection path (uploadpack_enforce.go),
// which previously derived a blob's path from `git rev-list --objects`'s
// output — that command dedupes by OID and prints only the FIRST path per
// object, so a blob reachable at both a denied path and an allowed path
// (identical content, or a rename across history) could be under-reported
// and served. Calling Resolve once per blob would fix that but re-walk every
// root tree once per blob (the exact process-spawn amplification this
// package's ls-tree fan-out is already flagged for); ResolveMany walks once
// and answers for the whole wanted set. A nil/empty oids list yields nil with
// no error. The per-mirror mutex is held for serialization.
func ResolveMany(ctx context.Context, m *Mirror, oids []string) (map[string][]string, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := buildBlobPathIndex(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("gitx: resolve many: %w", err)
	}
	out := make(map[string][]string, len(oids))
	for _, oid := range oids {
		if oid == "" {
			continue
		}
		out[oid] = idx[oid] // nil (absent) is a valid, meaningful answer: no path found
	}
	return out, nil
}

// buildBlobPathIndex walks every distinct root tree reachable from any ref
// EXACTLY ONCE and returns the full blob-oid -> []path mapping for every blob
// in the mirror. The caller MUST already hold m.mu (this is the unlocked core
// shared by Resolve and ResolveMany, mirroring filterPresentHaves's
// convention). See Resolve's doc comment for why a full tree walk (not
// `git rev-list --objects`) is required: a security filter must never
// under-report a blob's paths.
func buildBlobPathIndex(ctx context.Context, m *Mirror) (map[string][]string, error) {
	// Enumerate every distinct root tree reachable from any ref. `git log --all
	// --format=%T` lists the root tree (%T) of every reachable commit; an empty
	// repo (no refs) produces no output and exits 0, yielding an empty result.
	out, err := runGit(ctx, m.dir, "log", "--all", "--format=%T")
	if err != nil {
		return nil, fmt.Errorf("enumerate root trees: %w", err)
	}
	rootTrees := dedupStrings(splitCleanLines(out))

	// For each distinct root tree, recursively list every blob with its full
	// path. `ls-tree -r` lists only leaf blobs (not intermediate tree
	// objects), so each line is a blob entry reachable from that root tree. A
	// blob reachable at multiple paths within the same tree (same content in
	// two files) appears once per path; a blob renamed across commits appears
	// under each commit's tree; both are captured and deduped here, for every
	// blob in the mirror at once (not filtered to a single target oid).
	seen := make(map[string]map[string]struct{})
	idx := make(map[string][]string)
	for _, tree := range rootTrees {
		out, err := runGit(ctx, m.dir, "ls-tree", "-r", "--format=%(objectname) %(path)", tree)
		if err != nil {
			return nil, fmt.Errorf("ls-tree %s: %w", tree, err)
		}
		for _, line := range splitCleanLines(out) {
			sp := strings.IndexByte(line, ' ')
			if sp < 0 {
				continue // malformed line (should not happen for ls-tree -r)
			}
			oid := line[:sp]
			// Path is everything after the first space, so paths containing
			// spaces are preserved. (Paths containing newlines cannot occur in
			// git's line-based ls-tree output; this matches the line-based
			// limitation of WantedObjects/parseObjectPaths.)
			p := line[sp+1:]
			perOID := seen[oid]
			if perOID == nil {
				perOID = make(map[string]struct{})
				seen[oid] = perOID
			}
			if _, ok := perOID[p]; ok {
				continue
			}
			perOID[p] = struct{}{}
			idx[oid] = append(idx[oid], p)
		}
	}
	return idx, nil
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
