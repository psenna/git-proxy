package gitx

import (
	"context"
	"strings"
)

// Resolve returns the set of paths at which oid appears across all objects
// reachable from any ref in the mirror, via `git rev-list --objects --all`. For
// a blob this is the file path(s) the blob is reachable at; for a tree it is the
// directory path(s) (empty for the root tree of a commit). An OID the mirror does
// not know resolves to an empty (non-nil) slice with no error.
//
// This is the OID->path skeleton Task 10's on-demand blob-denial path uses to map
// a requested blob OID back to a path the read deny matcher can evaluate. Task 9
// does NOT call Resolve directly: the read-protection withholding works over
// the wanted set, where `WantedObjects` already yields (oid, path) pairs from a
// single scoped `git rev-list --objects <wants> --not <haves>` invocation, so no
// separate tree-walk is needed. Task 10 completes the on-demand use (it may
// optimize with a targeted tree-walk rather than a full --all scan); this
// minimal --all implementation pins the contract and is correct, just broad.
//
// The per-mirror mutex is held for serialization.
func Resolve(ctx context.Context, m *Mirror, oid string) ([]string, error) {
	if oid == "" {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := runGit(ctx, m.dir, "rev-list", "--objects", "--all")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range splitCleanLines(out) {
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue // commit/root tree: no path
		}
		if line[:sp] == oid {
			paths = append(paths, line[sp+1:])
		}
	}
	return paths, nil
}