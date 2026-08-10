package gitx_test

import (
	"fmt"
	"testing"

	"github.com/psenna/git-proxy/internal/gitx"
)

func TestIsCorruptionError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		// Corruption patterns — should match.
		{fmt.Errorf("git rev-list: exit status 128: fatal: bad object abc123"), true},
		{fmt.Errorf("gitx: wanted objects: git rev-list: exit status 128: fatal: bad object deadbeef"), true},
		{fmt.Errorf("fatal: missing object 1234"), true},
		{fmt.Errorf("error: corrupt loose object abc"), true},
		{fmt.Errorf("error: loose object abc (in .git/objects/...) is corrupt"), true},
		{fmt.Errorf("fatal: unable to unpack abc123 header"), true},
		// Type-specific "bad <type> object" variants — git uses these when a
		// non-commit object (tree, blob, tag) is missing from the object store.
		// The generic "bad object" pattern does NOT match these (e.g. "bad tree
		// object" does not contain the substring "bad object"), so they MUST be
		// listed explicitly. Without them, the self-healing wrapper never
		// triggers on a missing tree/blob and the fetch fails with HTTP 502
		// (issues #69/#71 regression).
		{fmt.Errorf("git rev-list: exit status 128: fatal: bad tree object 6015b9f19393e2b6"), true},
		{fmt.Errorf("gitx: wanted objects: git rev-list: exit status 128: fatal: bad tree object deadbeef"), true},
		{fmt.Errorf("fatal: bad blob object cafef00d"), true},
		{fmt.Errorf("fatal: bad commit object 1234abcd"), true},
		{fmt.Errorf("fatal: bad tag object 5678ef90"), true},
		// The full wrapped error from the enforce path (matches the production
		// log from issue #69 with a tree instead of a commit).
		{fmt.Errorf("gitproto: upload-pack enforce: wanted objects: gitx: wanted objects: git rev-list: exit status 128: fatal: bad tree object 6015b9f19393e2b6"), true},
		// Wrapped errors — still match.
		{fmt.Errorf("enforce: %w", fmt.Errorf("bad object 1234")), true},
		// Nil — not corruption.
		{nil, false},
		// Non-corruption errors — should NOT match.
		{fmt.Errorf("exit status 1"), false},
		{fmt.Errorf("connection refused"), false},
		{fmt.Errorf("permission denied"), false},
		{fmt.Errorf("timeout"), false},
		{fmt.Errorf("git fetch: exit status 128: fatal: could not read Username"), false},
	}
	for _, tt := range tests {
		got := gitx.IsCorruptionError(tt.err)
		if got != tt.want {
			t.Errorf("IsCorruptionError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
