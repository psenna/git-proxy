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

// These tests pin the robustness fix for the bug where a git client fetch
// through git-proxy fails with HTTP 502 when its advertised haves include a
// commit UNKNOWN to the inspection mirror (e.g. a stale local branch that
// references a commit no longer reachable in the current upstream).
//
// Root cause: Mirror.WantedObjects builds
//
//	git rev-list --objects <wants...> --not <haves...>
//
// and `git rev-list --not <missing-object>` FAILS with
//
//	fatal: bad object <sha>
//
// when a have is absent from the mirror's object store. The error is returned
// verbatim and the upload-pack enforce path wraps it into a 502. A real
// `git upload-pack` instead treats an unknown have as "not common ground" and
// simply continues the negotiation (sending more objects). So the proxy turned a
// harmless unknown-have into a hard 502 — distinct from the mirror-corruption
// case (issues #69/#71) where the mirror itself is missing an object it SHOULD
// have: here the MIRROR is fine and the CLIENT is advertising an object the
// server legitimately does not have.
//
// Fix: Mirror.WantedObjects/ShallowObjects now filter haves to those PRESENT in
// the mirror (via `git cat-file --batch-check`) before building `--not`, so an
// unknown have is dropped (treated as non-common ground) and the rev-list
// succeeds. The probe is fail-closed on error; missing WANTs still self-heal
// (corruption).

// makeUnrelatedCommit builds a real commit object in a throwaway repo and
// returns its OID. The commit is genuine (valid git object) but is NOT present
// in the mirror's object store — modeling the production scenario where the
// client has a stale local branch (e.g. "v2mainsim") referencing a commit the
// upstream/mirror no longer has.
func makeUnrelatedCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", dir)
	mustGit(t, dir, "config", "user.email", "test@example.com")
	mustGit(t, dir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("unrelated\n"), 0o644); err != nil {
		t.Fatalf("write unrelated.txt: %v", err)
	}
	mustGit(t, dir, "add", "unrelated.txt")
	mustGit(t, dir, "commit", "-q", "-m", "unrelated commit (unknown to mirror)")
	return revParseHead(t, dir)
}

// fakeOID is a valid-format 40-hex SHA that does not correspond to any object
// anywhere. `git rev-list --not <fakeOID>` fails with the same "bad object"
// error as a real-but-absent commit, so it exercises the same code path with
// no need to build a second repo.
const fakeOID = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// TestWantedObjects_UnknownHaveIsNotCorruption asserts the FIXED behavior: an
// unknown have (absent from the mirror) must NOT make WantedObjects error, and
// the result must NOT be classified as a corruption error (so the self-heal
// wrapper does NOT trigger a wasted Repair+re-clone that cannot help). It covers
// both a real commit OID from an unrelated repo and a fabricated 40-hex OID.
func TestWantedObjects_UnknownHaveIsNotCorruption(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Small source repo with one commit, mirrored.
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")
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

	// Sanity: a known have (the tip itself) does NOT error.
	if _, err := m.WantedObjects(ctx, []string{tip}, []string{tip}); err != nil {
		t.Fatalf("WantedObjects with known have errored (unexpected): %v", err)
	}

	unknownCommit := makeUnrelatedCommit(t)
	t.Logf("unrelated commit (not in mirror): %s", unknownCommit)

	for _, tc := range []struct {
		name string
		have string
	}{
		{"real-but-unknown commit", unknownCommit},
		{"fabricated 40-hex OID", fakeOID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := m.WantedObjects(ctx, []string{tip}, []string{tc.have})
			if err != nil {
				t.Fatalf("WantedObjects with unknown have %q returned error %v; want nil (unknown haves must be tolerated as non-common ground, like a real git server)", tc.have, err)
			}
			if gitx.IsCorruptionError(err) {
				t.Errorf("WantedObjects with unknown have %q returned a corruption-classified error %v; the self-heal wrapper would Repair+retry (a wasted re-clone) and still 502", tc.have, err)
			}
			if len(objs) == 0 {
				t.Errorf("WantedObjects with unknown have %q returned no objects; want the full reachable set from tip", tc.have)
			}
		})
	}
}

// TestWantedObjects_UnknownHaveShouldBeTolerated asserts the DESIRED behavior:
// an unknown have must be treated as non-common ground and the rev-list must
// succeed, returning the SAME object set as the equivalent fetch WITHOUT the
// unknown have (the proxy just sends more objects, exactly like a real git
// server). Table covers: all-unknown haves (== no-haves baseline), mixed
// known+unknown (== known-only), empty haves (nil and []), and duplicate haves
// (== known-only).
func TestWantedObjects_UnknownHaveShouldBeTolerated(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Source repo: A -> B (two commits, two distinct blobs).
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")
	writeFile(t, source, "b.txt", "beta\n")
	mustGit(t, source, "add", "b.txt")
	mustGit(t, source, "commit", "-q", "-m", "add b")
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

	// Baseline: object set with NO haves (the full reachable set from tip).
	baseline, err := m.WantedObjects(ctx, []string{tip}, nil)
	if err != nil {
		t.Fatalf("WantedObjects baseline (no haves): %v", err)
	}
	baselineSet := oidSet2(baseline)

	// Reference: object set with the KNOWN have (the tip itself) — the result a
	// mixed/duplicate have list must equal.
	known, err := m.WantedObjects(ctx, []string{tip}, []string{tip})
	if err != nil {
		t.Fatalf("WantedObjects known-have reference: %v", err)
	}
	knownSet := oidSet2(known)

	unknownCommit := makeUnrelatedCommit(t)
	t.Logf("unrelated commit (not in mirror): %s", unknownCommit)

	for _, tc := range []struct {
		name  string
		haves []string
		want  map[string]bool
	}{
		{"real-but-unknown commit == no-haves baseline", []string{unknownCommit}, baselineSet},
		{"fabricated 40-hex OID == no-haves baseline", []string{fakeOID}, baselineSet},
		{"mixed known+unknown == known-only", []string{tip, unknownCommit}, knownSet},
		{"empty haves (nil) == no-haves baseline", nil, baselineSet},
		{"empty haves ([]) == no-haves baseline", []string{}, baselineSet},
		{"duplicate haves == known-only", []string{tip, tip}, knownSet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := m.WantedObjects(ctx, []string{tip}, tc.haves)
			if err != nil {
				t.Fatalf("WantedObjects with haves %v returned error %v; want nil (unknown haves must be tolerated as non-common ground, like a real git server)", tc.haves, err)
			}
			got := oidSet2(objs)
			if !oidSetEqual3(got, tc.want) {
				t.Errorf("WantedObjects with haves %v returned a different object set than the reference:\n got = %v\n want = %v\n(an unknown have should suppress nothing, so the result equals the reference set)", tc.haves, sortedKeys2(got), sortedKeys2(tc.want))
			}
		})
	}
}

// oidSet2 collects ObjectPath OIDs into a set.
func oidSet2(objs []gitx.ObjectPath) map[string]bool {
	set := make(map[string]bool, len(objs))
	for _, op := range objs {
		set[op.OID] = true
	}
	return set
}

// oidSetEqual3 reports set equality over string->bool maps.
func oidSetEqual3(a, b map[string]bool) bool {
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

// sortedKeys2 returns the sorted keys of a string->bool map (for readable diffs).
func sortedKeys2(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// stable sort without importing sort at the top level (small sets in tests)
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// TestRealGit_RevListNotMissingFails demonstrates the underlying git mechanics:
// `git rev-list --objects <want> --not <missing-sha>` FAILS with
// `fatal: bad object <sha>`, while a real `git upload-pack` over the file://
// transport with a client advertising a bogus have does NOT fail (it treats the
// unknown have as non-common and proceeds). This is the git-level evidence that
// the proxy's hard error is a mismatch with real server behavior, not a
// git-imposed limitation.
func TestRealGit_RevListNotMissingFails(t *testing.T) {
	gitBinary(t)

	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")
	tip := revParseHead(t, source)

	// rev-list with a missing --not OID must fail with "bad object".
	cmd := exec.Command("git", "-C", source, "rev-list", "--objects", tip, "--not", fakeOID)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git rev-list --not <missing> unexpectedly succeeded; want 'bad object' error:\n%s", out)
	}
	if !strings.Contains(string(out), "bad object") {
		t.Fatalf("git rev-list --not <missing> output missing 'bad object':\n%s", out)
	}
	t.Logf("git rev-list --not <missing> correctly failed: %s", strings.TrimSpace(string(out)))

	// Contrast: rev-list with a present --not (the tip itself) succeeds and
	// yields an empty set (tip excludes itself). This confirms the --not flag is
	// the trigger, not the rev-list itself.
	cmd = exec.Command("git", "-C", source, "rev-list", "--objects", tip, "--not", tip)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-list --not <present> errored (unexpected): %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Logf("git rev-list --not <present> output non-empty (expected empty since tip excludes itself): %q", strings.TrimSpace(string(out)))
	}
}

// corruptMirrorPacks deletes all pack files in the mirror's object store,
// simulating corruption (the mirror's objects become unreadable). git clone
// --mirror packs everything into a single pack, so removing the pack makes
// rev-list fail with a corruption error ("bad object").
func corruptMirrorPacks(t *testing.T, m *gitx.Mirror) {
	t.Helper()
	packDir := filepath.Join(m.Dir(), "objects", "pack")
	for _, pat := range []string{"*.pack", "*.idx", "*.rev"} {
		files, gerr := filepath.Glob(filepath.Join(packDir, pat))
		if gerr != nil {
			t.Fatalf("glob %s: %v", pat, gerr)
		}
		for _, f := range files {
			t.Logf("removing %s to simulate corruption", filepath.Base(f))
			if rerr := os.Remove(f); rerr != nil {
				t.Fatalf("remove %s: %v", f, rerr)
			}
		}
	}
}

// TestWantedObjects_MissingWantStillSelfHeals is the regression guard for
// issues #69/#71: when the MIRROR itself is missing an object it should have
// (corruption), WantedObjects must STILL fail with a corruption-classified error
// so the self-heal wrapper repairs the mirror. The unknown-have tolerance must
// NOT swallow genuine mirror corruption.
func TestWantedObjects_MissingWantStillSelfHeals(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")
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

	// Sanity: works before corruption.
	if _, err := m.WantedObjects(ctx, []string{tip}, nil); err != nil {
		t.Fatalf("WantedObjects before corruption: %v", err)
	}

	corruptMirrorPacks(t, m)

	_, err = m.WantedObjects(ctx, []string{tip}, nil)
	if err == nil {
		t.Fatal("WantedObjects after corruption unexpectedly succeeded; want 'bad object' corruption error")
	}
	if !strings.Contains(err.Error(), "bad object") {
		t.Errorf("WantedObjects after corruption error %q missing 'bad object' signature", err.Error())
	}
	if !gitx.IsCorruptionError(err) {
		t.Fatalf("WantedObjects after corruption returned non-corruption error %v; the self-heal wrapper would NOT repair it", err)
	}
}

// TestShallowObjects_UnknownHaveTolerated asserts the shallow path tolerates
// unknown haves exactly like WantedObjects: an unknown have is non-common ground
// and the object set equals the equivalent fetch without it. It also proves the
// server-computed `excludes` (the shallow cut) is NOT filtered — a present
// exclude still excludes its objects.
func TestShallowObjects_UnknownHaveTolerated(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Source repo: A -> B (two commits, two distinct blobs).
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")
	A := revParseHead(t, source)
	writeFile(t, source, "b.txt", "beta\n")
	mustGit(t, source, "add", "b.txt")
	mustGit(t, source, "commit", "-q", "-m", "add b")
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

	// Baseline: shallow cut at A, no haves.
	baseline, err := m.ShallowObjects(ctx, []string{B}, []string{A}, nil)
	if err != nil {
		t.Fatalf("ShallowObjects baseline: %v", err)
	}
	baselineSet := oidSet2(baseline)

	// The excludes must genuinely exclude A's objects (proves excludes are NOT
	// filtered): the a.txt blob reachable only from A must be absent from the
	// shallow set.
	aObjs, err := m.WantedObjects(ctx, []string{A}, nil)
	if err != nil {
		t.Fatalf("WantedObjects(A) for a.txt blob lookup: %v", err)
	}
	var aBlob string
	for _, op := range aObjs {
		if op.Path == "a.txt" {
			aBlob = op.OID
		}
	}
	if aBlob == "" {
		t.Fatalf("could not locate a.txt blob in %+v", aObjs)
	}
	if baselineSet[aBlob] {
		t.Errorf("ShallowObjects(B not A) includes a.txt blob %s; the shallow cut must exclude A's objects", aBlob)
	}

	// Reference: known have (B itself) — the result a mixed/duplicate have list
	// must equal.
	known, err := m.ShallowObjects(ctx, []string{B}, []string{A}, []string{B})
	if err != nil {
		t.Fatalf("ShallowObjects known-have reference: %v", err)
	}
	knownSet := oidSet2(known)

	unknownCommit := makeUnrelatedCommit(t)
	t.Logf("unrelated commit (not in mirror): %s", unknownCommit)

	for _, tc := range []struct {
		name  string
		haves []string
		want  map[string]bool
	}{
		{"real-but-unknown commit == no-haves baseline", []string{unknownCommit}, baselineSet},
		{"fabricated 40-hex OID == no-haves baseline", []string{fakeOID}, baselineSet},
		{"mixed known+unknown == known-only", []string{B, unknownCommit}, knownSet},
		{"empty haves (nil) == no-haves baseline", nil, baselineSet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := m.ShallowObjects(ctx, []string{B}, []string{A}, tc.haves)
			if err != nil {
				t.Fatalf("ShallowObjects with haves %v returned error %v; want nil (unknown haves must be tolerated as non-common ground)", tc.haves, err)
			}
			got := oidSet2(objs)
			if !oidSetEqual3(got, tc.want) {
				t.Errorf("ShallowObjects with haves %v returned a different object set than the reference:\n got = %v\n want = %v", tc.haves, sortedKeys2(got), sortedKeys2(tc.want))
			}
		})
	}
}

// TestShallowObjects_MissingWantStillSelfHeals is the shallow-path regression
// guard for issues #69/#71: genuine mirror corruption (a missing WANT) must STILL
// fail with a corruption-classified error so the self-heal wrapper repairs the
// mirror. The unknown-have tolerance must NOT swallow it.
func TestShallowObjects_MissingWantStillSelfHeals(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "add a")
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

	// Sanity: works before corruption.
	if _, err := m.ShallowObjects(ctx, []string{tip}, nil, nil); err != nil {
		t.Fatalf("ShallowObjects before corruption: %v", err)
	}

	corruptMirrorPacks(t, m)

	_, err = m.ShallowObjects(ctx, []string{tip}, nil, nil)
	if err == nil {
		t.Fatal("ShallowObjects after corruption unexpectedly succeeded; want 'bad object' corruption error")
	}
	if !strings.Contains(err.Error(), "bad object") {
		t.Errorf("ShallowObjects after corruption error %q missing 'bad object' signature", err.Error())
	}
	if !gitx.IsCorruptionError(err) {
		t.Fatalf("ShallowObjects after corruption returned non-corruption error %v; the self-heal wrapper would NOT repair it", err)
	}
}
