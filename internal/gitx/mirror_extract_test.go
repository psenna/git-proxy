package gitx_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/port"
)

// TestMirrorExtract exercises NewCommits/CommitMessage/ChangedFiles/BlobContent
// against a real git mirror after Refresh + IngestPackfile, covering create
// and update ref updates and dedup across updates.
func TestMirrorExtract(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Source repo with two commits: A adds a.txt, B adds b.txt.
	source := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", source)
	mustGit(t, source, "config", "user.email", "test@example.com")
	mustGit(t, source, "config", "user.name", "Test")
	writeFile(t, source, "a.txt", "alpha\n")
	mustGit(t, source, "add", "a.txt")
	mustGit(t, source, "commit", "-q", "-m", "feat: add a")
	writeFile(t, source, "b.txt", "beta\n")
	mustGit(t, source, "add", "b.txt")
	mustGit(t, source, "commit", "-q", "-m", "fix: add b\n\nBody line here.")
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

	// Build a new commit C on top of B that modifies a.txt and adds c.txt, then
	// ingest its packfile into the mirror (no ref update on the mirror).
	work := t.TempDir()
	mustGit(t, "", "clone", "-q", "file://"+bare, work)
	mustGit(t, work, "config", "user.email", "test@example.com")
	mustGit(t, work, "config", "user.name", "Test")
	writeFile(t, work, "a.txt", "alpha-updated\n")
	writeFile(t, work, "c.txt", "gamma\n")
	mustGit(t, work, "add", "a.txt", "c.txt")
	mustGit(t, work, "commit", "-q", "-m", "feat: update a, add c")
	C := revParseHead(t, work)
	pack := makePackfileReachable(t, work, C)
	if err := m.IngestPackfile(ctx, bytes.NewReader(pack)); err != nil {
		t.Fatalf("IngestPackfile: %v", err)
	}

	// Update ref main: B -> C. NewCommits should return [C] (B already in mirror).
	updates := []port.RefUpdate{{Ref: "refs/heads/main", Old: B, New: C}}
	shas, err := m.NewCommits(ctx, updates)
	if err != nil {
		t.Fatalf("NewCommits: %v", err)
	}
	if len(shas) != 1 || shas[0] != C {
		t.Fatalf("NewCommits = %v, want [%s]", shas, C)
	}

	// CommitMessage for C: full message (subject + body if any).
	msg, err := m.CommitMessage(ctx, C)
	if err != nil {
		t.Fatalf("CommitMessage: %v", err)
	}
	if !strings.HasPrefix(msg, "feat: update a, add c") {
		t.Fatalf("CommitMessage = %q, want subject prefix", msg)
	}
	// CommitMessage for B carries the body.
	msgB, err := m.CommitMessage(ctx, B)
	if err != nil {
		t.Fatalf("CommitMessage B: %v", err)
	}
	if !strings.Contains(msgB, "Body line here.") {
		t.Fatalf("CommitMessage B = %q, want body", msgB)
	}

	// ChangedFiles for B->C: a.txt modified, c.txt added.
	files, err := m.ChangedFiles(ctx, updates)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	wantStatus := map[string]string{"a.txt": "M", "c.txt": "A"}
	gotStatus := map[string]string{}
	for _, f := range files {
		gotStatus[f.Path] = f.Status
		if f.Status != "D" && f.BlobOID == "" {
			t.Errorf("file %q status %q has empty BlobOID", f.Path, f.Status)
		}
	}
	for p, s := range wantStatus {
		if gotStatus[p] != s {
			t.Errorf("ChangedFiles[%q] = %q, want %q (got all: %+v)", p, gotStatus[p], s, gotStatus)
		}
	}

	// BlobContent for c.txt's oid returns "gamma\n".
	var cOID string
	for _, f := range files {
		if f.Path == "c.txt" {
			cOID = f.BlobOID
		}
	}
	if cOID == "" {
		t.Fatal("no oid for c.txt")
	}
	blob, err := m.BlobContent(ctx, cOID)
	if err != nil {
		t.Fatalf("BlobContent: %v", err)
	}
	if string(blob) != "gamma\n" {
		t.Fatalf("BlobContent = %q, want %q", string(blob), "gamma\n")
	}
}

// TestMirrorExtract_CreateRef verifies a ref creation diffs against the empty
// tree and reports all of the new ref's files as added.
func TestMirrorExtract_CreateRef(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	tips := makeSourceRepo(t, source, 2) // A, B
	A, B := tips[0], tips[1]
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

	// Create a new branch from B and ingest its packfile.
	work := t.TempDir()
	mustGit(t, "", "clone", "-q", "file://"+bare, work)
	mustGit(t, work, "config", "user.email", "test@example.com")
	mustGit(t, work, "config", "user.name", "Test")
	mustGit(t, work, "checkout", "-q", "-b", "topic", B)
	writeFile(t, work, "topic.txt", "topic\n")
	mustGit(t, work, "add", "topic.txt")
	mustGit(t, work, "commit", "-q", "-m", "feat: topic")
	T := revParseHead(t, work)
	pack := makePackfileReachable(t, work, T)
	if err := m.IngestPackfile(ctx, bytes.NewReader(pack)); err != nil {
		t.Fatalf("IngestPackfile: %v", err)
	}

	updates := []port.RefUpdate{{Ref: "refs/heads/topic", Old: "", New: T}}
	shas, err := m.NewCommits(ctx, updates)
	if err != nil {
		t.Fatalf("NewCommits: %v", err)
	}
	// New commits reachable from T not in any existing ref: only T (the topic
	// commit). A and B are reachable from main so must be excluded.
	gotSet := map[string]bool{}
	for _, s := range shas {
		gotSet[s] = true
	}
	if !gotSet[T] {
		t.Fatalf("NewCommits missing %s; got %v", T, shas)
	}
	if gotSet[A] || gotSet[B] {
		t.Fatalf("NewCommits included already-known commits: %v", shas)
	}

	files, err := m.ChangedFiles(ctx, updates)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	// Create diff against empty tree lists every file in T's tree as added:
	// a.txt, b.txt (from A,B), topic.txt.
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = f.Status
	}
	for _, p := range []string{"file0.txt", "file1.txt", "topic.txt"} {
		if got[p] != "A" {
			t.Errorf("ChangedFiles[%q] = %q, want A (got all: %+v)", p, got[p], got)
		}
	}
}

// TestMirrorExtract_DeleteOnlyNoChangedFiles verifies a delete-only update
// yields no new commits and no changed files.
func TestMirrorExtract_DeleteOnlyNoChangedFiles(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source := t.TempDir()
	makeSourceRepo(t, source, 1)
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

	tip := revParseHead(t, source)
	updates := []port.RefUpdate{{Ref: "refs/heads/main", Old: tip, New: ""}}
	shas, err := m.NewCommits(ctx, updates)
	if err != nil {
		t.Fatalf("NewCommits: %v", err)
	}
	if len(shas) != 0 {
		t.Fatalf("NewCommits on delete = %v, want empty", shas)
	}
	files, err := m.ChangedFiles(ctx, updates)
	if err != nil {
		t.Fatalf("ChangedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("ChangedFiles on delete = %+v, want empty", files)
	}
}

// makePackfileReachable builds a packfile containing the full object closure
// reachable from tip (commits, trees, blobs) via `git rev-list --objects | git
// pack-objects`. This mirrors what a real client push sends, unlike
// makePackfile which only packs the listed object ids.
func makePackfileReachable(t *testing.T, dir, tip string) []byte {
	t.Helper()
	revList := exec.Command("git", "-C", dir, "rev-list", "--objects", tip)
	var revOut bytes.Buffer
	revList.Stdout = &revOut
	if err := revList.Run(); err != nil {
		t.Fatalf("rev-list --objects: %v", err)
	}
	pack := exec.Command("git", "-C", dir, "pack-objects", "--stdout")
	pack.Stdin = &revOut
	var out bytes.Buffer
	pack.Stdout = &out
	if err := pack.Run(); err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	if out.Len() == 0 {
		t.Fatalf("pack-objects produced no bytes for tip %s", tip)
	}
	return out.Bytes()
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}