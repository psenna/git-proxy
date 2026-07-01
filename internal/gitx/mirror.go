package gitx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/psenna/git-proxy/internal/port"
)

// Mirror is a read-only bare clone of a single upstream repository, used only
// for object inspection (ancestry walks). The proxy never serves from it, it
// is never a push target, and the agent never sees it. A Mirror is safe for
// concurrent use after Open: a per-mirror mutex serializes the git invocations
// (Refresh, IngestPackfile, IsAncestor) so concurrent pushes to the same repo
// do not race on the shared bare dir (ref locks / index-pack).
type Mirror struct {
	dir         string // bare repo path
	upstreamURL string // full upstream URL for the repo (creds embedded if any)
	mu          sync.Mutex
}

// repoSlug derives a filesystem-safe, collision-resistant directory name from a
// repo path: path separators are replaced with "-" and a short hash of the repo
// path is appended so that "a/b" and "a-b" (which would collide under a plain
// replace) map to distinct directories. The slug is deterministic and stable
// across restarts (same repo -> same dir).
func repoSlug(repo string) string {
	if repo == "" {
		return "default"
	}
	sum := sha256.Sum256([]byte(repo))
	return strings.ReplaceAll(repo, "/", "-") + "-" + hex.EncodeToString(sum[:])[:8]
}

// upstreamRepoURL builds the full URL to the upstream repo. When creds supplies
// credentials for repo, they are embedded as HTTP Basic auth in the URL so the
// fetch leg authenticates without a git credential helper. The agent never sees
// this URL: it lives only inside the mirror's remote config.
//
// DEV NOTE (flagged for reviewer): inline-URL cred embedding is the simplest
// testable option and works for HTTP Basic auth upstreams. It does not cover
// SSH or token-in-header upstreams (those will need a per-mirror credential
// helper or http.extraHeader, to be added with the SSH frontend / richer
// upstreams). creds==nil means no credentials are attached (passthrough/test
// upstreams).
func upstreamRepoURL(upstreamURL, repo string, creds port.CredentialStore) string {
	base := strings.TrimRight(upstreamURL, "/")
	raw := base + "/" + repo
	if creds == nil {
		return raw
	}
	c, ok := creds.CredentialsFor(repo)
	if !ok {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = url.UserPassword(c.Username, c.Password)
	return u.String()
}

// Open opens a bare mirror of upstreamURL/repo at root/<repo-slug>, cloning it
// from the upstream if the directory does not already exist. creds, if non-nil,
// supplies upstream auth for the clone/fetch leg (agent never sees it). An
// existing mirror directory is reused (Open is idempotent); call Refresh to
// sync it to the current upstream state.
func Open(ctx context.Context, upstreamURL, repo, root string, creds port.CredentialStore) (*Mirror, error) {
	slug := repoSlug(repo)
	dir := filepath.Join(root, slug)
	repoURL := upstreamRepoURL(upstreamURL, repo, creds)

	// Detect an existing bare repo by checking for the HEAD file. If absent,
	// clone a fresh mirror. `git clone --mirror` sets up a refspec of
	// +refs/*:refs/* so Refresh fetches every ref.
	if !mirrorExists(ctx, dir) {
		if err := cloneMirror(ctx, dir, repoURL); err != nil {
			return nil, fmt.Errorf("gitx: open mirror for %q: %w", repo, err)
		}
	}
	// Disable background auto-gc on the mirror: Refresh (fetch) and
	// IngestPackfile (index-pack) can schedule `git gc --auto` asynchronously,
	// which races callers that tear the mirror down promptly (e.g. tests) and
	// is wasted work on a short-lived inspection-only clone. Idempotent.
	if _, err := runGit(ctx, dir, "config", "gc.auto", "0"); err != nil {
		return nil, fmt.Errorf("gitx: mirror gc.auto: %w", err)
	}
	return &Mirror{dir: dir, upstreamURL: repoURL}, nil
}

// mirrorExists reports whether dir looks like an existing git bare repo. The
// git invocation is ctx-aware so a cancelled context aborts the rev-parse.
func mirrorExists(ctx context.Context, dir string) bool {
	if dir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		return false
	}
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	// Confirm it is a git dir (git rev-parse succeeds).
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--git-dir").CombinedOutput()
	if err != nil {
		_ = out
		return false
	}
	return true
}

// cloneMirror runs `git clone --mirror <url> <dir>` with ctx.
func cloneMirror(ctx context.Context, dir, repoURL string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--mirror", "--quiet", repoURL, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("clone --mirror: %w: %s", err, redactCreds(strings.TrimSpace(string(out))))
	}
	return nil
}

// Refresh fetches all refs from the upstream so the mirror has the current
// "old" values the enforcement path compares pushed commits against. The
// per-mirror mutex is held for the duration of the fetch so concurrent pushes
// to the same repo serialize and do not race on the bare dir's ref locks.
func (m *Mirror) Refresh(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := runGit(ctx, m.dir, "fetch", "--quiet", "origin"); err != nil {
		return fmt.Errorf("gitx: refresh mirror: %w", err)
	}
	return nil
}

// IngestPackfile writes a pushed packfile's objects into the mirror's object
// store via `git index-pack --stdin` WITHOUT updating any ref. After this, both
// the old (from Refresh) and the new (from the pack) objects are present for
// ancestry walks. The packfile is read to EOF from r. The per-mirror mutex is
// held so index-pack does not race a concurrent Refresh or another IngestPackfile
// on the same bare dir.
func (m *Mirror) IngestPackfile(ctx context.Context, r io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmd := exec.CommandContext(ctx, "git", "-C", m.dir, "index-pack", "--stdin")
	cmd.Stdin = r
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gitx: index-pack --stdin: %w: %s", err, redactCreds(strings.TrimSpace(string(out))))
	}
	return nil
}

// IsAncestor reports whether old is an ancestor of new via
// `git merge-base --is-ancestor old new`. old=="" (ref creation) and new==""
// (ref deletion) are NOT force-pushes: return (false, nil) for those. An
// ancestry error (e.g. a missing object) is returned as an error so the caller
// can fail closed. The per-mirror mutex is held so this read-only walk does not
// race a concurrent Refresh/IngestPackfile on the same bare dir.
func (m *Mirror) IsAncestor(ctx context.Context, old, new string) (bool, error) {
	if old == "" || new == "" {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cmd := exec.CommandContext(ctx, "git", "-C", m.dir, "merge-base", "--is-ancestor", old, new)
	if err := cmd.Run(); err != nil {
		// merge-base --is-ancestor exits 1 when old is NOT an ancestor of new,
		// and non-zero otherwise. Distinguish the "not ancestor" exit from a
		// real error via ExitError.ExitCode().
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("gitx: merge-base --is-ancestor %s %s: %w", old, new, err)
	}
	return true, nil
}

// ObjectPath is a single object in the wanted set: the object id and, for
// blobs and non-root trees, the path `git rev-list --objects` reports it at.
// Path is "" for commits and the root tree of a commit (which rev-list emits
// without a path). Used by the read-protection path to enumerate the objects the
// proxy must pack and to withhold blobs whose path matches the read deny
// matcher.
type ObjectPath struct {
	OID  string
	Path string
}

// WantedObjects returns the objects reachable from wants excluding haves, with
// paths for blobs/trees as `git rev-list --objects <wants> --not <haves>` prints
// them: each output line is `<oid>` (commits and the root tree, no path) or
// `<oid> <path>` (blobs and non-root trees, with the path they are reachable at).
// The per-mirror mutex is held so the rev-list does not race a concurrent
// Refresh/IngestPackfile. A nil/empty wants list yields an empty result.
func (m *Mirror) WantedObjects(ctx context.Context, wants, haves []string) ([]ObjectPath, error) {
	if len(wants) == 0 {
		return nil, nil
	}
	args := make([]string, 0, 2+len(wants)+len(haves)+1)
	args = append(args, "rev-list", "--objects")
	args = append(args, wants...)
	if len(haves) > 0 {
		args = append(args, "--not")
		args = append(args, haves...)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := runGit(ctx, m.dir, args...)
	if err != nil {
		return nil, fmt.Errorf("gitx: wanted objects: %w", err)
	}
	return parseObjectPaths(out), nil
}

// parseObjectPaths parses `git rev-list --objects` output into ObjectPath values.
// Each line is `<oid>` or `<oid> <path>`; trailing newlines are stripped from the
// path. Empty lines are ignored.
func parseObjectPaths(out []byte) []ObjectPath {
	lines := splitCleanLines(out)
	objs := make([]ObjectPath, 0, len(lines))
	for _, line := range lines {
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			objs = append(objs, ObjectPath{OID: line})
			continue
		}
		objs = append(objs, ObjectPath{OID: line[:sp], Path: line[sp+1:]})
	}
	return objs
}

// ReadEnforceThin is the thin flag the read-enforce path MUST pass to
// PackObjects/PackObjectsStream. A thin pack re-includes withheld blobs as
// delta bases (`git pack-objects --thin` without a receiver have-set walks the
// listed objects' references and INCLUDES the referenced-but-unlisted blobs),
// which would break the read-protection guarantee. This exported constant
// hardens against a future maintainer accidentally re-enabling thin on the
// read-enforce path: the call site reads `gitx.ReadEnforceThin` instead of a
// bare `false`, making the constraint self-documenting at the point of use.
const ReadEnforceThin = false

// PackObjects builds a packfile containing exactly the given object ids (no
// reachability walk) via `git pack-objects --stdout [--thin]` reading the OID
// list from stdin. With thin=true it produces a thin pack (deltas may reference
// bases the receiver already has); with thin=false the pack is self-contained.
// The per-mirror mutex is held so pack-objects does not race a concurrent
// Refresh/IngestPackfile on the shared bare dir.
//
// This is the read-protection packfile-assembly primitive: the caller feeds the
// ALLOWED OID list (denied blobs omitted), so the resulting packfile genuinely
// excludes the withheld objects even when trees reference them.
//
// thin MUST stay false on the read-enforce path: a thin pack re-includes
// withheld blobs as delta bases, breaking read protection (see
// ReadEnforceThin). The thin=true path is exercised by tests for pack-validity
// only; do NOT route the enforce path through it.
//
// NOTE: PackObjects materializes the ENTIRE packfile in memory and is retained
// for tests / small-pack callers. The read-enforce SERVING path uses
// PackObjectsStream instead, which streams pack-objects output through a pipe
// so memory is bounded by the chunk size regardless of packfile size (no
// unbounded in-memory accumulation).
func (m *Mirror) PackObjects(ctx context.Context, oids []string, thin bool) ([]byte, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	args := []string{"pack-objects", "--stdout"}
	if thin {
		args = append(args, "--thin")
	}
	cmd := exec.CommandContext(ctx, "git", fullArgs(m.dir, args...)...)
	var stdin strings.Builder
	for _, oid := range oids {
		stdin.WriteString(oid)
		stdin.WriteByte('\n')
	}
	cmd.Stdin = strings.NewReader(stdin.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitx: pack-objects: %w: %s", err, redactCreds(strings.TrimSpace(stderr.String())))
	}
	return stdout.Bytes(), nil
}

// PackObjectsStream runs `git pack-objects --stdout [--thin]` reading the OID
// list from stdin and returns a reader over the packfile plus a wait function.
// The wait function MUST be called after the reader is fully drained (or
// closed/abandoned) and returns the pack-objects exit error (nil on success);
// it closes the reader end if needed so a partially-drained stream cannot
// deadlock the per-mirror goroutine.
//
// Memory is bounded by the pipe buffer and the consumer's read buffer: the full
// packfile is NEVER materialized in memory regardless of its size. This is the
// serving path used by the read-enforce flow so a large read-protected repo
// cannot OOM the proxy while assembling the pack (the push path caps request
// size via maxPackfileBytes/LimitReader; the read path caps served size by
// streaming instead of buffering).
//
// The per-mirror mutex is held until the command completes; the caller MUST
// drain or abandon the reader (via the wait function) so the goroutine can
// finish and release the mutex.
//
// thin MUST stay false on the read-enforce path: a thin pack re-includes
// withheld blobs as delta bases, breaking read protection (see ReadEnforceThin).
func (m *Mirror) PackObjectsStream(ctx context.Context, oids []string, thin bool) (io.Reader, func() error, error) {
	if len(oids) == 0 {
		return bytes.NewReader(nil), func() error { return nil }, nil
	}
	m.mu.Lock()
	args := []string{"pack-objects", "--stdout"}
	if thin {
		args = append(args, "--thin")
	}
	cmd := exec.CommandContext(ctx, "git", fullArgs(m.dir, args...)...)
	var stdin strings.Builder
	for _, oid := range oids {
		stdin.WriteString(oid)
		stdin.WriteByte('\n')
	}
	cmd.Stdin = strings.NewReader(stdin.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	var cmdErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer m.mu.Unlock()
		cmdErr = cmd.Run()
		if cmdErr != nil {
			cmdErr = fmt.Errorf("gitx: pack-objects: %w: %s", cmdErr, redactCreds(strings.TrimSpace(stderr.String())))
		}
		// Closing the writer signals EOF to the reader once the process has
		// exited and all stdout has been copied through the pipe.
		_ = pw.Close()
	}()

	wait := func() error {
		// Close the reader to unblock the writer goroutine if the stream was
		// not fully drained (e.g. pack-objects failed or the consumer stopped
		// reading). Idempotent: a second close on an already-closed pipe reader
		// is a no-op error that we discard.
		_ = pr.Close()
		<-done
		return cmdErr
	}
	return pr, wait, nil
}

// fullArgs prepends `-C dir` to a git argv, mirroring runGit's behavior for the
// pack-objects path that needs direct stdin/stdout control.
func fullArgs(dir string, args ...string) []string {
	full := make([]string, 0, len(args)+2)
	full = append(full, "-C", dir)
	full = append(full, args...)
	return full
}

// ObjectTypes returns the git object type ("commit", "tree", "blob", "tag") for
// each oid via `git cat-file --batch-check --stdin`. A missing object reports
// "missing". Used by the read-protection path to identify blobs (so only blobs
// are withheld; subtrees with a non-empty path are kept, preserving the tree
// structure the agent navigates). The per-mirror mutex is held for
// serialization. A nil/empty oid list yields nil with no error.
func (m *Mirror) ObjectTypes(ctx context.Context, oids []string) (map[string]string, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cmd := exec.CommandContext(ctx, "git", fullArgs(m.dir, "cat-file", "--batch-check")...)
	var stdin strings.Builder
	for _, oid := range oids {
		stdin.WriteString(oid)
		stdin.WriteByte('\n')
	}
	cmd.Stdin = strings.NewReader(stdin.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitx: object types: %w: %s", err, redactCreds(strings.TrimSpace(stderr.String())))
	}
	types := make(map[string]string, len(oids))
	for _, line := range splitCleanLines(stdout.Bytes()) {
		f := strings.Fields(line)
		if len(f) >= 2 {
			types[f[0]] = f[1]
		}
	}
	return types, nil
}

// Dir returns the mirror's bare repo path (for tests/inspection only).
func (m *Mirror) Dir() string { return m.dir }

// emptyTreeOID is git's well-known empty-tree object id, used as the diff base
// for a ref creation (Old == "").
const emptyTreeOID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// NewCommits returns the SHAs of commits introduced by the push across the
// given ref updates (old..new per update; create → all commits reachable from
// new that are new to the mirror). Delete updates (New == "") contribute no
// commits. Deduped (by construction via a single rev-list call) and in
// rev-list order (newest first). The per-mirror mutex is held so the rev-list
// does not race a concurrent Refresh/IngestPackfile.
func (m *Mirror) NewCommits(ctx context.Context, updates []port.RefUpdate) ([]string, error) {
	pos := make([]string, 0, len(updates))
	for _, u := range updates {
		if u.New != "" {
			pos = append(pos, u.New)
		}
	}
	if len(pos) == 0 {
		return nil, nil
	}
	args := append([]string{"rev-list"}, pos...)
	args = append(args, "--not", "--all")
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := runGit(ctx, m.dir, args...)
	if err != nil {
		return nil, fmt.Errorf("gitx: new commits: %w", err)
	}
	return splitCleanLines(out), nil
}

// CommitMessage returns the full commit message (subject + body) for sha via
// `git show -s --format=%B`. The per-mirror mutex is held for serialization.
func (m *Mirror) CommitMessage(ctx context.Context, sha string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := runGit(ctx, m.dir, "show", "-s", "--format=%B", sha)
	if err != nil {
		return "", fmt.Errorf("gitx: commit message %s: %w", sha, err)
	}
	// %B emits the raw message followed by a trailing newline; trim it so the
	// subject is the first line and the body follows naturally.
	return strings.TrimRight(string(out), "\n"), nil
}

// NewCommitMessages returns the SHAs and full commit messages of the commits
// introduced by the push across the given ref updates, in a SINGLE git
// invocation under ONE lock acquisition. It replaces the per-commit
// CommitMessage loop (one git call + one lock per commit) used by the
// enforcement population path so a push introducing many commits does not
// churn the per-mirror mutex. Delete updates (New == "") contribute no
// commits. The result is in rev-list order (newest first), matching
// NewCommits. The per-mirror mutex is held for the duration of the call.
//
// The format is `%H%x00%B%x00`: each commit emits `<SHA>\0<body>\0` and git
// appends a newline after the entry, so the full output is
// `SHA1\0body1\0\nSHA2\0body2\0\n`. Commit messages cannot contain NUL (git
// rejects it), so NUL is a safe field/record separator. Bodies carry %B's
// trailing newline; the message is trimmed of trailing newlines to match
// CommitMessage.
func (m *Mirror) NewCommitMessages(ctx context.Context, updates []port.RefUpdate) ([]port.Commit, error) {
	pos := make([]string, 0, len(updates))
	for _, u := range updates {
		if u.New != "" {
			pos = append(pos, u.New)
		}
	}
	if len(pos) == 0 {
		return nil, nil
	}
	args := append([]string{"log", "--format=%H%x00%B%x00"}, pos...)
	args = append(args, "--not", "--all")
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := runGit(ctx, m.dir, args...)
	if err != nil {
		return nil, fmt.Errorf("gitx: new commit messages: %w", err)
	}
	return parseCommitMessages(out), nil
}

// parseCommitMessages parses the output of `git log --format=%H%x00%B%x00`.
// Each commit record is `<SHA>\0<body>\0` with git appending a newline after
// each entry, so splitting on NUL yields parts = [SHA1, body1, "\nSHA2", body2,
// ..., "\n"]. SHAs after the first carry a leading "\n" (git's appended
// newline); the trailing "\n" after the last body is the final lone part.
func parseCommitMessages(out []byte) []port.Commit {
	if len(out) == 0 {
		return nil
	}
	parts := strings.Split(string(out), "\x00")
	var commits []port.Commit
	for i := 0; i+1 < len(parts); i += 2 {
		sha := strings.TrimPrefix(parts[i], "\n")
		commits = append(commits, port.Commit{
			SHA:     sha,
			Message: strings.TrimRight(parts[i+1], "\n"),
		})
	}
	return commits
}

// ChangedFiles returns the files added/modified/deleted across the push, per
// update `git diff --raw --no-renames old new` (create → diff against the empty
// tree). Delete updates (New == "") contribute no files. Deduped by
// (path, status, oid). The per-mirror mutex is held for serialization.
func (m *Mirror) ChangedFiles(ctx context.Context, updates []port.RefUpdate) ([]port.ChangedFile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]struct{})
	var files []port.ChangedFile
	for _, u := range updates {
		if u.New == "" {
			// Delete-only update: no changed files (a delete-only push yields an
			// empty ChangedFiles set; history_protect handles ref deletion).
			continue
		}
		old := u.Old
		if old == "" {
			old = emptyTreeOID
		}
		out, err := runGit(ctx, m.dir, "diff", "--raw", "--no-renames", old, u.New)
		if err != nil {
			return nil, fmt.Errorf("gitx: changed files %s..%s: %w", old, u.New, err)
		}
		for _, cf := range parseRawDiff(out) {
			key := cf.Path + "\x00" + cf.Status + "\x00" + cf.BlobOID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			files = append(files, cf)
		}
	}
	return files, nil
}

// BlobContent returns the bytes of blob oid via `git cat-file blob`. The
// per-mirror mutex is held for serialization.
func (m *Mirror) BlobContent(ctx context.Context, oid string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := runGit(ctx, m.dir, "cat-file", "blob", oid)
	if err != nil {
		return nil, fmt.Errorf("gitx: blob content %s: %w", oid, err)
	}
	return out, nil
}

// parseRawDiff parses `git diff --raw --no-renames` output lines into
// ChangedFile values. Each line has the form:
//
//	:<srcmode> <dstmode> <srcsha> <dstsha> <status>\t<path>
//
// with the all-zero oid for added/deleted sides. Malformed lines are skipped
// (fail-safe).
func parseRawDiff(out []byte) []port.ChangedFile {
	var files []port.ChangedFile
	for _, line := range splitCleanLines(out) {
		// Split off the path after the tab; the header before the tab carries
		// the modes/oids/status.
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		header, path := line[:tab], line[tab+1:]
		if path == "" {
			continue
		}
		fields := strings.Fields(header)
		// fields: [":<srcmode>", "<dstmode>", "<srcsha>", "<dstsha>", "<status>"]
		if len(fields) < 5 {
			continue
		}
		status := fields[4]
		dstOID := fields[3]
		// Normalize the all-zero oid (added/deleted side) to "".
		if isZeroOID(dstOID) {
			dstOID = ""
		}
		// Map git status letters to the A/M/D vocabulary; anything else is
		// skipped (renames are disabled via --no-renames, so only A/M/D/T arise;
		// T (type change) is treated as M for rule purposes).
		switch status {
		case "A":
			status = "A"
		case "M", "T":
			status = "M"
		case "D":
			status = "D"
			dstOID = ""
		default:
			continue
		}
		files = append(files, port.ChangedFile{Path: path, Status: status, BlobOID: dstOID})
	}
	return files
}

// isZeroOID reports whether s is the 40-zero object id git uses for absent
// sides of a diff.
func isZeroOID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < 40; i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// splitCleanLines splits stdout on newlines, dropping empty trailing lines.
func splitCleanLines(out []byte) []string {
	s := strings.TrimRight(string(out), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}