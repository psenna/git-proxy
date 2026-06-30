package gitx

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// Mirror is a read-only bare clone of a single upstream repository, used only
// for object inspection (ancestry walks). The proxy never serves from it, it
// is never a push target, and the agent never sees it. A Mirror is safe for
// concurrent use after Open.
type Mirror struct {
	dir         string // bare repo path
	upstreamURL string // full upstream URL for the repo (creds embedded if any)
}

// repoSlug derives a filesystem-safe directory name from a repo path, replacing
// path separators with "-". e.g. "org/team/repo.git" -> "org-team-repo.git".
func repoSlug(repo string) string {
	if repo == "" {
		return "default"
	}
	return strings.ReplaceAll(repo, "/", "-")
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
	if !mirrorExists(dir) {
		if err := cloneMirror(ctx, dir, repoURL); err != nil {
			return nil, fmt.Errorf("gitx: open mirror for %q: %w", repo, err)
		}
	}
	return &Mirror{dir: dir, upstreamURL: repoURL}, nil
}

// mirrorExists reports whether dir looks like an existing git bare repo.
func mirrorExists(dir string) bool {
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
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--git-dir").CombinedOutput()
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
		return fmt.Errorf("clone --mirror: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Refresh fetches all refs from the upstream so the mirror has the current
// "old" values the enforcement path compares pushed commits against.
func (m *Mirror) Refresh(ctx context.Context) error {
	if _, err := runGit(ctx, m.dir, "fetch", "--quiet", "origin"); err != nil {
		return fmt.Errorf("gitx: refresh mirror: %w", err)
	}
	return nil
}

// IngestPackfile writes a pushed packfile's objects into the mirror's object
// store via `git index-pack --stdin` WITHOUT updating any ref. After this, both
// the old (from Refresh) and the new (from the pack) objects are present for
// ancestry walks. The packfile is read to EOF from r.
func (m *Mirror) IngestPackfile(ctx context.Context, r io.Reader) error {
	cmd := exec.CommandContext(ctx, "git", "-C", m.dir, "index-pack", "--stdin")
	cmd.Stdin = r
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gitx: index-pack --stdin: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IsAncestor reports whether old is an ancestor of new via
// `git merge-base --is-ancestor old new`. old=="" (ref creation) and new==""
// (ref deletion) are NOT force-pushes: return (false, nil) for those. An
// ancestry error (e.g. a missing object) is returned as an error so the caller
// can fail closed.
func (m *Mirror) IsAncestor(ctx context.Context, old, new string) (bool, error) {
	if old == "" || new == "" {
		return false, nil
	}
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

// Dir returns the mirror's bare repo path (for tests/inspection only).
func (m *Mirror) Dir() string { return m.dir }