package gitx

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// staticStore is a port.CredentialStore that returns a fixed credential and
// ok flag for every repo (used to exercise upstreamRepoURL's credential
// branches without the profile store).
type staticStore struct {
	c  port.Credentials
	ok bool
}

func (s staticStore) CredentialsFor(string) (port.Credentials, bool) {
	return s.c, s.ok
}

// TestUpstreamRepoURL covers the git-protocol leg's upstream-URL credential
// embedding, in particular the token-only synthesis (GitHub PAT Basic form
// x-access-token:<token>) that lets a token-only profile authenticate the
// mirror's clone/fetch. It also guards against the pre-fix regression where a
// token-only profile embedded a malformed ":@" empty userinfo.
func TestUpstreamRepoURL(t *testing.T) {
	const base = "https://github.com/owner"
	const repo = "repo.git"
	const bare = "https://github.com/owner/repo.git"

	cases := []struct {
		name  string
		creds port.CredentialStore
		want  string
	}{
		{
			name:  "nil creds yields bare URL",
			creds: nil,
			want:  bare,
		},
		{
			name:  "no matching profile yields bare URL",
			creds: staticStore{ok: false},
			want:  bare,
		},
		{
			name:  "secretless profile (ok but all fields empty) yields bare URL, not malformed :@",
			creds: staticStore{c: port.Credentials{}, ok: true},
			want:  bare,
		},
		{
			name:  "token-only synthesizes x-access-token Basic userinfo",
			creds: staticStore{c: port.Credentials{Token: "ghp_x"}, ok: true},
			want:  "https://x-access-token:ghp_x@github.com/owner/repo.git",
		},
		{
			name:  "full profile embeds username:password userinfo",
			creds: staticStore{c: port.Credentials{Username: "u", Password: "p", Token: "ghp_x"}, ok: true},
			want:  "https://u:p@github.com/owner/repo.git",
		},
		{
			name:  "password-only profile embeds :password userinfo",
			creds: staticStore{c: port.Credentials{Password: "p"}, ok: true},
			want:  "https://:p@github.com/owner/repo.git",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := upstreamRepoURL(base, repo, tc.creds)
			if got != tc.want {
				t.Fatalf("upstreamRepoURL(...) = %q, want %q", got, tc.want)
			}
			// Defense-in-depth: the token-only URL must never be the malformed
			// ":@" empty-userinfo form that caused issue #71's 401/502.
			if strings.Contains(tc.name, "token-only") && !strings.Contains(got, "x-access-token:ghp_x@") {
				t.Errorf("token-only URL missing synthesized userinfo: %q", got)
			}
		})
	}
}

// TestRedactCreds_SynthesizedUserinfo confirms the synthesized x-access-token
// userinfo is stripped from git stderr before an error reaches the agent, so
// the embedded PAT never leaks through a wrapped gitx error.
func TestRedactCreds_SynthesizedUserinfo(t *testing.T) {
	in := "fatal: could not read Username for 'https://x-access-token:ghp_supersecret@github.com/owner/repo.git'"
	got := redactCreds(in)
	want := "fatal: could not read Username for 'https://***@github.com/owner/repo.git'"
	if got != want {
		t.Fatalf("redactCreds(...) = %q, want %q", got, want)
	}
	if strings.Contains(got, "ghp_supersecret") {
		t.Errorf("redactCreds leaked the token: %q", got)
	}
}

// --- filterPresentHaves white-box tests (package gitx) ---

// hasGit skips the test if git is unavailable.
func hasGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not found on PATH: %v", err)
	}
}

// gitCmd runs git in dir ("" for cwd) and fails the test on error.
func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// gitOutput runs git -C dir <args...> and returns trimmed stdout, failing the
// test on error.
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := make([]string, 0, len(args)+2)
	full = append(full, "-C", dir)
	full = append(full, args...)
	out, err := exec.Command("git", full...).Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// openTestMirror opens a fresh mirror over a one-commit upstream and refreshes
// it, returning the mirror. The tip OID is available via
// gitOutput(t, m.dir, "rev-parse", "refs/heads/main").
func openTestMirror(t *testing.T, ctx context.Context) *Mirror {
	t.Helper()
	source := t.TempDir()
	gitCmd(t, "", "init", "-q", "-b", "main", source)
	gitCmd(t, source, "config", "user.email", "test@example.com")
	gitCmd(t, source, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	gitCmd(t, source, "add", "a.txt")
	gitCmd(t, source, "commit", "-q", "-m", "add a")

	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "up.git")
	gitCmd(t, "", "init", "--bare", "-q", "-b", "main", bare)
	gitCmd(t, source, "push", "-q", "file://"+bare, "main")

	root := t.TempDir()
	m, err := Open(ctx, "file://"+bareRoot, "up.git", root, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return m
}

// TestFilterPresentHaves_ParsingFailClosed exercises the white-box
// filterPresentHaves helper (callers hold m.mu): empty input yields (nil, nil);
// all-missing haves yield an empty slice with no error; mixed present/missing
// haves yield only the present OIDs in input order (duplicates preserved); a
// cancelled context fails closed (non-nil error, nil slice).
func TestFilterPresentHaves_ParsingFailClosed(t *testing.T) {
	hasGit(t)
	ctx := context.Background()
	m := openTestMirror(t, ctx)
	tip := gitOutput(t, m.dir, "rev-parse", "refs/heads/main")
	unknown := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// Empty input -> (nil, nil).
	m.mu.Lock()
	got, err := m.filterPresentHaves(ctx, nil)
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("filterPresentHaves(nil) error: %v", err)
	}
	if got != nil {
		t.Errorf("filterPresentHaves(nil) = %v, want nil", got)
	}

	// All-missing -> empty slice, nil error.
	m.mu.Lock()
	got, err = m.filterPresentHaves(ctx, []string{unknown})
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("filterPresentHaves(all missing) error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("filterPresentHaves(all missing) = %v, want empty", got)
	}

	// Mixed present/missing -> only present, order preserved (duplicates kept).
	m.mu.Lock()
	got, err = m.filterPresentHaves(ctx, []string{tip, unknown, tip})
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("filterPresentHaves(mixed) error: %v", err)
	}
	want := []string{tip, tip}
	if len(got) != len(want) {
		t.Fatalf("filterPresentHaves(mixed) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filterPresentHaves(mixed) = %v, want %v (order must be preserved)", got, want)
		}
	}

	// Cancelled context -> non-nil error, nil slice (fail closed).
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.mu.Lock()
	got, err = m.filterPresentHaves(cctx, []string{tip})
	m.mu.Unlock()
	if err == nil {
		t.Fatal("filterPresentHaves(cancelled ctx) returned nil error; want fail-closed error")
	}
	if got != nil {
		t.Errorf("filterPresentHaves(cancelled ctx) = %v, want nil slice on error", got)
	}
}
