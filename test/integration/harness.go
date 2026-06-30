// Package integration provides the end-to-end test harness for git-proxy.
//
// The harness stands up a real upstream git HTTP server (git http-backend over
// CGI) backed by a bare repository in a temporary directory, starts the proxy
// pointing at it, and gives the test a real `git` client configured to talk to
// the proxy via a url.<proxy>.insteadOf <upstream> rewrite.
//
// Every later milestone extends this harness; it is the single place that knows
// how to bring up a real upstream + proxy pair.
package integration

import (
	"context"
	"net"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/credentials/file"
	"github.com/psenna/git-proxy/internal/port"
	httpfront "github.com/psenna/git-proxy/internal/transport/http"
	"github.com/psenna/git-proxy/internal/upstream/plain"
)

// Harness holds a running upstream git HTTP server and proxy pair.
type Harness struct {
	// UpstreamURL is the real git HTTP upstream URL (git http-backend).
	UpstreamURL string
	// ProxyURL is the proxy's base URL. The git client talks to this.
	ProxyURL string
	// Repo is the repository path served by the upstream (e.g. "test.git").
	Repo string
	// BarePath is the filesystem path to the upstream bare repo, for
	// verifying that pushes through the proxy reached upstream directly.
	BarePath string
	// Token is the valid agent bearer token when the proxy is started with
	// auth enabled (StartWithAuth). Empty for the unauthenticated passthrough
	// harness (Start). The git client sends it via http.extraHeader.
	Token string
	// VaultPath is the filesystem path to the credential vault file when the
	// proxy is started with a vault (StartWithAuth). Empty when no vault.
	VaultPath string

	upstreamSrv *httptest.Server
	ln          net.Listener
	cancel      context.CancelFunc
	errCh       chan error
}

// gitHTTPBackendPath locates the git-http-backend CGI executable.
func gitHTTPBackendPath(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("git-http-backend"); err == nil {
		return p
	}
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := exec.LookPath(p); err != nil {
		t.Fatalf("git-http-backend not found: %v", err)
	}
	return p
}

// Start brings up an upstream bare repo (seeded with one commit) served by
// git http-backend over CGI, plus a passthrough proxy pointing at it.
//
// repo is the repository path to create (e.g. "test.git"). The returned
// harness's ProxyURL replaces UpstreamURL for any git client via insteadOf.
func Start(t *testing.T, repo string) *Harness {
	t.Helper()

	root := t.TempDir()
	barePath := filepath.Join(root, repo)
	mustRun(t, "git", "init", "--bare", "-b", "main", barePath)
	// Enable push over smart HTTP: git http-backend disables receive-pack by
	// default; http.receivepack=true on the bare repo turns it on.
	mustRun(t, "git", "-C", barePath, "config", "http.receivepack", "true")
	seedUpstream(t, barePath)

	// Upstream HTTP server: git http-backend over CGI.
	upstreamSrv := httptest.NewServer(&cgi.Handler{
		Path: gitHTTPBackendPath(t),
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	})

	// Proxy: ephemeral listener, passthrough upstream, identity repo map.
	// No auth and no vault: passthrough mode (kept for the passthrough suite).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		upstreamSrv.Close()
		t.Fatalf("listen: %v", err)
	}
	up := plain.New(upstreamSrv.URL, nil)
	frontend := httpfront.New(ln, up, upstreamSrv.URL, map[string]string{repo: repo}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- frontend.Serve(ctx) }()

	h := &Harness{
		UpstreamURL: upstreamSrv.URL,
		ProxyURL:    "http://" + ln.Addr().String(),
		Repo:        repo,
		BarePath:    barePath,
		upstreamSrv: upstreamSrv,
		ln:          ln,
		cancel:      cancel,
		errCh:       errCh,
	}
	t.Cleanup(h.Close)
	return h
}

// StartWithAuth brings up the same upstream + proxy pair as Start, but with
// Bearer token authentication enabled on the proxy and an optional credential
// vault. token is the single valid agent token. vaultCreds, if non-nil, is
// written to a vault file the proxy loads and used to attach upstream Basic
// auth on the proxy→upstream leg. The harness exposes Token (for the git
// client) and VaultPath (so a test can assert creds isolation against the
// file's contents).
func StartWithAuth(t *testing.T, repo, agentToken string, vaultCreds map[string]port.Credentials) *Harness {
	t.Helper()

	h := Start(t, repo)
	// Stop the passthrough frontend Start built and rebuild with auth + vault.
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	if h.errCh != nil {
		<-h.errCh
		h.errCh = nil
	}
	if h.ln != nil {
		_ = h.ln.Close()
		h.ln = nil
	}

	var store port.CredentialStore
	if vaultCreds != nil {
		h.VaultPath = writeVault(t, vaultCreds)
		s, err := file.New(h.VaultPath)
		if err != nil {
			t.Fatalf("load vault: %v", err)
		}
		store = s
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	up := plain.New(h.UpstreamURL, store)
	authn := token.New(map[string]string{agentToken: "agent-1"})
	frontend := httpfront.New(ln, up, h.UpstreamURL, map[string]string{h.Repo: h.Repo}, authn, store)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- frontend.Serve(ctx) }()

	h.ProxyURL = "http://" + ln.Addr().String()
	h.Token = agentToken
	h.ln = ln
	h.cancel = cancel
	h.errCh = errCh
	return h
}

// writeVault writes a credential vault YAML file and returns its path. The
// vault maps repo paths to upstream credentials.
func writeVault(t *testing.T, creds map[string]port.Credentials) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("credentials:\n")
	for repo, c := range creds {
		b.WriteString("  \"" + repo + "\":\n")
		b.WriteString("    username: " + c.Username + "\n")
		b.WriteString("    password: " + c.Password + "\n")
	}
	p := filepath.Join(t.TempDir(), "vault.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	return p
}

// Close stops the proxy and upstream servers. It is safe to call multiple
// times; Start registers it with t.Cleanup, so callers need not call it.
func (h *Harness) Close() {
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	if h.ln != nil {
		_ = h.ln.Close()
		h.ln = nil
	}
	if h.errCh != nil {
		<-h.errCh
		h.errCh = nil
	}
	if h.upstreamSrv != nil {
		h.upstreamSrv.Close()
		h.upstreamSrv = nil
	}
}

// seedUpstream creates an initial commit in the bare repo by cloning it to a
// throwaway worktree, committing a file, and pushing back over file://.
func seedUpstream(t *testing.T, barePath string) {
	t.Helper()
	work := t.TempDir()
	mustRun(t, "git", "clone", "-q", "file://"+barePath, work)
	mustRun(t, "git", "-C", work, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", work, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	mustRun(t, "git", "-C", work, "add", "README.md")
	mustRun(t, "git", "-C", work, "commit", "-q", "-m", "initial seed")
	mustRun(t, "git", "-C", work, "push", "-q", "origin", "main")
}

// Git returns a `git` command preconfigured to route upstream URLs through the
// proxy via url.<proxy>.insteadOf <upstream>, run in the given working dir.
//
// Pass dir as "" to use the test's temp dir. The returned command has its
// stdout/stderr unattached; use RunGit for fail-fast execution or set
// cmd.Stdout/Stderr yourself for inspection.
func (h *Harness) Git(dir string, args ...string) *exec.Cmd {
	full := []string{"-c", "url." + h.ProxyURL + ".insteadOf=" + h.UpstreamURL}
	if h.Token != "" {
		// Send the agent bearer token to the proxy. http.extraHeader applies
		// to every HTTP request git makes; the only HTTP server it talks to is
		// the proxy (via insteadOf), so the header reaches the proxy and never
		// the upstream.
		full = append(full, "-c", "http.extraHeader=Authorization: Bearer "+h.Token)
	}
	full = append(full, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	return cmd
}

// RunGit runs a git command through the proxy and fails the test on error.
func (h *Harness) RunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := h.Git(dir, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// UpstreamRef returns the SHA a ref points at in the upstream bare repo,
// verified directly via the filesystem (bypassing HTTP) so a test can prove a
// push through the proxy actually reached upstream.
func (h *Harness) UpstreamRef(t *testing.T, ref string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", h.BarePath, "rev-parse", ref).Output()
	if err != nil {
		t.Fatalf("rev-parse %s in upstream: %v", ref, err)
	}
	return strings.TrimSpace(string(out))
}

// mustRun runs a command and fails the test on error.
func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// mustOutput runs a command and returns its stdout, failing the test on a
// non-zero exit (its stderr is included in the failure message).
func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, ee.Stderr)
		}
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}
