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
	"sync"
	"testing"
	"time"

	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/credentials/file"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/policy"
	_ "github.com/psenna/git-proxy/internal/policy/rules" // register rules via init()
	"github.com/psenna/git-proxy/internal/port"
	httpfront "github.com/psenna/git-proxy/internal/transport/http"
	"github.com/psenna/git-proxy/internal/upstream/plain"
	fileaudit "github.com/psenna/git-proxy/internal/audit/file"
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
	// AuditFile is the filesystem path to the JSONL audit log when the proxy is
	// started with audit enabled (StartWithPolicyAndAudit). Empty when no audit.
	AuditFile string

	upstreamSrv *httptest.Server
	ln          net.Listener
	cancel      context.CancelFunc
	errCh       chan error
	// onClose is invoked from Close AFTER the frontend has fully stopped (the
	// errCh drain returns), so any buffered writes (e.g. audit events) land
	// before the hook runs. nil when nothing needs closing. Set by builders
	// that wire extra resources whose lifetime must follow the frontend.
	onClose func()
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

	root := tolerantTempDir(t)
	barePath := filepath.Join(root, repo)
	mustRun(t, "git", "init", "--bare", "-b", "main", barePath)
	// Enable push over smart HTTP: git http-backend disables receive-pack by
	// default; http.receivepack=true on the bare repo turns it on.
	mustRun(t, "git", "-C", barePath, "config", "http.receivepack", "true")
	// Disable background auto-gc: git receive-pack may schedule `git gc --auto`
	// after a push, which runs asynchronously and can leave the bare repo
	// directory non-empty when the test's TempDir cleanup runs, causing flaky
	// "directory not empty" cleanup failures.
	mustRun(t, "git", "-C", barePath, "config", "gc.auto", "0")
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

// StartWithPolicy brings up the same upstream + proxy pair as Start, but with
// push enforcement enabled: the policy engine is built from pol via the default
// rule registry, and a caching inspection mirror opener is wired with its root
// at a fresh temp directory. The upstream is unauthenticated (no vault, no
// agent auth), matching the enforcement integration tests. pol's Mirror and
// Push knobs are read here; Mirror.Dir is overridden to a temp dir regardless.
//
// Pass pol as a config.PolicyConfig with the desired rules enabled (and their
// Params). An empty/nil rule set yields passthrough (use Start instead).
func StartWithPolicy(t *testing.T, repo string, pol config.PolicyConfig) *Harness {
	t.Helper()
	return startWithPolicy(t, repo, pol, "", false, nil)
}

// StartWithPolicyAndAudit is StartWithPolicy plus an append-only JSONL audit
// sink wired into the proxy's frontend with the "http" transport tag. The
// audit file is created at auditFile (parent dirs created); the harness closes
// the sink on Close. h.AuditFile is set so tests can read the JSONL events.
// Use to assert audit events for push allow/deny and read-protected fetch.
func StartWithPolicyAndAudit(t *testing.T, repo string, pol config.PolicyConfig, auditFile string) *Harness {
	t.Helper()
	return startWithPolicy(t, repo, pol, auditFile, false, nil)
}

// StartWithPolicyAuditAlerts is StartWithPolicyAndAudit plus dry-run mode and
// an alert sink wired into the proxy's frontend. dryRun=true enables dry-run
// (the proxy forwards a clean engine push-deny instead of blocking it). The
// alertSink (typically a webhook built from an httptest.Server URL) receives
// an Alert on every deny (enforced or dry-run). A nil alertSink means alerts
// are off (the proxy never fires an Alert). Use for the dry-run + alerts
// integration suite (Task 13).
func StartWithPolicyAuditAlerts(t *testing.T, repo string, pol config.PolicyConfig, auditFile string, dryRun bool, alertSink port.AlertSink) *Harness {
	t.Helper()
	return startWithPolicy(t, repo, pol, auditFile, dryRun, alertSink)
}

// startWithPolicy is the shared builder for StartWithPolicy,
// StartWithPolicyAndAudit, and StartWithPolicyAuditAlerts. auditFile is empty
// → no audit; non-empty → a file sink is opened (fail-closed at test startup on
// open error) and wired in. dryRun enables dry-run mode on the proxy. alertSink
// (nil → off) is wired into the proxy so denies fire an Alert.
func startWithPolicy(t *testing.T, repo string, pol config.PolicyConfig, auditFile string, dryRun bool, alertSink port.AlertSink) *Harness {
	t.Helper()

	h := Start(t, repo)
	// Stop the passthrough frontend Start built and rebuild with enforcement.
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

	eng, err := policy.Resolve(pol.ToPolicy(), nil)
	if err != nil {
		t.Fatalf("policy.Resolve: %v", err)
	}

	mirrorRoot := tolerantTempDir(t)
	opener := cachingMirrorOpener(h.UpstreamURL, mirrorRoot, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	up := plain.New(h.UpstreamURL, nil)
	frontend := httpfront.New(ln, up, h.UpstreamURL, map[string]string{h.Repo: h.Repo}, nil, nil)
	frontend.SetEnforcement(eng, opener, pol.MaxPackfileBytesOrDefault())
	// Read protection: wire the proxy-level fetch path matcher when configured.
	// Fail-closed on malformed patterns (mirrors main.go startup validation).
	if pol.ReadDenyEnabled() {
		if bad := pol.MalformedReadDenyPatterns(); len(bad) > 0 {
			t.Fatalf("read protection: malformed deny pattern(s): %q", bad)
		}
		frontend.SetReadDeny(pol.ReadDenyMatcher())
	}
	// Audit: wire an append-only JSONL file sink when an audit path is given.
	// Fail-closed at test startup on open error (mirrors main.go). The sink is
	// closed after the frontend stops so all buffered writes land before the
	// test reads the file.
	var auditSink *fileaudit.Sink
	if auditFile != "" {
		s, err := fileaudit.New(auditFile)
		if err != nil {
			t.Fatalf("audit: open %s: %v", auditFile, err)
		}
		auditSink = s
		frontend.SetAuditSink(auditSink, "http")
		h.AuditFile = auditFile
	}
	// Dry-run + alerts (Task 13): wired into the proxy's frontend alongside
	// audit. dryRun enables forward-on-clean-engine-deny (policy denies only,
	// NOT inspection errors). alertSink (nil → off) fires an Alert on every
	// deny. Best-effort: an alert delivery error never blocks the op.
	if dryRun {
		frontend.SetDryRun(true)
	}
	if alertSink != nil {
		frontend.SetAlertSink(alertSink)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- frontend.Serve(ctx) }()

	h.ProxyURL = "http://" + ln.Addr().String()
	h.ln = ln
	h.cancel = cancel
	h.errCh = errCh
	if auditSink != nil {
		// Close the audit sink after the frontend has fully stopped (the
		// errCh drain in Close returns), so all buffered audit writes land
		// before the test reads the JSONL file. errCh is drained exactly once,
		// in Close — we must NOT consume it here (that would deadlock Close).
		auditSink := auditSink // capture for the closure
		h.onClose = func() {
			if cerr := auditSink.Close(); cerr != nil {
				t.Logf("close audit sink: %v", cerr)
			}
		}
	}
	return h
}

// cachingMirrorOpener returns a gitproto.MirrorOpener that caches one bare
// mirror per repo under root, cloning from upstreamURL on first open. The
// upstream creds (for the fetch leg) are attached when non-nil; the agent never
// sees them. The cache is safe for concurrent use.
func cachingMirrorOpener(upstreamURL, root string, creds port.CredentialStore) gitproto.MirrorOpener {
	var mu sync.Mutex
	cache := map[string]*gitx.Mirror{}
	return func(ctx context.Context, repo string) (*gitx.Mirror, error) {
		mu.Lock()
		if m, ok := cache[repo]; ok {
			mu.Unlock()
			return m, nil
		}
		mu.Unlock()
		m, err := gitx.Open(ctx, upstreamURL, repo, root, creds)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		cache[repo] = m
		mu.Unlock()
		return m, nil
	}
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
	// onClose runs after the frontend has fully stopped (the errCh drain
	// above), so any buffered writes (e.g. audit events) land before the hook
	// closes its sink. Single place that drains errCh; no double read.
	if h.onClose != nil {
		h.onClose()
		h.onClose = nil
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

// tolerantTempDir creates a temp directory whose t.Cleanup removal retries on
// "directory not empty" errors. The upstream git-http-backend spawns git
// subprocesses (upload-pack/receive-pack) that can briefly hold files in the
// bare repo after a test completes; a plain t.TempDir cleanup races those
// subprocesses and fails flakily. Retrying lets the subprocesses exit first.
// Cleanup failures after the retries are reported via t.Errorf rather than
// fatal, so a transient race does not abort the whole test binary.
func tolerantTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gitproxy-it-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 5; i++ {
			if err := os.RemoveAll(dir); err == nil {
				return
			} else if !isBusyDirErr(err) {
				t.Errorf("cleanup temp dir %s: %v", dir, err)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		// Last attempt; report remaining files for diagnosis.
		if err := os.RemoveAll(dir); err != nil {
			var left []string
			_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
				if err == nil {
					left = append(left, p)
				}
				return nil
			})
			t.Errorf("cleanup temp dir %s after retries: %v; remaining: %v", dir, err, left)
		}
	})
	return dir
}

// isBusyDirErr reports whether err is a "directory not empty" style error that
// is safe to retry (a concurrent subprocess is momentarily holding a file).
func isBusyDirErr(err error) bool {
	return strings.Contains(err.Error(), "directory not empty")
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
