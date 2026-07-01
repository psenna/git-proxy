package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/auth/keyauth"
	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/policy"
	_ "github.com/psenna/git-proxy/internal/policy/rules" // register rules via init()
	"github.com/psenna/git-proxy/internal/port"
	sshfront "github.com/psenna/git-proxy/internal/transport/ssh"
	"github.com/psenna/git-proxy/internal/upstream/plain"
	"golang.org/x/crypto/ssh"
)

// SSHHarness extends a running upstream (git http-backend) with an SSH-enabled
// git-proxy. It generates an ephemeral host key (for the proxy's SSH server)
// and a client key (for the git client), authorizes the client key → agent,
// and exposes SSHProxyAddr for ssh:// clone/push. Reuses the existing HTTP
// upstream (plain.Upstream → git-http-backend) so fetch/push over SSH exercise
// the real protocol stack end to end.
type SSHHarness struct {
	// SSHProxyAddr is the proxy's SSH listen address (host:port).
	SSHProxyAddr string
	// SSHUser is the agent identity the client key maps to (used as the ssh
	// user in ssh://agent@host URLs — the user is the agent name, but the proxy
	// maps by KEY not user; we pass the agent name for clarity).
	SSHUser string
	// ClientKeyPath is the filesystem path to the client's private key PEM.
	ClientKeyPath string
	// ClientHostKeyPath is the filesystem path to a known_hosts file pinning
	// the proxy's ephemeral host key (so GIT_SSH_COMMAND can disable strict host
	// checking OR pin it).
	ClientHostKeyPath string

	// Embeds the HTTP-facing harness fields (UpstreamURL, BarePath, Repo, etc.)
	// via the underlying Harness. SSH-only tests do not use ProxyURL.
	h *Harness

	// sshCancel stops the SSH frontend.
	sshCancel context.CancelFunc
	// sshErrCh receives the SSH frontend's Serve result.
	sshErrCh chan error
}

// StartSSH brings up the same upstream + proxy pair as Start, but with the SSH
// frontend enabled: a generated host key, a generated client key authorized →
// agent (agentName), and push enforcement + read protection optionally wired
// from pol (mirror dir is a fresh temp dir). Returns an SSHHarness whose
// GitSSH method returns a git command configured for ssh:// clone/push via
// GIT_SSH_COMMAND with the client key and disabled strict host checking.
//
// Pass pol as a config.PolicyConfig with the desired rules enabled; an empty
// rule set + no read-deny yields passthrough. mirrorRoot is overridden to a
// temp dir regardless.
func StartSSH(t *testing.T, repo, agentName string, pol config.PolicyConfig) *SSHHarness {
	t.Helper()

	h := Start(t, repo)
	// Stop the passthrough HTTP frontend Start built; the SSH harness only
	// needs the upstream (git http-backend). Keep the HTTP upstream server.
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
	h.ProxyURL = "" // SSH harness does not expose an HTTP proxy URL.

	// Build enforcement state shared with the SSH frontend (same as main.go).
	var (
		eng      *policy.Engine
		opener   gitproto.MirrorOpener
		readDeny = pol.ReadDenyMatcher()
		maxBytes = pol.MaxPackfileBytesOrDefault()
	)
	if pol.HasEnabledRules() {
		e, err := policy.Resolve(pol.ToPolicy(), nil)
		if err != nil {
			t.Fatalf("policy.Resolve: %v", err)
		}
		eng = e
	}
	mirrorRoot := tolerantTempDir(t)
	opener = cachingMirrorOpener(h.UpstreamURL, mirrorRoot, nil)
	if pol.ReadDenyEnabled() {
		if bad := pol.MalformedReadDenyPatterns(); len(bad) > 0 {
			t.Fatalf("read protection: malformed deny pattern(s): %q", bad)
		}
	}

	// Generate the proxy's ephemeral SSH host key (PEM file). The harness always
	// supplies a host key (the brief notes ephemeral is the fallback; here we
	// write one so the proxy can load it from a path).
	hostKeyPath, hostSigner := writeHostKey(t)
	// Generate the client's SSH key pair and authorize its public key → agent.
	clientKeyPath, authorizedKey := writeClientKey(t)

	sshAuthn, err := keyauth.New(map[string]string{agentName: authorizedKey})
	if err != nil {
		t.Fatalf("keyauth.New: %v", err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssh listen: %v", err)
	}
	sshFE, err := sshfront.New(sshLn, plainUpstream(t, h), map[string]string{repo: repo}, sshAuthn, hostKeyPath)
	if err != nil {
		t.Fatalf("ssh frontend: %v", err)
	}
	sshFE.SetEnforcement(eng, opener, maxBytes)
	sshFE.SetReadDeny(readDeny)

	ctx, cancel := context.WithCancel(context.Background())
	sshErrCh := make(chan error, 1)
	go func() { sshErrCh <- sshFE.Serve(ctx) }()

	sh := &SSHHarness{
		SSHProxyAddr:      sshLn.Addr().String(),
		SSHUser:           agentName,
		ClientKeyPath:     clientKeyPath,
		ClientHostKeyPath: writeKnownHosts(t, sshLn.Addr().String(), hostSigner),
		h:                 h,
		sshCancel:         cancel,
		sshErrCh:          sshErrCh,
	}
	t.Cleanup(sh.Close)
	return sh
}

// plainUpstream builds a plain.Upstream for the harness's HTTP upstream URL
// (no vault creds — the SSH harness upstream is unauthenticated, matching the
// push-enforcement integration tests).
func plainUpstream(t *testing.T, h *Harness) port.Upstream {
	t.Helper()
	return plain.New(h.UpstreamURL, nil)
}

// Close stops the SSH frontend and the underlying upstream. Safe to call
// multiple times; StartSSH registers it with t.Cleanup.
func (s *SSHHarness) Close() {
	if s.sshCancel != nil {
		s.sshCancel()
		s.sshCancel = nil
	}
	if s.sshErrCh != nil {
		<-s.sshErrCh
		s.sshErrCh = nil
	}
	if s.h != nil {
		s.h.Close()
		s.h = nil
	}
}

// GitSSH returns a `git` command configured to talk to the proxy over SSH
// (ssh://user@host:port/repo) using the generated client key and disabled
// strict host checking. The repo path is passed through unchanged (the proxy
// maps repo→repo via the repos map). The command runs in dir ("" for t.TempDir).
//
// The upstream URL is rewritten via url.<ssh-proxy>.insteadOf so the test can
// call `git clone <upstream-url>/repo` and have it routed over SSH.
func (s *SSHHarness) GitSSH(dir string, args ...string) *exec.Cmd {
	sshProxy := "ssh://" + s.SSHUser + "@" + s.SSHProxyAddr
	sshCmd := fmt.Sprintf(
		"ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR",
		s.ClientKeyPath,
	)
	full := []string{
		"-c", "url." + sshProxy + ".insteadOf=" + s.h.UpstreamURL,
		"-c", "core.sshCommand=" + sshCmd,
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

// RunGitSSH runs a git command over the SSH proxy and fails the test on error.
func (s *SSHHarness) RunGitSSH(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := s.GitSSH(dir, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// UpstreamRef returns the SHA a ref points at in the upstream bare repo
// (verified directly via the filesystem), so a test can prove a push over SSH
// reached upstream.
func (s *SSHHarness) UpstreamRef(t *testing.T, ref string) string {
	t.Helper()
	return s.h.UpstreamRef(t, ref)
}

// writeHostKey generates an ed25519 SSH host key pair, writes the private key
// PEM to a temp file, and returns the path + the ssh.Signer (for known_hosts).
func writeHostKey(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal host key: %v", err)
	}
	p := filepath.Join(t.TempDir(), "ssh_host_ed25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	return p, signer
}

// writeClientKey generates an ed25519 SSH client key pair, writes the private
// key PEM to a temp file, and returns the path + the authorized-keys string
// for the public key.
func writeClientKey(t *testing.T) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	p := filepath.Join(t.TempDir(), "client_ed25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("client public key: %v", err)
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
	return p, authorized
}

// writeKnownHosts writes a known_hosts file pinning the proxy's host key for
// host:port, so a test that prefers pinning (over StrictHostChecking=no) can
// use it. Returns the path.
func writeKnownHosts(t *testing.T, addr string, signer ssh.Signer) string {
	t.Helper()
	pubKey := signer.PublicKey()
	line := fmt.Sprintf("%s %s\n", addr, string(ssh.MarshalAuthorizedKey(pubKey)))
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return p
}