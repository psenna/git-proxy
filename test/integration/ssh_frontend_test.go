package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/policy"
)

// TestSSH_ClonePassthrough verifies a real `git clone ssh://agent@host:port/repo`
// succeeds through the proxy in passthrough mode (no policy rules). The clone
// fetches the seed commit and the working tree matches the upstream.
func TestSSH_ClonePassthrough(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	sh := StartSSH(t, "ssh-test.git", "agent-1", config.PolicyConfig{})
	work := t.TempDir()
	sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-test.git", "clone")
	clone := filepath.Join(work, "clone")
	// The clone should contain the seed README.md.
	if _, err := os.Stat(filepath.Join(clone, "README.md")); err != nil {
		t.Fatalf("clone missing README.md: %v", err)
	}
	// And HEAD should match the upstream main.
	if got := revParse(t, clone, "HEAD"); got != sh.UpstreamRef(t, "refs/heads/main") {
		t.Errorf("clone HEAD = %s, upstream main = %s", got, sh.UpstreamRef(t, "refs/heads/main"))
	}
}

// TestSSH_PushPolicyForcePushBlocked verifies that a force-push to a protected
// ref is blocked by the history_protect rule over SSH: the push is rejected
// with a reason visible to the client, and the upstream is left unchanged.
func TestSSH_PushPolicyForcePushBlocked(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	pol := policyHistoryProtect("refs/heads/main")
	sh := StartSSH(t, "ssh-push.git", "agent-1", pol)
	work := t.TempDir()
	sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-push.git", "clone")
	clone := filepath.Join(work, "clone")
	mustRunGit(t, clone, "config", "user.email", "test@example.com")
	mustRunGit(t, clone, "config", "user.name", "Test")

	// Rewrite history on main: amend the seed commit (a non-fast-forward
	// rewrite) so history_protect must block the force-push.
	mustRunGit(t, clone, "commit", "--amend", "--allow-empty", "-q", "-m", "rewrite")
	upstreamBefore := sh.UpstreamRef(t, "refs/heads/main")

	// Force-push main: must be rejected by history_protect.
	cmd := sh.GitSSH(clone, "push", "-f", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("force-push over SSH succeeded; history_protect should have blocked it")
	}
	if !strings.Contains(string(out), "history") && !strings.Contains(string(out), "protected") && !strings.Contains(string(out), "rejected") && !strings.Contains(string(out), "denied") {
		t.Fatalf("force-push output does not show a policy rejection:\n%s", out)
	}
	// Upstream MUST be unchanged (push did not reach it).
	if got := sh.UpstreamRef(t, "refs/heads/main"); got != upstreamBefore {
		t.Fatalf("upstream main changed after blocked force-push: %s -> %s", upstreamBefore, got)
	}
}

// TestSSH_PushCleanFFReachesUpstream verifies that a clean fast-forward push
// over SSH is forwarded to the upstream (policy allows it — history_protect
// blocks force/rewrite, not FF).
func TestSSH_PushCleanFFReachesUpstream(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	pol := policyHistoryProtect("refs/heads/main")
	sh := StartSSH(t, "ssh-ff.git", "agent-1", pol)
	work := t.TempDir()
	sh.RunGitSSH(t, work, "clone", sh.h.UpstreamURL+"/ssh-ff.git", "clone")
	clone := filepath.Join(work, "clone")
	mustRunGit(t, clone, "config", "user.email", "test@example.com")
	mustRunGit(t, clone, "config", "user.name", "Test")

	// Add a NEW commit on top of main (fast-forward, no rewrite).
	if err := os.WriteFile(filepath.Join(clone, "new.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	mustRunGit(t, clone, "add", "new.txt")
	mustRunGit(t, clone, "commit", "-q", "-m", "ff commit")
	newHead := revParse(t, clone, "HEAD")

	// Push main: should be a fast-forward and reach the upstream.
	sh.RunGitSSH(t, clone, "push", "origin", "main")
	if got := sh.UpstreamRef(t, "refs/heads/main"); got != newHead {
		t.Fatalf("upstream main = %s, want pushed HEAD %s (FF push did not reach upstream)", got, newHead)
	}
}

// TestSSH_UnknownKeyCloneFails verifies fail-closed key auth: a clone with an
// unknown client key is rejected (auth denied — no session, no advertisement).
func TestSSH_UnknownKeyCloneFails(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	sh := StartSSH(t, "ssh-auth.git", "agent-1", config.PolicyConfig{})
	// Generate a DIFFERENT client key not in the authorized set.
	unknownKeyPath, _ := writeClientKey(t)
	work := t.TempDir()
	sshCmd := "ssh -i " + unknownKeyPath + " -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
	cmd := exec.Command("git",
		"-c", "url.ssh://agent-1@"+sh.SSHProxyAddr+".insteadOf="+sh.h.UpstreamURL,
		"-c", "core.sshCommand="+sshCmd,
		"clone", sh.h.UpstreamURL+"/ssh-auth.git", filepath.Join(work, "clone"),
	)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("clone with unknown key succeeded; SSH key auth should have rejected it (fail closed)")
	}
	// The failure must be an auth denial, not a different error. Git surfaces
	// "Permission denied" for SSH auth failures.
	if !strings.Contains(string(out), "Permission denied") && !strings.Contains(string(out), "denied") {
		t.Fatalf("unknown-key clone did not report an auth denial:\n%s", out)
	}
}

// gitAvailable reports whether the git binary is usable.
func gitAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	return true
}

// mustRunGit runs a git command in dir and fails the test on error (no proxy).
func mustRunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestSSH_ReadProtection_CloneWithholdsSecretBlob is the SSH-transport
// counterpart of TestReadProtection_CloneWithholdsSecretBlob. A real
// `git clone --filter=blob:none ssh://agent@host:port/repo` through the
// read-protected SSH frontend must receive a packfile that OMITS the denied
// secret blob while delivering the non-denied blobs (README.md, docs/guide.md).
//
// This exercises the read-protected SSH path end to end: the frontend's
// writeAdvertisement re-emits the upstream advertisement as v0 with the
// `filter` + `allow-reachable-sha1-in-want` extra caps (because
// proxy.ReadDenyOn()), and Proxy.UploadPack assembles the filtered packfile
// via ServeUploadPackEnforced, withholding blobs whose path matches the deny
// matcher. Read protection is wired over SSH through the shared *gitproto.Proxy
// (the reviewer confirmed), so this is a coverage-add; it must pass on the
// existing code.
//
// What is asserted (the packfile-withholding guarantee over SSH):
//   - The denied secret blob OID is NOT in the clone's local object store right
//     after clone (inspected via --batch-all-objects, which does not trigger
//     the on-demand fetch path).
//   - The non-denied blob OIDs (README.md, docs/guide.md) ARE present, proving
//     the proxy delivered the rest of the repo over SSH.
//   - The secret canary string never appears in the received packfile bytes.
//
// What is NOT asserted (out of v1 / single-round-over-SSH scope): an on-demand
// fetch of the denied blob over SSH (`git cat-file -p <oid>`) is not exercised
// here — the single-round v0-over-SSH path does not expose a clean on-demand
// fetch round the way the HTTP path does, and the core read-protection
// guarantee (the denied blob is withheld from the served packfile) is what this
// test proves. The on-demand denial is covered for the HTTP transport in
// TestServeUploadPackEnforced_OnDemandBlob_DenyByPath.
func TestSSH_ReadProtection_CloneWithholdsSecretBlob(t *testing.T) {
	if !gitAvailable(t) {
		t.Skip("git not available")
	}
	sh := StartSSH(t, "ssh-readprot.git", "agent-1", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, sh.h)

	work := t.TempDir()
	dst := filepath.Join(work, "clone")
	// Partial clone through the SSH proxy. Checkout aborts on the denied blob's
	// missing-object pre-fetch, so a non-zero exit is expected and acceptable;
	// the clone still creates the repo and indexes the served packfile.
	cmd := sh.GitSSH(work, "clone", "--filter=blob:none", sh.h.UpstreamURL+"/ssh-readprot.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld over SSH): %v\n%s", err, out)
	}

	// Resolve the blob OIDs directly from the upstream bare repo (bypassing the
	// proxy) so the assertions compare against the real object ids.
	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", sh.h.BarePath, "rev-parse", "HEAD:secrets/secret.txt"))
	readmeOID := strings.TrimSpace(mustOutput(t, "git", "-C", sh.h.BarePath, "rev-parse", "HEAD:README.md"))
	guideOID := strings.TrimSpace(mustOutput(t, "git", "-C", sh.h.BarePath, "rev-parse", "HEAD:docs/guide.md"))

	// Inspect the clone's local object store WITHOUT triggering any on-demand
	// fetch (--batch-all-objects lists only objects already present).
	present := presentObjectOIDs(t, dst)

	if present[secretOID] {
		t.Errorf("DENY LEAK over SSH: denied secret blob %s is present in the clone's object store (packfile withholding failed)", secretOID)
	}
	if !present[readmeOID] {
		t.Errorf("non-denied blob %s (README.md) missing from SSH clone — other files must clone fine", readmeOID)
	}
	if !present[guideOID] {
		t.Errorf("non-denied blob %s (docs/guide.md) missing from SSH clone — other files must clone fine", guideOID)
	}

	// Belt-and-suspenders: the secret canary must not appear anywhere in the
	// received packfile bytes.
	const canary = "TOP-SECRET-VALUE-DO-NOT-LEAK"
	if packs, _ := filepath.Glob(filepath.Join(dst, ".git", "objects", "pack", "*.pack")); len(packs) > 0 {
		for _, p := range packs {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Logf("read pack %s: %v", p, err)
				continue
			}
			if strings.Contains(string(b), canary) {
				t.Errorf("DENY LEAK over SSH: secret canary found in served packfile %s", p)
			}
		}
	}
}

// Ensure policy import is used (rule registry init side effect).
var _ = policy.FirstDeny