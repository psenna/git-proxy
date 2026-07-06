package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/port"
)

// TestE2E_V1Capstone is the v1 capstone end-to-end test. It exercises the full
// v1 contract in a single real-git flow against ONE proxy instance configured
// with the full v1 policy (auth + push rules + read protection + audit). Each
// step maps to a milestone acceptance criterion, so the "all milestones hold
// end-to-end" acceptance is self-evident from this one test:
//
//	M3  — Auth: fail-closed without the agent token (ls-remote rejected); success
//	         with the token (ls-remote advertises refs/heads/main).
//	M5  — Push enforcement: a clean fast-forward push to feat/* is ALLOWED and
//	         reaches the upstream (assert the upstream ref advanced — the real
//	         allow signal, not just an exit code). A --force push to the
//	         history_protect-guarded ref main is BLOCKED; the upstream ref is
//	         unchanged and the agent sees a structured deny reason.
//	M6  — secret_scan: a secret-bearing push is denied; the secret canary must
//	         NOT leak into the audit file (no-leak canary, feeds M9a).
//	M7  — Read protection: git clone --filter=blob:none withholds the denied
//	         secrets/** blob (absent from the agent's object store) while a
//	         non-denied blob is delivered.
//	M9a — Audit: the JSONL audit file holds attributable events (agent id +
//	         verdict) for the allow, the force-push deny, and the read-protection
//	         withhold; the secret canary from the secret-bearing push does NOT
//	         appear in the audit file.
//
// HTTP-primary (the SSH frontend is covered by ssh_frontend_test.go; this test
// does not re-test SSH). Real git via harness.Git() (the insteadOf rewrite +
// Bearer header apply — raw exec.Command is used ONLY for the no-token auth
// probe, which must NOT carry the bearer header). Upstream ref states are
// asserted by reading the upstream bare repo directly (harness.UpstreamRef),
// not by proxying.
func TestE2E_V1Capstone(t *testing.T) {
	auditPath := auditFile(t)
	const agentToken = "e2e-agent-token"
	// Full v1 policy on one proxy: auth + history_protect(main) +
	// branch_pattern(main + feat/*) + secret_scan + read protection(secrets/**).
	// branch_pattern uses path.Match globs (a single-segment *), so refs/heads/
	// feat/* matches feat/e2e and feat/secret, while refs/heads/main matches the
	// protected main ref (allowed for FF, blocked for force by history_protect).
	pol := config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"history_protect": {Enabled: true, Params: map[string]any{"refs": []string{"refs/heads/main"}}},
			"branch_pattern":  {Enabled: true, Params: map[string]any{"allow": []string{"refs/heads/main", "refs/heads/feat/*"}}},
			"secret_scan":     {Enabled: true},
		},
		Read: config.ReadConfig{Deny: []string{"secrets/**"}},
	}
	h := StartWithAuthPolicyAndAudit(t, "test.git", agentToken, pol, auditPath)

	// ---- M3: Auth fail-closed, then success with token. ----
	// Without the token: ls-remote through the proxy must be rejected. We build
	// the git command by hand (NOT harness.Git) so the bearer header is absent —
	// the insteadOf rewrite still routes the request to the proxy.
	noToken := exec.Command("git",
		"-c", "url."+h.ProxyURL+".insteadOf="+h.UpstreamURL,
		"ls-remote", h.UpstreamURL+"/test.git")
	noToken.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	if out, err := noToken.CombinedOutput(); err == nil {
		t.Fatalf("M3: ls-remote without token unexpectedly succeeded; got:\n%s", out)
	}
	// With the token: ls-remote succeeds and advertises refs/heads/main.
	lsOut, err := h.Git("", "ls-remote", h.UpstreamURL+"/test.git").CombinedOutput()
	if err != nil {
		t.Fatalf("M3: ls-remote with token failed: %v\n%s", err, lsOut)
	}
	if !strings.Contains(string(lsOut), "refs/heads/main") {
		t.Fatalf("M3: ls-remote with token missing refs/heads/main; got:\n%s", lsOut)
	}

	// ---- M5: Clean FF push to feat/* reaches the upstream. ----
	// The seed upstream holds only README.md (no secrets/** blob), so a plain
	// clone through the read-protected proxy succeeds — there is nothing to
	// withhold. cloneForPush clones through the proxy via harness.Git.
	dst := cloneForPush(t, h)
	commitFile(t, dst, "work.txt", "e2e work\n", "feat: add work")
	mustRun(t, "git", "-C", dst, "checkout", "-q", "-b", "feat/e2e")
	featSHA := revParse(t, dst, "HEAD")
	h.RunGit(t, dst, "push", "-q", "origin", "feat/e2e")
	if got := h.UpstreamRef(t, "refs/heads/feat/e2e"); got != featSHA {
		t.Fatalf("M5: clean push to feat/e2e did not reach upstream: upstream=%s, pushed=%s", got, featSHA)
	}

	// ---- M5: Force-push to protected main is blocked; upstream unchanged. ----
	// Advance main with a fast-forward push first (allowed: branch_pattern
	// permits refs/heads/*, history_protect permits a FF to main).
	mustRun(t, "git", "-C", dst, "checkout", "-q", "main")
	commitFile(t, dst, "ff.txt", "ff\n", "feat: ff on main")
	h.RunGit(t, dst, "push", "-q", "origin", "main")
	afterFF := h.UpstreamRef(t, "refs/heads/main")
	// Rewrite main history: reset to the seed and make a divergent commit, so the
	// next push is a non-fast-forward (force-push) to a protected ref.
	mustRun(t, "git", "-C", dst, "reset", "--hard", "HEAD~1")
	commitFile(t, dst, "divergent.txt", "div\n", "divergent commit")
	forceOut, err := h.Git(dst, "push", "--force", "origin", "main").CombinedOutput()
	if err == nil {
		t.Fatalf("M5: force-push to protected main unexpectedly succeeded")
	}
	if !strings.Contains(string(forceOut), "force-push") {
		t.Fatalf("M5: force-push rejection missing structured reason; got:\n%s", forceOut)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != afterFF {
		t.Fatalf("M5: upstream main changed after denied force-push: %s, want %s", got, afterFF)
	}

	// ---- M6 + M9a canary: secret-bearing push denied; secret must not leak. ----
	// The canary is shaped like an AWS access key id (AKIA[0-9A-Z]{16}) so the
	// default secret_scan rule detects it; the audit no-leak canary asserts this
	// exact string never reaches the audit file.
	const secretCanary = "AKIAE2ESECRET9F3A7C2"
	mustRun(t, "git", "-C", dst, "checkout", "-q", "-b", "feat/secret")
	commitFile(t, dst, "secrets/leaked.txt", secretCanary+"\n", "feat: leak a secret")
	secretOut, err := h.Git(dst, "push", "origin", "feat/secret").CombinedOutput()
	if err == nil {
		t.Fatalf("M6: secret-bearing push unexpectedly succeeded")
	}
	if !strings.Contains(string(secretOut), "secret") {
		t.Fatalf("M6: secret rejection missing reason; got:\n%s", secretOut)
	}
	// The denied ref must NOT exist upstream (the push never reached it).
	if out, err := exec.Command("git", "-C", h.BarePath, "show-ref", "refs/heads/feat/secret").CombinedOutput(); err == nil && len(strings.TrimSpace(string(out))) != 0 {
		t.Fatalf("M6: denied secret push reached upstream: %s", out)
	}

	// ---- M7: Read protection withholds the denied blob; allowed blob fetches. ----
	// Seed a secrets/ file directly upstream (bypassing the proxy) so the proxy's
	// read-deny policy has something to withhold. The proxy's mirror refreshes on
	// every fetch, so the next clone sees the newly seeded blob.
	seedProtectedFiles(t, h) // adds docs/guide.md + secrets/secret.txt upstream.
	clone2 := t.TempDir()
	dst2 := filepath.Join(clone2, "repo")
	// Partial clone with --no-checkout: the proxy withholds the denied blob
	// from the served packfile while delivering the non-denied blobs. With
	// --no-checkout there is no working-tree pre-fetch, so the clone is
	// expected to succeed; the t.Logf is belt-and-suspenders against an
	// unexpected non-zero exit. The repo is created and the served packfile
	// is indexed regardless.
	cloneCmd := h.Git(clone2, "clone", "-q", "--filter=blob:none", "--no-checkout",
		h.UpstreamURL+"/test.git", dst2)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		t.Logf("M7: clone exit (unexpected under --no-checkout — inspect): %v\n%s", err, out)
	}
	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:secrets/secret.txt"))
	readmeOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:README.md"))
	present := presentObjectOIDs(t, dst2)
	if present[secretOID] {
		t.Errorf("M7: DENY LEAK: denied secret blob %s is present in the clone's object store (packfile withholding failed)", secretOID)
	}
	if !present[readmeOID] {
		t.Errorf("M7: non-denied blob %s (README.md) missing from clone — allowed blobs must fetch", readmeOID)
	}

	// ---- M9a: Audit — attributable events + no-leak canary. ----
	events := readAuditEvents(t, auditPath)
	// Allow event for the clean feat/e2e push.
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-receive-pack" && e.Verdict == "allow" &&
			len(e.Refs) > 0 && e.Refs[0].Ref == "refs/heads/feat/e2e"
	}) {
		t.Fatalf("M9a: no push allow audit event for feat/e2e; events=%+v", events)
	}
	// Deny event for the force-push to main (structured reason recorded).
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-receive-pack" && e.Verdict == "deny" &&
			len(e.Refs) > 0 && e.Refs[0].Ref == "refs/heads/main"
	}) {
		t.Fatalf("M9a: no push deny audit event for force-push to main; events=%+v", events)
	}
	// Read-protection withhold deny event with DeniedPaths.
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-upload-pack" && e.Verdict == "deny" &&
			containsString(e.DeniedPaths, "secrets/secret.txt")
	}) {
		t.Fatalf("M9a: no read-protection deny audit event with DeniedPaths; events=%+v", events)
	}
	// Agent id present on the push events (auth wired → agent-1).
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Agent == "agent-1" && e.Service == "git-receive-pack"
	}) {
		t.Fatalf("M9a: no push audit event attributed to agent-1; events=%+v", events)
	}
	// The secret-bearing push (feat/secret) MUST have been audited as a deny.
	// This anchors the no-leak canary below: it proves the secret actually
	// reached the audit-recording path (the redaction point), so the canary is
	// non-vacuous — without this, a regression that skipped audit recording on
	// a secret-scan deny would make the canary pass for the wrong reason (no
	// event means nothing to leak).
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-receive-pack" && e.Verdict == "deny" &&
			len(e.Refs) > 0 && e.Refs[0].Ref == "refs/heads/feat/secret"
	}) {
		t.Fatalf("M9a: no secret-scan deny audit event for feat/secret — canary would be vacuous; events=%+v", events)
	}
	// No-leak canary: the secret string from the secret-bearing push MUST NOT
	// appear in the audit file (the rules redact secrets; the audit records only
	// generic redacted reason strings — never blob content).
	auditBytes, _ := os.ReadFile(auditPath)
	if strings.Contains(string(auditBytes), secretCanary) {
		t.Fatalf("M9a: audit file leaked the secret canary: %q", auditBytes)
	}
}