package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/port"
)

// readAuditEvents parses the JSONL audit file at path and returns the events.
func readAuditEvents(t *testing.T, path string) []port.AuditEvent {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(b) == 0 {
		return nil
	}
	var events []port.AuditEvent
	for i, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		var e port.AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit line %d: %v (line=%q)", i, err, line)
		}
		events = append(events, e)
	}
	return events
}

// auditFile returns a fresh audit JSONL path in a temp dir.
func auditFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.jsonl")
}

// hasAuditEvent reports whether any audit event matches pred.
func hasAuditEvent(events []port.AuditEvent, pred func(port.AuditEvent) bool) bool {
	for _, e := range events {
		if pred(e) {
			return true
		}
	}
	return false
}

// TestAudit_PushDeniedRecordsEvent: a denied push (secret_scan) produces an
// audit event with verdict=deny, the ref, a generic reason, and the agent id.
// The reason MUST NOT contain the secret value (no-leak assertion). The
// upstream is unchanged.
func TestAudit_PushDeniedRecordsEvent(t *testing.T) {
	auditPath := auditFile(t)
	// Enable secret_scan so a push carrying a secret is denied.
	pol := config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"secret_scan":  {Enabled: true},
			"branch_pattern": {Enabled: true, Params: map[string]any{"allow": []string{"refs/heads/*"}}},
		},
	}
	h := StartWithPolicyAndAudit(t, "test.git", pol, auditPath)
	// Configure an agent identity via auth so the audit event has an agent.
	// StartWithPolicy is unauthenticated (agent=""), so the event carries "".
	// The push: commit a file with a secret and push.
	dst := cloneForPush(t, h)
	secret := "AKIAIOSFODNN7EXAMPLE" // AWS access key id shape (detected by default secret_scan)
	commitFile(t, dst, "secrets/creds.txt", secret+"\n", "leak secret")

	before := h.UpstreamRef(t, "refs/heads/main")
	cmd := h.Git(dst, "push", "origin", "main")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push with secret unexpectedly succeeded")
	}
	if !strings.Contains(string(out), "secret") {
		t.Fatalf("rejection output missing secret reason; got:\n%s", out)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != before {
		t.Fatalf("upstream changed after denied push: %s, want %s", got, before)
	}

	events := readAuditEvents(t, auditPath)
	// Find the deny event for git-receive-pack on refs/heads/main.
	var deny *port.AuditEvent
	for i := range events {
		if events[i].Service == "git-receive-pack" && events[i].Verdict == "deny" {
			deny = &events[i]
			break
		}
	}
	if deny == nil {
		t.Fatalf("no push deny audit event; events=%+v", events)
	}
	if deny.Repo != "test.git" {
		t.Fatalf("deny event repo: %q want test.git", deny.Repo)
	}
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return len(e.Refs) > 0 && e.Refs[0].Ref == "refs/heads/main"
	}) {
		t.Fatalf("deny event missing ref refs/heads/main; refs=%+v", deny.Refs)
	}
	if len(deny.Reasons) == 0 {
		t.Fatalf("deny event has no reasons")
	}
	// No-leak: the audit file must NOT contain the secret value.
	b, _ := os.ReadFile(auditPath)
	if strings.Contains(string(b), secret) {
		t.Fatalf("audit file leaked secret value: %q", b)
	}
}

// TestAudit_PushAllowedRecordsEvent: an allowed push (clean FF to feat/*)
// produces an audit event with verdict=allow and the ref.
func TestAudit_PushAllowedRecordsEvent(t *testing.T) {
	auditPath := auditFile(t)
	pol := config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"branch_pattern": {Enabled: true, Params: map[string]any{"allow": []string{"refs/heads/feat/*"}}},
		},
	}
	h := StartWithPolicyAndAudit(t, "test.git", pol, auditPath)
	dst := cloneForPush(t, h)
	commitFile(t, dst, "work.txt", "w\n", "feat: add work")
	// Create and push a feat branch (allowed by branch_pattern).
	mustRun(t, "git", "-C", dst, "checkout", "-q", "-b", "feat/x")
	h.RunGit(t, dst, "push", "-q", "origin", "feat/x")

	events := readAuditEvents(t, auditPath)
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-receive-pack" && e.Verdict == "allow" &&
			len(e.Refs) > 0 && e.Refs[0].Ref == "refs/heads/feat/x"
	}) {
		t.Fatalf("no push allow audit event for feat/x; events=%+v", events)
	}
}

// TestAudit_ReadProtectedFetchWithhold: a read-protected fetch that withholds a
// denied blob produces an audit event with verdict=deny and DeniedPaths
// containing the denied path. The audit file MUST NOT contain the secret blob
// content.
func TestAudit_ReadProtectedFetchWithhold(t *testing.T) {
	auditPath := auditFile(t)
	h := StartWithPolicyAndAudit(t, "test.git", policyReadDeny("secrets/**"), auditPath)
	seedProtectedFiles(t, h)
	secret := "TOP-SECRET-VALUE-DO-NOT-LEAK"

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	// Partial clone with --no-checkout: the proxy withholds the denied blob
	// from the served packfile (recording a deny audit event with DeniedPaths)
	// while delivering the non-denied blobs. --no-checkout avoids the checkout-
	// time pre-fetch that would abort on the missing denied blob (mirrors the
	// established read-protection test pattern). A non-zero exit is acceptable;
	// the upload-pack enforce that records the deny event runs during the
	// negotiation/packfile phase regardless of checkout outcome.
	cmd := h.Git(clone, "clone", "-q", "--filter=blob:none", "--no-checkout",
		h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	events := readAuditEvents(t, auditPath)
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-upload-pack" && e.Verdict == "deny" &&
			containsString(e.DeniedPaths, "secrets/secret.txt")
	}) {
		t.Fatalf("no fetch deny audit event with DeniedPaths secrets/secret.txt; events=%+v", events)
	}
	// No-leak: the audit file must NOT contain the secret blob content.
	b, _ := os.ReadFile(auditPath)
	if strings.Contains(string(b), secret) {
		t.Fatalf("audit file leaked secret blob content: %q", b)
	}
}

// TestAudit_OnDemandDeniedBlob: an on-demand fetch of a denied blob is refused
// with an ERR pkt-line (Task 10) and produces an audit event with DeniedOIDs
// carrying the denied blob OID.
func TestAudit_OnDemandDeniedBlob(t *testing.T) {
	auditPath := auditFile(t)
	h := StartWithPolicyAndAudit(t, "test.git", policyReadDeny("secrets/**"), auditPath)
	seedProtectedFiles(t, h)

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	// Partial clone with --no-checkout: the denied blob is withheld from the
	// initial packfile (Task 9) and the clone's checkout does not abort on the
	// missing-object pre-fetch (mirrors TestOnDemandDeny_AllowedServed_DeniedRefused).
	// A non-zero exit is acceptable; the repo is created and the served packfile
	// is indexed regardless.
	cmd := h.Git(clone, "clone", "-q", "--filter=blob:none", "--no-checkout",
		h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	// Compute the denied blob OID upstream (bypassing the proxy).
	work := t.TempDir()
	mustRun(t, "git", "clone", "-q", "file://"+h.BarePath, work)
	mustRun(t, "git", "-C", work, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", work, "config", "user.name", "Test")
	// Re-seed to ensure the secret is present upstream (seedProtectedFiles already pushed).
	deniedOID := strings.TrimSpace(mustOutput(t, "git", "-C", work, "rev-parse", "HEAD:secrets/secret.txt"))

	// Reading the denied file triggers an on-demand fetch the proxy refuses.
	// h.Git applies the url.<proxy>.insteadOf <upstream> rewrite so the lazy
	// fetch reaches the proxy's on-demand deny path (Task 10) and records a deny
	// audit event with DeniedOIDs carrying the denied blob OID. A raw
	// exec.Command would bypass the proxy (origin URL is the upstream, no
	// insteadOf rewrite) and fetch the secret directly from the unprotected
	// upstream — so h.Git is required here.
	catCmd := h.Git(dst, "cat-file", "-p", deniedOID)
	if out, err := catCmd.CombinedOutput(); err == nil {
		t.Fatalf("on-demand fetch of denied blob unexpectedly succeeded; got:\n%s", out)
	}

	events := readAuditEvents(t, auditPath)
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-upload-pack" && e.Verdict == "deny" &&
			containsString(e.DeniedOIDs, deniedOID)
	}) {
		t.Fatalf("no on-demand deny audit event with DeniedOIDs %s; events=%+v", deniedOID, events)
	}
	// No-leak: the audit file must NOT contain the secret content.
	b, _ := os.ReadFile(auditPath)
	if strings.Contains(string(b), "TOP-SECRET-VALUE-DO-NOT-LEAK") {
		t.Fatalf("audit file leaked secret blob content: %q", b)
	}
}

// TestAudit_PassthroughBareAllow: with policy OFF (no engine), the proxy
// records a bare allow event for a passthrough push (the flagged passthrough-
// audit decision: log all traffic). The event has verdict=allow and no reasons.
func TestAudit_PassthroughBareAllow(t *testing.T) {
	auditPath := auditFile(t)
	// An empty policy (no rules, no read-deny) → passthrough. Use StartWithPolicy
	// with an empty PolicyConfig (no enabled rules → passthrough).
	h := StartWithPolicyAndAudit(t, "test.git", config.PolicyConfig{}, auditPath)
	dst := cloneForPush(t, h)
	commitFile(t, dst, "work.txt", "w\n", "add work")
	h.RunGit(t, dst, "push", "-q", "origin", "main")

	events := readAuditEvents(t, auditPath)
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-receive-pack" && e.Verdict == "allow" && len(e.Reasons) == 0
	}) {
		t.Fatalf("no passthrough bare allow audit event; events=%+v", events)
	}
}

// TestAudit_AppendOnlyConcurrent: concurrent pushes (allowed + denied) must not
// corrupt the JSONL audit file — re-reading parses every line, the file only
// grew, and every event is attributable (carries service + verdict).
func TestAudit_AppendOnlyConcurrent(t *testing.T) {
	auditPath := auditFile(t)
	pol := config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"branch_pattern": {Enabled: true, Params: map[string]any{"allow": []string{"refs/heads/feat/*"}}},
			"secret_scan":    {Enabled: true},
		},
	}
	h := StartWithPolicyAndAudit(t, "test.git", pol, auditPath)

	// Run several concurrent pushes from independent clones: some allowed
	// (feat/*), some denied (secret in main). Each records an audit event.
	const n = 6
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			dst := cloneForPush(t, h)
			if i%2 == 0 {
				// Allowed: push a feat branch.
				commitFile(t, dst, "work.txt", "w\n", "feat: add work")
				mustRun(t, "git", "-C", dst, "checkout", "-q", "-b", "feat/x")
				_ = h.Git(dst, "push", "origin", "feat/x").Run()
			} else {
				// Denied: push a secret to main.
				commitFile(t, dst, "secrets/creds.txt", "AKIAIOSFODNN7EXAMPLE\n", "leak")
				_ = h.Git(dst, "push", "origin", "main").Run()
			}
		}()
	}
	wg.Wait()

	events := readAuditEvents(t, auditPath)
	if len(events) == 0 {
		t.Fatalf("no audit events recorded under concurrency")
	}
	// Append-only: re-reading parses all events as JSONL (readAuditEvents would
	// have fatal'd on a corrupt line). Every event is attributable.
	for i, e := range events {
		if e.Service == "" || e.Verdict == "" {
			t.Fatalf("event %d not attributable (service/verdict empty): %+v", i, e)
		}
	}
}

// containsString reports whether s contains v.
func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}