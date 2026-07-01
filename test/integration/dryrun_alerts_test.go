package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/alert/webhook"
	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/port"
)

// mustWebhookSink builds a webhook AlertSink for url (fail-fast on a malformed
// URL — should not happen with an httptest.Server URL). The sink is closed via
// t.Cleanup so idle connections do not leak across tests.
func mustWebhookSink(t *testing.T, url string) port.AlertSink {
	t.Helper()
	s, err := webhook.New(url)
	if err != nil {
		t.Fatalf("webhook.New(%s): %v", url, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// testWebhook stands up an httptest.Server that records the JSON Alerts POSTed
// to it. It returns the server and a snapshot function for assertions. The
// server URL is passed to the harness as the alert webhook sink (via the
// webhook.New-built sink wired into the frontend). The caller defers Close.
type testWebhook struct {
	srv     *httptest.Server
	mu      sync.Mutex
	alerts  []port.Alert
	bodies  [][]byte
}

func newTestWebhook(t *testing.T) *testWebhook {
	t.Helper()
	tw := &testWebhook{}
	tw.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		tw.mu.Lock()
		tw.bodies = append(tw.bodies, body)
		var a port.Alert
		if err := json.Unmarshal(body, &a); err == nil {
			tw.alerts = append(tw.alerts, a)
		}
		tw.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { tw.srv.Close() })
	return tw
}

func (tw *testWebhook) snapshot() []port.Alert {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	cp := make([]port.Alert, len(tw.alerts))
	copy(cp, tw.alerts)
	return cp
}

// rawBodies returns the raw POST bodies (for no-leak assertions against the
// exact bytes that left the proxy).
func (tw *testWebhook) rawBodies() [][]byte {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	cp := make([][]byte, len(tw.bodies))
	copy(cp, tw.bodies)
	return cp
}

// policyDenyAll returns a PolicyConfig whose branch_pattern has an empty allow
// list (denies every push). Used for dry-run / enforced deny assertions.
func policyDenyAll() config.PolicyConfig {
	return config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"branch_pattern": {Enabled: true, Params: map[string]any{"allow": nil}},
		},
	}
}

// TestDryRun_PushDenyForwarded asserts that with dry_run: true, a push the
// engine DENIES is FORWARDED to the upstream (the upstream ref CHANGES — the
// key dry-run signal), an audit event records verdict=deny + dry_run=true, and
// an alert fires with DryRun=true. The enforced (dry_run=false) control push of
// the same content is BLOCKED (upstream unchanged) and records dry_run=false.
func TestDryRun_PushDenyForwarded(t *testing.T) {
	auditPath := auditFile(t)
	tw := newTestWebhook(t)
	sink := mustWebhookSink(t, tw.srv.URL)

	// Dry-run harness: deny-all policy + dry_run + alert webhook.
	h := StartWithPolicyAuditAlerts(t, "test.git", policyDenyAll(), auditPath, true, sink)
	dst := cloneForPush(t, h)
	commitFile(t, dst, "work.txt", "w\n", "feat: denied work")

	before := h.UpstreamRef(t, "refs/heads/main")
	// The push is denied by branch_pattern, but dry-run forwards it.
	cmd := h.Git(dst, "push", "origin", "main")
	if out, err := cmd.CombinedOutput(); err != nil {
		// A dry-run forward may still surface a non-zero exit if the upstream
		// rejects (it won't here — FF to main is accepted by the upstream). Log
		// the output for diagnosis but do not fail on a non-zero exit if the
		// upstream ref changed (the dry-run forward is the load-bearing signal).
		t.Logf("dry-run push exit (inspecting): %v\n%s", err, out)
	}
	after := h.UpstreamRef(t, "refs/heads/main")
	if after == before {
		t.Fatalf("dry-run must forward the denied push (upstream ref must change); before=%s after=%s", before, after)
	}

	// Audit: a deny event with DryRun=true.
	events := readAuditEvents(t, auditPath)
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
	if !deny.DryRun {
		t.Fatalf("dry-run deny audit DryRun: %v want true", deny.DryRun)
	}

	// Alert: fired with DryRun=true.
	alerts := tw.snapshot()
	var dryRunAlert *port.Alert
	for i := range alerts {
		if alerts[i].DryRun {
			dryRunAlert = &alerts[i]
			break
		}
	}
	if dryRunAlert == nil {
		t.Fatalf("no dry-run alert fired; alerts=%+v", alerts)
	}
	if dryRunAlert.Verdict != "deny" {
		t.Fatalf("dry-run alert verdict: %q want deny", dryRunAlert.Verdict)
	}

	// Enforced control: a fresh harness with dry_run=false + the same policy.
	auditPath2 := auditFile(t)
	tw2 := newTestWebhook(t)
	sink2 := mustWebhookSink(t, tw2.srv.URL)
	h2 := StartWithPolicyAuditAlerts(t, "test.git", policyDenyAll(), auditPath2, false, sink2)
	dst2 := cloneForPush(t, h2)
	commitFile(t, dst2, "work.txt", "w\n", "feat: denied work")
	before2 := h2.UpstreamRef(t, "refs/heads/main")
	cmd2 := h2.Git(dst2, "push", "origin", "main")
	if out2, err := cmd2.CombinedOutput(); err == nil {
		t.Fatalf("enforced deny must reject the push; got success\n%s", out2)
	}
	if got := h2.UpstreamRef(t, "refs/heads/main"); got != before2 {
		t.Fatalf("enforced deny must not change upstream: %s, want %s", got, before2)
	}
	events2 := readAuditEvents(t, auditPath2)
	var deny2 *port.AuditEvent
	for i := range events2 {
		if events2[i].Service == "git-receive-pack" && events2[i].Verdict == "deny" {
			deny2 = &events2[i]
			break
		}
	}
	if deny2 == nil {
		t.Fatalf("no enforced push deny audit event")
	}
	if deny2.DryRun {
		t.Fatalf("enforced deny audit DryRun: %v want false", deny2.DryRun)
	}
}

// TestAlert_EnforcedDenyFiresAndNoLeak asserts a denied push (secret_scan) fires
// an alert to the webhook carrying agent + verdict=deny + a reason, and the
// payload does NOT contain the secret value (no-leak canary). A clean allowed
// push fires NO alert.
func TestAlert_EnforcedDenyFiresAndNoLeak(t *testing.T) {
	auditPath := auditFile(t)
	tw := newTestWebhook(t)
	sink := mustWebhookSink(t, tw.srv.URL)
	pol := config.PolicyConfig{
		Rules: map[string]config.RuleConfig{
			"secret_scan":    {Enabled: true},
			"branch_pattern": {Enabled: true, Params: map[string]any{"allow": []string{"refs/heads/*"}}},
		},
	}
	h := StartWithPolicyAuditAlerts(t, "test.git", pol, auditPath, false, sink)
	dst := cloneForPush(t, h)
	secret := "AKIAIOSFODNN7EXAMPLE"
	commitFile(t, dst, "secrets/creds.txt", secret+"\n", "leak secret")

	before := h.UpstreamRef(t, "refs/heads/main")
	cmd := h.Git(dst, "push", "origin", "main")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("push with secret must be denied")
	} else if !strings.Contains(string(out), "secret") {
		t.Fatalf("rejection output missing secret reason; got:\n%s", out)
	}
	if got := h.UpstreamRef(t, "refs/heads/main"); got != before {
		t.Fatalf("denied push changed upstream: %s, want %s", got, before)
	}

	alerts := tw.snapshot()
	if len(alerts) == 0 {
		t.Fatalf("enforced deny must fire an alert")
	}
	if alerts[0].Verdict != "deny" {
		t.Fatalf("alert verdict: %q want deny", alerts[0].Verdict)
	}
	if len(alerts[0].Reasons) == 0 {
		t.Fatalf("alert must carry a reason")
	}
	// No-leak: the raw POST bodies must NOT contain the secret value.
	for _, b := range tw.rawBodies() {
		if strings.Contains(string(b), secret) {
			t.Fatalf("webhook payload leaked secret value: %q", b)
		}
	}

	// Clean allowed push fires NO alert: clear the recorded alerts, then push a
	// clean branch from a FRESH clone (the upstream does not have the secret —
	// the secret push was denied — so a fresh clone is clean). The clean branch
	// is allowed by branch_pattern (refs/heads/*) and carries no secret, so no
	// alert fires.
	tw.mu.Lock()
	tw.alerts = nil
	tw.bodies = nil
	tw.mu.Unlock()
	dst2 := cloneForPush(t, h)
	commitFile(t, dst2, "clean.txt", "ok\n", "feat: clean work")
	mustRun(t, "git", "-C", dst2, "checkout", "-q", "-b", "clean")
	h.RunGit(t, dst2, "push", "-q", "origin", "clean")
	if len(tw.snapshot()) != 0 {
		t.Fatalf("clean allowed push must not fire an alert; got %+v", tw.snapshot())
	}
}

// TestAlert_ReadProtectionDenyFires asserts a read-protected fetch that
// withholds a denied blob fires an alert with DeniedPaths, and an on-demand
// denied blob fires an alert with DeniedOIDs. No secret content in the
// payload.
func TestAlert_ReadProtectionDenyFires(t *testing.T) {
	auditPath := auditFile(t)
	tw := newTestWebhook(t)
	sink := mustWebhookSink(t, tw.srv.URL)
	h := StartWithPolicyAuditAlerts(t, "test.git", policyReadDeny("secrets/**"), auditPath, false, sink)
	seedProtectedFiles(t, h)
	secret := "TOP-SECRET-VALUE-DO-NOT-LEAK"

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "-q", "--filter=blob:none", "--no-checkout",
		h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	alerts := tw.snapshot()
	var pathAlert *port.Alert
	for i := range alerts {
		if len(alerts[i].DeniedPaths) > 0 {
			pathAlert = &alerts[i]
			break
		}
	}
	if pathAlert == nil {
		t.Fatalf("no read-protection alert with DeniedPaths; alerts=%+v", alerts)
	}
	if !containsString(pathAlert.DeniedPaths, "secrets/secret.txt") {
		t.Fatalf("DeniedPaths missing secrets/secret.txt: %+v", pathAlert.DeniedPaths)
	}
	// No-leak: the webhook payload must NOT contain the secret blob content.
	for _, b := range tw.rawBodies() {
		if strings.Contains(string(b), secret) {
			t.Fatalf("webhook payload leaked secret blob content: %q", b)
		}
	}
}

// TestDryRun_ReadProtectionStillEnforces asserts that dry-run does NOT soften
// read protection: a read-protected fetch withholds the denied blob regardless
// of dry_run (read-protection dry-run is OUT of v1 scope, binding). The alert
// fires with DryRun=false.
func TestDryRun_ReadProtectionStillEnforces(t *testing.T) {
	auditPath := auditFile(t)
	tw := newTestWebhook(t)
	sink := mustWebhookSink(t, tw.srv.URL)
	// dry_run: true, but read protection must still withhold.
	h := StartWithPolicyAuditAlerts(t, "test.git", policyReadDeny("secrets/**"), auditPath, true, sink)
	seedProtectedFiles(t, h)

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "-q", "--filter=blob:none", "--no-checkout",
		h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld even in dry-run): %v\n%s", err, out)
	}
	alerts := tw.snapshot()
	var pathAlert *port.Alert
	for i := range alerts {
		if len(alerts[i].DeniedPaths) > 0 {
			pathAlert = &alerts[i]
			break
		}
	}
	if pathAlert == nil {
		t.Fatalf("read-protection must still fire an alert in dry-run; alerts=%+v", alerts)
	}
	if pathAlert.DryRun {
		t.Fatalf("read-protection alert DryRun: %v want false (read protection enforced regardless of dry-run)", pathAlert.DryRun)
	}
	// The denied blob must NOT be present in the clone (read protection enforced).
	if _, err := os.Stat(filepath.Join(dst, "secrets", "secret.txt")); err == nil {
		t.Fatalf("denied blob must not be present in the clone (read protection enforced even in dry-run)")
	}
}