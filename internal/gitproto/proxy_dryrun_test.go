package gitproto_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/port"
)

// buildPushRequestWithOld builds a receive-pack request whose "old" OID is old
// (a non-zero ref update, not a create). Used to exercise the ancestry-check
// path: an old OID absent from the mirror makes IsAncestor error, producing an
// inspection-failure deny (EnforceReceivePack returns deny + non-nil error).
func buildPushRequestWithOld(t *testing.T, ref, old, newSHA string, pack []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	line := old + " " + newSHA + " " + ref + "\x00report-status\n"
	if err := e.EncodeString(line); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if pack != nil {
		buf.Write(pack)
	}
	return buf.Bytes()
}

// fakeAlertSink records alerts for assertions. err, if non-nil, is returned
// from Alert to exercise the best-effort path (the proxy must log the error and
// proceed — the verdict/forward is unchanged).
type fakeAlertSink struct {
	mu      sync.Mutex
	alerts  []port.Alert
	err     error
}

func (s *fakeAlertSink) Alert(ctx context.Context, a port.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
	return s.err
}

func (s *fakeAlertSink) snapshot() []port.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]port.Alert, len(s.alerts))
	copy(cp, s.alerts)
	return cp
}

// commonDryRunSetup builds a push that the engine DENIES (empty branch_pattern
// allow list → deny all) with a real mirror opener, returning the proxy (with
// enforcement wired) and the request body. Caller wires audit/alert sinks and
// dry-run as needed.
func commonDryRunSetup(t *testing.T) (*gitproto.Proxy, []byte, *fakeUpstream, string) {
	t.Helper()
	gitBinary(t)
	ref := "refs/heads/main"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	body := buildPushRequestWithNew(t, ref, tip, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": nil}, // empty allow list → deny all (clean engine deny)
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	proxy.SetTransport("http")
	return proxy, body, up, ref
}

// TestProxyDryRun_DenyForwardsAndAlerts asserts that with dry-run ON, a clean
// engine deny is FORWARDED to the upstream (upstream receives the bytes), the
// audit event records verdict=deny + DryRun=true, and an alert fires with
// DryRun=true.
func TestProxyDryRun_DenyForwardsAndAlerts(t *testing.T) {
	proxy, body, up, _ := commonDryRunSetup(t)
	audit := &fakeAuditSink{}
	alerts := &fakeAlertSink{}
	proxy.SetAuditSink(audit)
	proxy.SetAlertSink(alerts)
	proxy.SetDryRun(true)

	var out bytes.Buffer
	if err := proxy.ReceivePack(context.Background(), "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	// Dry-run forwards the denied push to the upstream.
	if len(up.forwarded) != len(body) {
		t.Fatalf("dry-run must forward denied push; got %d bytes forwarded, want %d", len(up.forwarded), len(body))
	}
	// Audit: one deny event with DryRun=true.
	events := audit.snapshot()
	var deny *port.AuditEvent
	for i := range events {
		if events[i].Verdict == "deny" {
			deny = &events[i]
			break
		}
	}
	if deny == nil {
		t.Fatalf("no deny audit event; events=%+v", events)
	}
	if !deny.DryRun {
		t.Fatalf("deny audit DryRun: %v want true", deny.DryRun)
	}
	// Alert: one alert with DryRun=true, verdict=deny.
	a := alerts.snapshot()
	if len(a) != 1 {
		t.Fatalf("want 1 alert, got %d", len(a))
	}
	if a[0].Verdict != "deny" {
		t.Fatalf("alert verdict: %q want deny", a[0].Verdict)
	}
	if !a[0].DryRun {
		t.Fatalf("alert DryRun: %v want true", a[0].DryRun)
	}
}

// TestProxyDryRun_EnforcedDenyBlocksAndAlerts asserts that with dry-run OFF,
// the same denied push is BLOCKED (upstream unchanged, no forward), the audit
// event records verdict=deny + DryRun=false, and an alert fires with
// DryRun=false.
func TestProxyDryRun_EnforcedDenyBlocksAndAlerts(t *testing.T) {
	proxy, body, up, _ := commonDryRunSetup(t)
	audit := &fakeAuditSink{}
	alerts := &fakeAlertSink{}
	proxy.SetAuditSink(audit)
	proxy.SetAlertSink(alerts)
	// dry-run OFF (default).

	var out bytes.Buffer
	if err := proxy.ReceivePack(context.Background(), "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	// Enforced: must NOT forward.
	if len(up.forwarded) != 0 {
		t.Fatalf("enforced deny must not forward; got %d bytes", len(up.forwarded))
	}
	events := audit.snapshot()
	var deny *port.AuditEvent
	for i := range events {
		if events[i].Verdict == "deny" {
			deny = &events[i]
			break
		}
	}
	if deny == nil {
		t.Fatalf("no deny audit event")
	}
	if deny.DryRun {
		t.Fatalf("enforced deny audit DryRun: %v want false", deny.DryRun)
	}
	a := alerts.snapshot()
	if len(a) != 1 {
		t.Fatalf("want 1 alert, got %d", len(a))
	}
	if a[0].DryRun {
		t.Fatalf("enforced deny alert DryRun: %v want false", a[0].DryRun)
	}
}

// TestProxyDryRun_AllowNoAlert asserts an allowed push does NOT fire an alert
// (alerts fire on deny only), and dry-run does not change allows.
func TestProxyDryRun_AllowNoAlert(t *testing.T) {
	gitBinary(t)
	ref := "refs/heads/feat/x"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	body := buildPushRequestWithNew(t, ref, tip, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}}, // allow feat/*
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	proxy.SetTransport("http")
	audit := &fakeAuditSink{}
	alerts := &fakeAlertSink{}
	proxy.SetAuditSink(audit)
	proxy.SetAlertSink(alerts)
	proxy.SetDryRun(true) // dry-run does not change allows

	var out bytes.Buffer
	if err := proxy.ReceivePack(context.Background(), "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != len(body) {
		t.Fatalf("allow must forward; got %d, want %d", len(up.forwarded), len(body))
	}
	if len(alerts.snapshot()) != 0 {
		t.Fatalf("allow must not fire an alert; got %+v", alerts.snapshot())
	}
}

// TestProxyDryRun_InspectionErrorStillFailsClosed asserts that an inspection
// error deny (the engine could not evaluate — here a push with a ref whose
// ancestry cannot be verified because the mirror lacks the old object) STILL
// fail-closes in dry-run: no forward, DryRun=false on the audit/alert. Dry-run
// only softens POLICY denies, not inspection failures.
func TestProxyDryRun_InspectionErrorStillFailsClosed(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	// Build a push whose "old" OID does not exist in the mirror, so the ancestry
	// check (IsAncestor) errors → EnforceReceivePack returns a deny + non-nil
	// error (inspection failure), which must fail-closed even in dry-run.
	ref := "refs/heads/main"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	pack := packObjects(t, dir, tip)
	// "old" is a nonexistent OID → ancestry check errors → inspection-failure deny.
	body := buildPushRequestWithOld(t, ref, "1111111111111111111111111111111111111111", tip, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/*"}}, // would allow if inspection succeeded
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	proxy.SetTransport("http")
	audit := &fakeAuditSink{}
	alerts := &fakeAlertSink{}
	proxy.SetAuditSink(audit)
	proxy.SetAlertSink(alerts)
	proxy.SetDryRun(true) // dry-run must NOT soften the inspection-failure deny

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	// Inspection-failure deny must fail-closed even in dry-run: NO forward.
	if len(up.forwarded) != 0 {
		t.Fatalf("inspection-error deny must not forward in dry-run; got %d bytes", len(up.forwarded))
	}
	events := audit.snapshot()
	var deny *port.AuditEvent
	for i := range events {
		if events[i].Verdict == "deny" {
			deny = &events[i]
			break
		}
	}
	if deny == nil {
		t.Fatalf("no deny audit event (inspection failure)")
	}
	if deny.DryRun {
		t.Fatalf("inspection-error deny audit DryRun: %v want false (fail-closed)", deny.DryRun)
	}
	a := alerts.snapshot()
	if len(a) != 1 {
		t.Fatalf("want 1 alert for inspection-failure deny, got %d", len(a))
	}
	if a[0].DryRun {
		t.Fatalf("inspection-error deny alert DryRun: %v want false", a[0].DryRun)
	}
}

// TestProxyDryRun_NilAlertSinkNoOp asserts a nil alert sink (alerts off)
// preserves the existing behavior — no panic, deny still denies, dry-run still
// forwards.
func TestProxyDryRun_NilAlertSinkNoOp(t *testing.T) {
	proxy, body, up, _ := commonDryRunSetup(t)
	audit := &fakeAuditSink{}
	proxy.SetAuditSink(audit)
	proxy.SetDryRun(true)
	// No SetAlertSink → nil alert sink → no alerts, no panic.

	var out bytes.Buffer
	if err := proxy.ReceivePack(context.Background(), "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != len(body) {
		t.Fatalf("dry-run must forward even with nil alert sink; got %d, want %d", len(up.forwarded), len(body))
	}
}

// TestProxyDryRun_BestEffortAlertErrorDoesNotBlock asserts that when the alert
// sink returns an error, the proxy does NOT change the verdict or block the
// op — the dry-run deny still forwards, the audit event still records, and the
// alert error is swallowed (best-effort, binding).
func TestProxyDryRun_BestEffortAlertErrorDoesNotBlock(t *testing.T) {
	proxy, body, up, _ := commonDryRunSetup(t)
	audit := &fakeAuditSink{}
	alerts := &fakeAlertSink{err: errors.New("webhook down")}
	proxy.SetAuditSink(audit)
	proxy.SetAlertSink(alerts)
	proxy.SetDryRun(true)

	var out bytes.Buffer
	if err := proxy.ReceivePack(context.Background(), "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	// Alert error must NOT block the dry-run forward.
	if len(up.forwarded) != len(body) {
		t.Fatalf("alert error must not block dry-run forward; got %d, want %d", len(up.forwarded), len(body))
	}
	if len(audit.snapshot()) == 0 {
		t.Fatalf("audit must still record despite alert error")
	}
	if len(alerts.snapshot()) == 0 {
		t.Fatalf("alert sink must still receive the alert (error is returned AFTER delivery attempt)")
	}
}

// TestProxyDryRun_NoLeakCanary asserts the alert payload does NOT contain a
// secret value present in the pushed content. The Alert carries only generic
// reasons (secret_scan redacts the matched secret in its reason message), so
// the alert payload is leak-free even though the webhook leaves the proxy.
func TestProxyDryRun_NoLeakCanary(t *testing.T) {
	// Reuse the secret_scan rule which denies a push carrying a secret. The
	// rule's reason message is redacted (the secret value is masked), so the
	// alert fired on the deny carries no secret. This is the load-bearing
	// no-leak assertion for the alert payload (mirrors the Task 12 audit canary).
	secret := "AKIAIOSFODNN7EXAMPLE"
	ctx := context.Background()

	ref := "refs/heads/main"
	dir, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	_ = tip
	bareRoot := t.TempDir()
	bare := bareRoot + "/repo.git"
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, dir, "push", "-q", "file://"+bare, "main")
	testBareRoot = bareRoot

	// Commit a file with the secret; the push carries it in the packfile.
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o755); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	writeFile(t, dir, "secrets/creds.txt", secret+"\n")
	mustGit(t, dir, "add", "secrets/creds.txt")
	mustGit(t, dir, "commit", "-q", "-m", "leak secret")
	tip2 := revParseHead(t, dir)
	pack := packObjects(t, dir, tip2)
	body := buildPushRequestWithNew(t, ref, tip2, pack)

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	eng := enforceEngine(t, map[string]map[string]any{
		"secret_scan":    {"enabled": "true"},
		"branch_pattern": {"allow": []string{"refs/heads/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	proxy.SetTransport("http")
	alerts := &fakeAlertSink{}
	proxy.SetAlertSink(alerts)
	proxy.SetDryRun(true)

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	a := alerts.snapshot()
	if len(a) == 0 {
		t.Fatalf("expected an alert for the secret_scan deny")
	}
	// Reassemble the alert payload as the webhook sink would marshal it, and
	// assert the secret value is NOT present.
	var payload bytes.Buffer
	for _, al := range a {
		payload.WriteString(strings.Join(al.Reasons, " "))
		for _, r := range al.Refs {
			payload.WriteString(r.Ref)
			payload.WriteString(r.Old)
			payload.WriteString(r.New)
		}
		for _, p := range al.DeniedPaths {
			payload.WriteString(p)
		}
		for _, o := range al.DeniedOIDs {
			payload.WriteString(o)
		}
	}
	if strings.Contains(payload.String(), secret) {
		t.Fatalf("alert payload leaked secret value: %q", payload.String())
	}
}