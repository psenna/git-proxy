package gitproto_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/port"
)

// fakeAuditSink is a port.AuditSink that records events for audit assertions.
// err, if non-nil, is returned from Record to exercise the best-effort path
// (the proxy must log the error and proceed — the verdict is unchanged).
type fakeAuditSink struct {
	mu     sync.Mutex
	events []port.AuditEvent
	err    error
}

func (s *fakeAuditSink) Record(ctx context.Context, e port.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return s.err
}

func (s *fakeAuditSink) snapshot() []port.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]port.AuditEvent, len(s.events))
	copy(cp, s.events)
	return cp
}

// TestProxyAudit_PushAllowRecordsEvent asserts an allowed push produces an
// audit event with verdict=allow, the agent, the repo, the service, and the
// pushed ref(s). The event carries only generic reasons (none for allow).
func TestProxyAudit_PushAllowRecordsEvent(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

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
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	sink := &fakeAuditSink{}
	proxy.SetAuditSink(sink)
	proxy.SetTransport("http")

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(events))
	}
	e := events[0]
	if e.Verdict != "allow" {
		t.Fatalf("verdict: %q want allow", e.Verdict)
	}
	if e.Service != "git-receive-pack" {
		t.Fatalf("service: %q", e.Service)
	}
	if e.Transport != "http" {
		t.Fatalf("transport: %q want http", e.Transport)
	}
	if e.Repo != "repo.git" {
		t.Fatalf("repo: %q", e.Repo)
	}
	if len(e.Refs) != 1 || e.Refs[0].Ref != ref || e.Refs[0].New != tip {
		t.Fatalf("refs: %+v", e.Refs)
	}
	if len(e.Reasons) != 0 {
		t.Fatalf("allow reasons should be empty, got %v", e.Reasons)
	}
}

// TestProxyAudit_PushDenyRecordsEvent asserts a denied push (engine deny)
// produces an audit event with verdict=deny, the ref, and a generic reason.
func TestProxyAudit_PushDenyRecordsEvent(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

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
		"branch_pattern": {"allow": nil}, // empty allow list denies all
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	sink := &fakeAuditSink{}
	proxy.SetAuditSink(sink)
	proxy.SetTransport("ssh")

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != 0 {
		t.Fatalf("denied push must not forward; got %d bytes", len(up.forwarded))
	}
	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(events))
	}
	e := events[0]
	if e.Verdict != "deny" {
		t.Fatalf("verdict: %q want deny", e.Verdict)
	}
	if e.Transport != "ssh" {
		t.Fatalf("transport: %q want ssh", e.Transport)
	}
	if len(e.Refs) != 1 || e.Refs[0].Ref != ref {
		t.Fatalf("refs: %+v", e.Refs)
	}
	if len(e.Reasons) == 0 {
		t.Fatalf("deny event must carry a reason")
	}
}

// TestProxyAudit_PushOversizeDenyRecordsEvent asserts the oversize fail-closed
// branch records a deny event (not just the engine path).
func TestProxyAudit_PushOversizeDenyRecordsEvent(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

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
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	// maxBytes smaller than the body → oversize deny before the engine runs.
	proxy.SetEnforcement(eng, testMirrorOpener(t), int64(len(body)-1))
	sink := &fakeAuditSink{}
	proxy.SetAuditSink(sink)
	proxy.SetTransport("http")

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != 0 {
		t.Fatalf("oversize push must not forward")
	}
	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 audit event, got %d", len(events))
	}
	if events[0].Verdict != "deny" {
		t.Fatalf("verdict: %q want deny (oversize)", events[0].Verdict)
	}
	if len(events[0].Reasons) == 0 || !strings.Contains(events[0].Reasons[0], "too large") {
		t.Fatalf("oversize reason missing: %+v", events[0].Reasons)
	}
}

// TestProxyAudit_PassthroughRecordsBareAllow asserts that with policy OFF (no
// engine), the proxy still records a bare allow event for the op (the chosen
// passthrough-audit decision: log all traffic). The event has verdict=allow,
// the service, and no reasons.
func TestProxyAudit_PassthroughRecordsBareAllow(t *testing.T) {
	ctx := context.Background()
	ref := "refs/heads/main"
	// A minimal receive-pack request body (command + flush, no packfile) so
	// parsing succeeds and refs are available for the event.
	var body bytes.Buffer
	enc := pktline.NewEncoder(&body)
	line := "0000000000000000000000000000000000000000 " + ref + "\x00report-status\n"
	if err := enc.EncodeString(line); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := enc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	up := &fakeUpstream{resp: cannedReceivePackResponse(t, ref)}
	proxy := gitproto.New(up) // no enforcement → passthrough
	sink := &fakeAuditSink{}
	proxy.SetAuditSink(sink)
	proxy.SetTransport("http")

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body.Bytes()), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) == 0 {
		t.Fatalf("passthrough push must forward to upstream")
	}
	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("want 1 passthrough audit event, got %d", len(events))
	}
	ev := events[0]
	if ev.Verdict != "allow" {
		t.Fatalf("passthrough verdict: %q want allow", ev.Verdict)
	}
	if len(ev.Reasons) != 0 {
		t.Fatalf("passthrough event should have no reasons, got %v", ev.Reasons)
	}
	if ev.Service != "git-receive-pack" {
		t.Fatalf("service: %q", ev.Service)
	}
}

// TestProxyAudit_NilSinkNoOp asserts a nil sink (audit off) preserves the
// existing behavior — no panic, op proceeds.
func TestProxyAudit_NilSinkNoOp(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

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
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	// No SetAuditSink → nil sink → no audit, no panic.

	var out bytes.Buffer
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
}

// TestProxyAudit_BestEffortSinkErrorDoesNotBlock asserts that when the audit
// sink returns an error, the proxy does NOT change the verdict or block the
// op — the push still forwards (allow) and the deny still denies. The audit
// write is best-effort (binding).
func TestProxyAudit_BestEffortSinkErrorDoesNotBlock(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

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
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	proxy := gitproto.New(up)
	proxy.SetEnforcement(eng, testMirrorOpener(t), 1<<28)
	sink := &fakeAuditSink{err: errors.New("disk full")}
	proxy.SetAuditSink(sink)
	proxy.SetTransport("http")

	var out bytes.Buffer
	// Allow path: the push MUST still forward despite the audit error.
	if err := proxy.ReceivePack(ctx, "repo.git", bytes.NewReader(body), &out); err != nil {
		t.Fatalf("ReceivePack: %v", err)
	}
	if len(up.forwarded) != len(body) {
		t.Fatalf("audit error must not block forward; got %d bytes forwarded, want %d", len(up.forwarded), len(body))
	}
}