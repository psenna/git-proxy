package port_test

import (
	"context"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// TestAuditEventShape asserts the AuditEvent/AuditRef value types carry the
// fields the audit contract requires (verdict, agent, refs, denied paths/oids).
// It is a compile-time + shape guard for the pure audit types.
func TestAuditEventShape(t *testing.T) {
	e := port.AuditEvent{
		Transport: "http",
		Agent:     "alice",
		Repo:      "team/repo.git",
		Service:   "git-receive-pack",
		Verdict:   "deny",
		Reasons:   []string{"push rejected: protected ref"},
		Refs: []port.AuditRef{
			{Ref: "refs/heads/main", Old: "aaa", New: "bbb", Force: true},
		},
		DeniedPaths: []string{"secrets/secret.txt"},
		DeniedOIDs:  []string{"deadbeef"},
	}
	if e.Verdict != "deny" {
		t.Fatalf("verdict: %q", e.Verdict)
	}
	if len(e.Refs) != 1 || e.Refs[0].Ref != "refs/heads/main" || !e.Refs[0].Force {
		t.Fatalf("refs: %+v", e.Refs)
	}
	if len(e.DeniedPaths) != 1 || e.DeniedPaths[0] != "secrets/secret.txt" {
		t.Fatalf("denied paths: %+v", e.DeniedPaths)
	}
	if len(e.DeniedOIDs) != 1 || e.DeniedOIDs[0] != "deadbeef" {
		t.Fatalf("denied oids: %+v", e.DeniedOIDs)
	}
}

// recordingSink is a port.AuditSink that records every event for tests in other
// packages (gitproto, audit/file). It lives here so the type assertion
// (var _ port.AuditSink = (*recordingSink)(nil)) guards the interface shape.
type recordingSink struct {
	events []port.AuditEvent
	err    error
}

func (s *recordingSink) Record(ctx context.Context, e port.AuditEvent) error {
	s.events = append(s.events, e)
	return s.err
}

// TestAuditSinkInterface asserts the AuditSink interface is implementable and
// Record returns an error (the best-effort contract surface).
func TestAuditSinkInterface(t *testing.T) {
	var s port.AuditSink = &recordingSink{}
	if err := s.Record(context.Background(), port.AuditEvent{Service: "git-upload-pack"}); err != nil {
		t.Fatalf("record: %v", err)
	}
}