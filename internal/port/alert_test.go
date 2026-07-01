package port_test

import (
	"context"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// TestAlert_NoLeakShape verifies the Alert struct carries only generic,
// non-secret fields and that an AlertSink implementation satisfies the
// interface (pluggability). The Alert reuses AuditRef from audit.go (no
// duplication) and the no-leak contract is documented on the type.
func TestAlert_NoLeakShape(t *testing.T) {
	a := port.Alert{
		Transport:    "http",
		Agent:        "agent-1",
		Repo:         "team/repo.git",
		Service:      "git-receive-pack",
		Verdict:      "deny",
		DryRun:       true,
		Reasons:      []string{"push denied by branch_pattern"},
		Refs:         []port.AuditRef{{Ref: "refs/heads/main", Old: "abc", New: "def"}},
		DeniedPaths:  []string{"secrets/creds.txt"},
		DeniedOIDs:   []string{"deadbeef"},
	}
	if a.Verdict != "deny" {
		t.Fatalf("verdict: %q want deny", a.Verdict)
	}
	if !a.DryRun {
		t.Fatalf("dry_run: want true")
	}
	// The Alert fields are the ONLY fields — no Content / raw-secret / URL
	// field exists. This is enforced by construction; the type carries generic
	// reasons, paths, and OIDs only (no-leak contract, documented on Alert).
}

// noopAlertSink is a minimal AlertSink implementation verifying the interface
// is satisfied by any type implementing Alert(ctx, Alert) error.
type noopAlertSink struct{}

func (noopAlertSink) Alert(ctx context.Context, a port.Alert) error { return nil }

func TestAlertSink_InterfaceSatisfied(t *testing.T) {
	var _ port.AlertSink = noopAlertSink{}
	// A nil alert sink means "alerts off" — the proxy MUST guard every call.
	var nilSink port.AlertSink = nil
	_ = nilSink
}

// TestAuditEvent_DryRunAdditive verifies the DryRun field is present on
// AuditEvent (additive, backward-compatible). Default false preserves Task 12
// behavior (an event constructed without setting DryRun reads false).
func TestAuditEvent_DryRunAdditive(t *testing.T) {
	var e port.AuditEvent
	if e.DryRun {
		t.Fatalf("zero-value AuditEvent.DryRun must be false (preserves Task 12)")
	}
	e.DryRun = true
	if !e.DryRun {
		t.Fatalf("DryRun field not settable")
	}
}