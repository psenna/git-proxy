package alert_test

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/alert"
	logalert "github.com/psenna/git-proxy/internal/alert/log"
	"github.com/psenna/git-proxy/internal/port"
)

// fakeAlertSink records alerts for assertions. err, if non-nil, is returned to
// exercise the best-effort path (the multi-sink must log/swallow and continue
// to the next sink, not abort the fan-out).
type fakeAlertSink struct {
	mu     sync.Mutex
	alerts []port.Alert
	err    error
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

// TestMultiAlertSink_FanOut verifies the multi-sink delivers the alert to ALL
// child sinks, even when an earlier sink returns an error (best-effort per
// sink: one failure does not block the others).
func TestMultiAlertSink_FanOut(t *testing.T) {
	a := port.Alert{Verdict: "deny", Agent: "a1"}
	s1 := &fakeAlertSink{}
	s2 := &fakeAlertSink{err: errors.New("webhook down")}
	s3 := &fakeAlertSink{}

	multi := alert.Multi(s1, s2, s3)
	if err := multi.Alert(context.Background(), a); err != nil {
		t.Fatalf("Multi must not surface child errors (best-effort): %v", err)
	}
	for i, got := range [][]port.Alert{s1.snapshot(), s2.snapshot(), s3.snapshot()} {
		if len(got) != 1 || got[0].Agent != "a1" {
			t.Fatalf("sink %d did not receive alert: %+v", i, got)
		}
	}
}

// TestMultiAlertSink_NilChildrenNoOp verifies a multi-sink with nil children
// (and a nil multi itself) is a no-op — never panics.
func TestMultiAlertSink_NilChildrenNoOp(t *testing.T) {
	var multi alert.MultiAlertSink
	if err := multi.Alert(context.Background(), port.Alert{Verdict: "deny"}); err != nil {
		t.Fatalf("nil multi must be no-op, got %v", err)
	}
	// Multi(nil, nil) is also a no-op.
	m2 := alert.Multi(nil, nil)
	if err := m2.Alert(context.Background(), port.Alert{Verdict: "deny"}); err != nil {
		t.Fatalf("Multi(nil,nil) must be no-op, got %v", err)
	}
}

// TestLogSink_WritesToLogger verifies the log sink writes a line containing the
// agent + verdict + dry_run to the configured logger, and never errors
// (best-effort: logging is best-effort, the log sink always succeeds).
func TestLogSink_WritesToLogger(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	sink := logalert.NewSink(l)
	a := port.Alert{Verdict: "deny", Agent: "agent-7", DryRun: true, Repo: "r.git",
		Reasons: []string{"branch_pattern denied"}}
	if err := sink.Alert(context.Background(), a); err != nil {
		t.Fatalf("log sink must not error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "agent-7") {
		t.Fatalf("log line missing agent: %q", out)
	}
	if !strings.Contains(out, "deny") {
		t.Fatalf("log line missing verdict: %q", out)
	}
	if !strings.Contains(out, "dry_run=true") {
		t.Fatalf("log line missing dry_run: %q", out)
	}
}

// TestLogSink_NoLeakCanary verifies the log sink does not write a secret that
// was in the pushed content — the Alert carries only generic reasons.
func TestLogSink_NoLeakCanary(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	sink := logalert.NewSink(l)
	secret := "AKIAIOSFODNN7EXAMPLE"
	a := port.Alert{
		Verdict: "deny",
		Reasons: []string{"secret_scan matched a secret (redacted)"},
	}
	if err := sink.Alert(context.Background(), a); err != nil {
		t.Fatalf("log sink: %v", err)
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("log sink leaked secret: %q", buf.String())
	}
}