// Package alert provides composite AlertSink implementations for fan-out. The
// v1 alert wiring (cmd/git-proxy) builds a MultiAlertSink of a webhook sink
// plus a log sink so operators see violations both in real time (webhook) and
// in the proxy log (stderr). Each child sink is best-effort: one sink's
// failure is logged and does NOT block the others (a down webhook must not
// silence the log sink).
package alert

import (
	"context"
	"log"

	"github.com/psenna/git-proxy/internal/port"
)

// MultiAlertSink is an AlertSink that fans an Alert out to N child sinks. Each
// child delivery is best-effort: an error from one sink is logged (via the
// proxy's standard logger) and the fan-out continues to the remaining sinks.
// The MultiAlertSink itself never returns an error (alerting is observability,
// not a gate — the caller's verdict stands regardless). A nil *MultiAlertSink
// or a multi with no children is a no-op.
type MultiAlertSink struct {
	sinks []port.AlertSink
}

// Multi returns a MultiAlertSink that fans out to the given sinks. Nil entries
// are skipped (so a caller can pass Multi(webhook, log) without worrying about
// nil). Use Multi() or the zero value for an empty no-op sink.
func Multi(sinks ...port.AlertSink) MultiAlertSink {
	out := MultiAlertSink{sinks: make([]port.AlertSink, 0, len(sinks))}
	for _, s := range sinks {
		if s == nil {
			continue
		}
		out.sinks = append(out.sinks, s)
	}
	return out
}

// Alert delivers a to every child sink, best-effort. Each error is logged and
// swallowed; the fan-out continues. Never returns an error (the caller treats
// alerting as non-fatal; the multi-sink surfaces nothing so the proxy does not
// double-log).
func (m MultiAlertSink) Alert(ctx context.Context, a port.Alert) error {
	for _, s := range m.sinks {
		if s == nil {
			continue
		}
		if err := s.Alert(ctx, a); err != nil {
			log.Printf("alert: multi-sink child delivery failed: %v", err)
		}
	}
	return nil
}