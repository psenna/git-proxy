// Package log is a best-effort AlertSink that writes each Alert as one line
// to a *log.Logger (typically stderr). It never returns an error (logging is
// best-effort; the log sink always succeeds from the caller's perspective).
// Useful as a secondary sink in a MultiAlertSink (e.g. webhook + stderr) so
// operators see violations in the proxy log even when the webhook is
// unreachable. The Alert carries only generic reasons/paths/OIDs (no-leak
// contract) — the log line reuses those fields, never blob content.
package log

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// Sink is an AlertSink that writes alerts to a *log.Logger.
type Sink struct {
	l *log.Logger
}

// NewSink returns a log AlertSink writing to l. If l is nil, the standard
// logger is used (so a nil logger is still a working sink, not a panic).
func NewSink(l *log.Logger) *Sink {
	if l == nil {
		l = log.Default()
	}
	return &Sink{l: l}
}

// Alert writes one line describing the violation to the logger. It never
// returns an error (best-effort: the caller treats alert delivery as
// non-fatal; the log sink reports success regardless). The line carries the
// transport, agent, repo, service, verdict, dry_run, reasons, and a count of
// denied paths/OIDs — no blob content (no-leak contract, enforced at Alert
// construction).
func (s *Sink) Alert(ctx context.Context, a port.Alert) error {
	dryRun := "false"
	if a.DryRun {
		dryRun = "true"
	}
	reasons := strings.Join(a.Reasons, "; ")
	line := fmt.Sprintf("git-proxy alert: transport=%s agent=%q repo=%q service=%s verdict=%s dry_run=%s reasons=%q denied_paths=%d denied_oids=%d",
		a.Transport, a.Agent, a.Repo, a.Service, a.Verdict, dryRun, reasons,
		len(a.DeniedPaths), len(a.DeniedOIDs))
	s.l.Print(line)
	return nil
}