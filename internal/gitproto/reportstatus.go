package gitproto

import (
	"fmt"
	"io"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/port"
)

// EncodeReportStatusDeny writes a git report-status response that a real git
// client interprets as a rejected push: an "unpack ok" line, one
// "ng <ref> <reason>" line per denied ref, terminated by a flush-pkt.
//
// The unpack status is "ok" because the proxy never unpacked anything (it
// never forwarded the push); this mirrors a pre-receive hook decline: the ref
// is rejected with the given reason while the pack itself is reported as
// unpacked cleanly. The client surfaces the per-ref reason in its stderr.
//
// The reason text is the aggregated deny reasons (Rule.Message joined with
// "; "), with any newlines collapsed to spaces so each ref's status fits on a
// single pkt-line as the report-status wire format requires.
//
// If refs is empty, a single placeholder "ng <ref>" is not emitted; instead
// only the "unpack ok" + flush is written (the push had no commands, an edge
// case the caller should generally not hit).
func EncodeReportStatusDeny(w io.Writer, refs []string, dec port.Decision) error {
	e := pktline.NewEncoder(w)
	if err := e.EncodeString("unpack ok\n"); err != nil {
		return fmt.Errorf("gitproto: encode report-status unpack: %w", err)
	}
	reason := aggregateReasons(dec)
	for _, ref := range refs {
		if err := e.EncodeString(fmt.Sprintf("ng %s %s\n", ref, reason)); err != nil {
			return fmt.Errorf("gitproto: encode report-status ng %s: %w", ref, err)
		}
	}
	if err := e.Flush(); err != nil {
		return fmt.Errorf("gitproto: encode report-status flush: %w", err)
	}
	return nil
}

// aggregateReasons joins a Decision's deny reasons into a single human-readable
// string with newlines collapsed to spaces (the report-status wire format puts
// each ref status on one pkt-line). An empty Reasons slice yields a generic
// "push denied by policy" message.
func aggregateReasons(dec port.Decision) string {
	if len(dec.Reasons) == 0 {
		return "push denied by policy"
	}
	parts := make([]string, 0, len(dec.Reasons))
	for _, r := range dec.Reasons {
		msg := strings.TrimSpace(r.Message)
		if msg == "" {
			msg = "denied by " + r.Rule
		}
		parts = append(parts, msg)
	}
	joined := strings.Join(parts, "; ")
	// Collapse any embedded newlines so the status stays on one pkt-line.
	joined = strings.ReplaceAll(joined, "\n", " ")
	joined = strings.ReplaceAll(joined, "\r", " ")
	return joined
}