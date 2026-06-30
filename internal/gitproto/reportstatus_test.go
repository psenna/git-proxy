package gitproto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/port"
)

// TestEncodeReportStatusDeny verifies the deny report-status the proxy writes to
// the agent parses as a valid report-status: an "unpack ok" line, one
// "ng <ref> <reason>" line per denied ref, terminated by a flush-pkt. The
// format must match what a real git client decodes.
func TestEncodeReportStatusDeny(t *testing.T) {
	dec := port.Decision{
		Verdict: port.VerdictDeny,
		Reasons: []port.Reason{
			{Rule: "history_protect", Message: `force-push to protected ref "refs/heads/main" is not allowed`},
		},
	}
	refs := []string{"refs/heads/main"}

	var out bytes.Buffer
	if err := gitproto.EncodeReportStatusDeny(&out, refs, dec); err != nil {
		t.Fatalf("EncodeReportStatusDeny: %v", err)
	}

	// Decode the written bytes as a report-status stream.
	s := pktline.NewScanner(bytes.NewReader(out.Bytes()))
	type line struct {
		marker pktline.Marker
		data   string
	}
	var lines []line
	for s.Scan() {
		lines = append(lines, line{s.Marker(), string(s.Bytes())})
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// The final marker must be a flush (the scanner stops at flush; collect it).
	if got := len(lines); got < 2 {
		t.Fatalf("expected at least unpack+ng lines, got %d lines: %v", got, lines)
	}

	// First line: "unpack ok".
	if strings.TrimSpace(lines[0].data) != "unpack ok" {
		t.Fatalf("first line = %q, want %q", lines[0].data, "unpack ok")
	}
	// Second line: "ng <ref> <reason>".
	ngLine := strings.TrimSpace(lines[1].data)
	if !strings.HasPrefix(ngLine, "ng refs/heads/main ") {
		t.Fatalf("ng line = %q, want prefix %q", ngLine, "ng refs/heads/main ")
	}
	reason := strings.TrimPrefix(ngLine, "ng refs/heads/main ")
	if !strings.Contains(reason, "force-push") {
		t.Fatalf("ng reason = %q, want it to contain the deny reason", reason)
	}
	// The reason must not contain a raw newline (single pkt-line per ref).
	if strings.ContainsAny(reason, "\n\r") {
		t.Fatalf("ng reason contains a newline: %q", reason)
	}
	// Stream must end with a flush-pkt (0000). The raw bytes must end with the
	// flush marker.
	if !bytes.HasSuffix(out.Bytes(), []byte("0000")) {
		t.Fatalf("report-status does not end with flush-pkt 0000; bytes=%x", out.Bytes())
	}
}

// TestEncodeReportStatusDenyMultipleRefs verifies every denied ref gets its own
// ng line carrying the aggregated reason text.
func TestEncodeReportStatusDenyMultipleRefs(t *testing.T) {
	dec := port.Decision{
		Verdict: port.VerdictDeny,
		Reasons: []port.Reason{
			{Rule: "history_protect", Message: "force-push denied"},
			{Rule: "branch_pattern", Message: "ref not allowed"},
		},
	}
	refs := []string{"refs/heads/main", "refs/heads/release"}

	var out bytes.Buffer
	if err := gitproto.EncodeReportStatusDeny(&out, refs, dec); err != nil {
		t.Fatalf("EncodeReportStatusDeny: %v", err)
	}

	s := pktline.NewScanner(bytes.NewReader(out.Bytes()))
	var ngCount int
	for s.Scan() {
		if s.Marker() != pktline.Data {
			continue
		}
		line := strings.TrimSpace(string(s.Bytes()))
		if strings.HasPrefix(line, "ng ") {
			ngCount++
			// Both refs must appear and the reason must aggregate both messages.
			if !strings.Contains(line, "refs/heads/main") && !strings.Contains(line, "refs/heads/release") {
				t.Fatalf("ng line for unexpected ref: %q", line)
			}
			if !strings.Contains(line, "force-push denied") || !strings.Contains(line, "ref not allowed") {
				t.Fatalf("ng line reason not aggregated: %q", line)
			}
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ngCount != 2 {
		t.Fatalf("ng line count = %d, want 2", ngCount)
	}
}