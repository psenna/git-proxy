package gitproto

import (
	"bytes"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// TestWriteUploadPackErr_EncodesERRPktLine verifies the v0 upload-pack error
// helper writes a single `ERR <reason>\n` pkt-line that a real git client
// surfaces as a fetch error. v0 upload-pack lets the server send an ERR
// pkt-line at any point to abort the negotiation; the on-demand blob-denial
// path (Task 10) uses it to refuse denied on-demand blob fetches with a
// structured, fail-closed reason instead of a silent empty pack.
//
// The encoded form MUST be a normal data pkt-line whose payload is exactly
// "ERR <reason>\n" (the trailing newline is part of the payload, matching git's
// upload-pack ERR convention). The reason must contain NO upstream creds and
// NO secret content (fail-closed / redaction discipline).
func TestWriteUploadPackErr_EncodesERRPktLine(t *testing.T) {
	const reason = "access to object deadbeef denied by read policy"
	var buf bytes.Buffer
	if err := writeUploadPackErr(&buf, reason); err != nil {
		t.Fatalf("writeUploadPackErr: %v", err)
	}

	s := pktline.NewScanner(&buf)
	if !s.Scan() {
		t.Fatalf("no pkt-line; scan err=%v", s.Err())
	}
	if s.Marker() != pktline.Data {
		t.Fatalf("marker = %v, want Data", s.Marker())
	}
	want := "ERR " + reason + "\n"
	if got := string(s.Bytes()); got != want {
		t.Errorf("ERR pkt-line payload = %q, want %q", got, want)
	}
	// Exactly one pkt-line, nothing else (no packfile, no NAK, no flush).
	if s.Scan() {
		t.Errorf("unexpected second pkt-line after ERR: marker=%v bytes=%q", s.Marker(), s.Bytes())
	}
}