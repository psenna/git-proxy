package gitproto

import (
	"bytes"
	"errors"
	"strings"
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

// failFirstWriter fails its first Write call and succeeds thereafter. With a
// non-empty pack and no shallow lines, the very first byte writeV0UploadPackResponse
// sends to w is the "NAK\n" pkt-line encode — nothing else precedes it in that
// path — so failing the first write deterministically exercises the NAK-encode
// error branch regardless of how the pktline encoder internally chunks its
// output into underlying Write calls.
type failFirstWriter struct {
	failed bool
}

func (w *failFirstWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, errors.New("simulated first-write failure (NAK encode)")
	}
	return len(p), nil
}

// TestWriteV0UploadPackResponse_PackWaitCalledOnNAKEncodeFailure is the
// security review H8 regression guard: EVERY error return in
// writeV0UploadPackResponse must call packWait() before returning, because
// packWait() is what unblocks the pack-objects producer goroutine (which
// holds the mirror's per-repo mutex until it exits). One return path — the
// NAK-encode failure in the non-empty-pack branch — was missing this call: a
// client that opens a read-protected fetch and drops the connection right as
// the NAK write fails would leave the producer goroutine blocked forever,
// the mutex held forever, and every subsequent fetch/push to that repo
// deadlocked permanently.
func TestWriteV0UploadPackResponse_PackWaitCalledOnNAKEncodeFailure(t *testing.T) {
	pack := strings.NewReader("fake-pack-bytes-nonempty") // n > 0, shorter than the 4096 head-read
	waitCalled := 0
	packWait := func() error {
		waitCalled++
		return nil
	}
	w := &failFirstWriter{}

	err := writeV0UploadPackResponse(w, pack, packWait, nil, nil)
	if err == nil {
		t.Fatal("writeV0UploadPackResponse: want an error from the simulated NAK-encode failure, got nil")
	}
	if waitCalled != 1 {
		t.Errorf("packWait called %d times, want exactly 1 — a missed call here is a permanent per-repo deadlock (finding H8)", waitCalled)
	}
}
