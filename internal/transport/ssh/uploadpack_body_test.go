package sshfront

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
)

// TestReadUploadPackRequest_CappedOnOversizedNoDone verifies the SSH framer
// fail-closes when a rogue authorized agent streams `want` lines without ever
// sending `done` — the unbounded-accumulation DoS the review flagged. The
// framer must cap the upload-pack request read at gitproto.MaxUploadPackRequestBytes
// (1 MiB) and return an error; it must NOT keep accumulating into an unbounded
// bytes.Buffer (OOM). A real upload-pack request is tiny (wants/haves/caps),
// so 1 MiB is a generous ceiling.
func TestReadUploadPackRequest_CappedOnOversizedNoDone(t *testing.T) {
	// Build a stream of `want <sha>` pkt-lines that exceeds the cap, with NO
	// `done` terminator — the DoS shape (a rogue agent streams wants forever).
	sha := strings.Repeat("a", 40)
	one := encodePktLine(t, fmt.Sprintf("want %s\n", sha))
	// Target the cap + 512 KiB so we clearly cross the 1 MiB ceiling.
	target := gitproto.MaxUploadPackRequestBytes + 1<<19
	var raw []byte
	for int64(len(raw)) < target {
		raw = append(raw, one...)
	}

	_, err := readUploadPackRequest(bytes.NewReader(raw))
	if err == nil {
		t.Fatalf("readUploadPackRequest returned nil error for an oversized, no-done stream (unbounded growth DoS not fail-closed)")
	}
	if !strings.Contains(err.Error(), "exceeds") && !strings.Contains(err.Error(), "no done") {
		t.Errorf("error does not surface the cap reason: %v", err)
	}
}

// TestReadUploadPackRequest_SmallCloneSucceeds verifies a real (tiny) clone
// request — wants, flush, done — is framed successfully and well under the cap.
// This guards the regression that the cap breaks legitimate fetches (real
// upload-pack requests are far smaller than 1 MiB).
func TestReadUploadPackRequest_SmallCloneSucceeds(t *testing.T) {
	sha := strings.Repeat("a", 40)
	var raw []byte
	raw = append(raw, encodePktLine(t, fmt.Sprintf("want %s ofs-delta\n", sha))...)
	raw = append(raw, flushPkt()...)
	raw = append(raw, encodePktLine(t, "done\n")...)
	// The framer returns at `done` (git does not send a trailing flush after
	// it; the client waits for the server response), so the framed body is the
	// wants + flush + done — no trailing flush.
	want := raw

	got, err := readUploadPackRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readUploadPackRequest small clone: unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("framed bytes do not match input: got %q want %q", got, want)
	}
}

// encodePktLine encodes a single pkt-line data payload (the 4-byte hex length
// prefix + payload), as a git client would send it.
func encodePktLine(t *testing.T, payload string) []byte {
	t.Helper()
	n := len(payload) + 4 // +4 for the length prefix itself
	return []byte(fmt.Sprintf("%04x%s", n, payload))
}

// flushPkt returns the git flush-pkt "0000".
func flushPkt() []byte {
	return []byte("0000")
}