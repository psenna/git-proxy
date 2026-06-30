package gitproto_test

import (
	"bytes"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// buildWantHaveStream builds a synthetic upload-pack request with two wants
// (first carrying capabilities), a flush, one have, a done, and a final flush.
func buildWantHaveStream(t *testing.T, want1, want2, have string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	mustEncode(t, e, "want "+want1+" ofs-delta no-progress\n")
	mustEncode(t, e, "want "+want2+"\n")
	mustFlush(t, e)
	mustEncode(t, e, "have "+have+"\n")
	mustEncode(t, e, "done\n")
	mustFlush(t, e)
	return &buf
}

func mustEncode(t *testing.T, e *pktline.Encoder, s string) {
	t.Helper()
	if err := e.EncodeString(s); err != nil {
		t.Fatalf("encode %q: %v", s, err)
	}
}

func mustFlush(t *testing.T, e *pktline.Encoder) {
	t.Helper()
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}
