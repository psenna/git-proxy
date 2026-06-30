package gitproto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// fixtureBytes reads a golden fixture from test/integration/fixtures. The
// internal test package cannot use the _test helper in gitproto_test, so it
// resolves the path itself.
func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "integration", "fixtures", name),
		filepath.Join("..", "..", "test", "integration", "fixtures", name),
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Fatalf("fixture %s not found", name)
	return nil
}

// TestForwardStreamRoundTripSideband feeds a recorded sideband-muxed
// upload-pack response through forwardStream and asserts it is forwarded
// byte-exact.
func TestForwardStreamRoundTripSideband(t *testing.T) {
	in := fixtureBytes(t, "upload-pack-response.bin")
	var out bytes.Buffer
	if err := forwardStream(bytes.NewReader(in), &out); err != nil {
		t.Fatalf("forwardStream: %v", err)
	}
	if !bytes.Equal(in, out.Bytes()) {
		t.Fatalf("sideband forward not byte-exact: in=%d out=%d", len(in), out.Len())
	}
}

// TestForwardStreamRoundTripReceivePackResponse feeds a recorded receive-pack
// response through forwardStream and asserts byte-exact forwarding.
func TestForwardStreamRoundTripReceivePackResponse(t *testing.T) {
	in := fixtureBytes(t, "receive-pack-response.bin")
	var out bytes.Buffer
	if err := forwardStream(bytes.NewReader(in), &out); err != nil {
		t.Fatalf("forwardStream: %v", err)
	}
	if !bytes.Equal(in, out.Bytes()) {
		t.Fatalf("receive-pack response forward not byte-exact: in=%d out=%d", len(in), out.Len())
	}
}

// TestForwardStreamRawPackfile exercises the non-sideband response shape
// (NAK, flush, then a raw packfile body) and asserts forwardStream switches to
// raw copy and forwards every byte.
func TestForwardStreamRawPackfile(t *testing.T) {
	var in bytes.Buffer
	e := pktline.NewEncoder(&in)
	if err := e.EncodeString("NAK\n"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Raw packfile section (not a pkt-line): the PACK magic followed by body
	// bytes that are not valid hex.
	pack := []byte("PACK\x00\x00\x00\x02\x1e\x00\x00\x00raw-packfile-body")
	in.Write(pack)

	var out bytes.Buffer
	if err := forwardStream(bytes.NewReader(in.Bytes()), &out); err != nil {
		t.Fatalf("forwardStream: %v", err)
	}
	if !bytes.Equal(in.Bytes(), out.Bytes()) {
		t.Fatalf("raw packfile forward not byte-exact: in=%d out=%d", len(in.Bytes()), out.Len())
	}
}

// TestForwardStreamEmpty asserts an empty response forwards cleanly.
func TestForwardStreamEmpty(t *testing.T) {
	var out bytes.Buffer
	if err := forwardStream(bytes.NewReader(nil), &out); err != nil {
		t.Fatalf("forwardStream empty: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty output, got %d bytes", out.Len())
	}
}
