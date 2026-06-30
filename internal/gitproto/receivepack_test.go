package gitproto_test

import (
	"bytes"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// TestParseReceivePackRequest parses a recorded git-receive-pack push request
// (commands + flush + packfile) and asserts the command, capabilities, and
// packfile boundary are extracted.
func TestParseReceivePackRequest(t *testing.T) {
	data := fixture(t, "receive-pack-request.bin")
	req, err := gitproto.ParseReceivePackRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Commands) != 1 {
		t.Fatalf("commands = %v, want 1", req.Commands)
	}
	c := req.Commands[0]
	if !isHexSHA(c.Old) {
		t.Fatalf("old = %q, want 40-hex", c.Old)
	}
	if !isHexSHA(c.New) {
		t.Fatalf("new = %q, want 40-hex", c.New)
	}
	if c.Old == c.New {
		t.Fatalf("old == new (%s), expected a real update", c.Old)
	}
	if c.Ref != "refs/heads/main" {
		t.Fatalf("ref = %q, want refs/heads/main", c.Ref)
	}
	if len(c.Caps) == 0 {
		t.Fatalf("expected capabilities on first command, got none")
	}
	has := func(want string) bool {
		for _, cap := range c.Caps {
			if cap == want {
				return true
			}
		}
		return false
	}
	if !has("report-status-v2") {
		t.Fatalf("missing report-status-v2 capability, got %v", c.Caps)
	}

	// Packfile boundary: the byte at PackfileOffset must begin "PACK".
	if req.PackfileOffset < 0 {
		t.Fatalf("packfile offset = %d, want >= 0", req.PackfileOffset)
	}
	if req.PackfileOffset+4 > int64(len(data)) {
		t.Fatalf("packfile offset %d out of bounds (data %d)", req.PackfileOffset, len(data))
	}
	if string(data[req.PackfileOffset:req.PackfileOffset+4]) != "PACK" {
		t.Fatalf("bytes at packfile offset = %q, want %q",
			data[req.PackfileOffset:req.PackfileOffset+4], "PACK")
	}
}

// TestParseReceivePackRequestMultipleCommands parses a synthetic multi-command
// push and asserts all commands are extracted with capabilities only on the
// first.
func TestParseReceivePackRequestMultipleCommands(t *testing.T) {
	stream := buildMultiCommandStream(t,
		"0000000000000000000000000000000000000000",
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222")
	raw := append([]byte(nil), stream.Bytes()...)
	req, err := gitproto.ParseReceivePackRequest(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Commands) != 2 {
		t.Fatalf("commands = %v, want 2", req.Commands)
	}
	first := req.Commands[0]
	if first.Old != "0000000000000000000000000000000000000000" ||
		first.New != "1111111111111111111111111111111111111111" ||
		first.Ref != "refs/heads/main" {
		t.Fatalf("first command = %+v", first)
	}
	if len(first.Caps) != 2 || first.Caps[0] != "report-status" || first.Caps[1] != "atomic" {
		t.Fatalf("first caps = %v", first.Caps)
	}
	second := req.Commands[1]
	if second.Old != "0000000000000000000000000000000000000000" ||
		second.New != "2222222222222222222222222222222222222222" ||
		second.Ref != "refs/tags/v1" {
		t.Fatalf("second command = %+v", second)
	}
	if second.Caps != nil {
		t.Fatalf("second command caps = %v, want nil (caps only on first)", second.Caps)
	}
	// A packfile follows the flush.
	if req.PackfileOffset < 0 {
		t.Fatalf("packfile offset = %d, want >= 0", req.PackfileOffset)
	}
	off := int(req.PackfileOffset)
	got := raw[off : off+4]
	if string(got) != "PACK" {
		t.Fatalf("packfile bytes at %d = %q, want PACK (full=%q)", off, got, raw)
	}
}

// TestParseReceivePackRequestDeleteOnly parses a delete-only push (zero new
// SHA) with no packfile following the flush.
func TestParseReceivePackRequestDeleteOnly(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	// Delete: <old> <zero-new> <ref>\0<caps>
	mustEncode(t, e, "1234567890123456789012345678901234567890 0000000000000000000000000000000000000000 refs/heads/feature\x00 report-status\n")
	mustFlush(t, e)
	// No packfile: delete-only pushes carry no pack data.

	req, err := gitproto.ParseReceivePackRequest(&buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Commands) != 1 {
		t.Fatalf("commands = %v, want 1", req.Commands)
	}
	if req.Commands[0].New != "0000000000000000000000000000000000000000" {
		t.Fatalf("new = %q, want zero SHA", req.Commands[0].New)
	}
	if req.PackfileOffset != -1 {
		t.Fatalf("packfile offset = %d, want -1 (no packfile)", req.PackfileOffset)
	}
}

// TestParseReceivePackRequestNoCommands rejects an empty command list.
func TestParseReceivePackRequestNoCommands(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	mustFlush(t, e)

	_, err := gitproto.ParseReceivePackRequest(&buf)
	if err == nil {
		t.Fatalf("expected error for empty command list")
	}
}

// buildMultiCommandStream builds a synthetic receive-pack request with two
// commands (first carrying capabilities), a flush, and a raw PACK section.
func buildMultiCommandStream(t *testing.T, old, new1, new2 string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	mustEncode(t, e, old+" "+new1+" refs/heads/main\x00 report-status atomic\n")
	mustEncode(t, e, old+" "+new2+" refs/tags/v1\n")
	mustFlush(t, e)
	buf.WriteString("PACK\x00\x00\x00\x02dummy-packfile-bytes")
	return &buf
}
