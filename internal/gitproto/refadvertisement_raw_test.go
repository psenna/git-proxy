package gitproto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// TestEmitRefAdvertisementRaw verifies the raw v0 re-emitter (the SSH git
// protocol form): it writes the ref list with caps on the first ref and a
// terminating flush, with NO "# service=" preamble and NO leading flush.
// Extra caps are appended and `version 2` is stripped (the read-protected
// SSH path is v0-only, like the HTTP read-protected path).
func TestEmitRefAdvertisementRaw(t *testing.T) {
	adv := &gitproto.RefAdvertisement{
		Service: "git-upload-pack",
		Refs: []gitproto.AdvertisedRef{
			{Hash: "1111111111111111111111111111111111111111", Name: "HEAD"},
			{Hash: "2222222222222222222222222222222222222222", Name: "refs/heads/main"},
		},
		Caps: []string{"multi_ack", "thin-pack", "side-band-64k", "ofs-delta", "version 2", "agent=git/x"},
	}
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementRaw(&buf, adv, []string{"filter", "allow-reachable-sha1-in-want"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	s := pktline.NewScanner(bytes.NewReader(buf.Bytes()))
	// NO service banner and NO leading flush: the first pkt-line MUST be the
	// first ref line carrying caps after a NUL.
	if !s.Scan() || s.Marker() != pktline.Data {
		t.Fatalf("expected first ref line as first pkt-line, got marker=%v", s.Marker())
	}
	line := string(s.Bytes())
	if strings.HasPrefix(line, "# service=") {
		t.Fatalf("raw advertisement must NOT carry the smart-HTTP service preamble: %q", line)
	}
	if !strings.HasPrefix(line, "1111111111111111111111111111111111111111 HEAD\x00") {
		t.Fatalf("first ref line missing NUL cap separator: %q", line)
	}
	capPart := line[strings.Index(line, "\x00")+1:]
	caps := strings.Fields(strings.TrimRight(capPart, "\n"))
	if !containsStr(caps, "filter") || !containsStr(caps, "allow-reachable-sha1-in-want") {
		t.Errorf("caps missing extra caps; got %v", caps)
	}
	if !containsStr(caps, "thin-pack") || !containsStr(caps, "side-band-64k") || !containsStr(caps, "ofs-delta") {
		t.Errorf("caps dropped original v0 caps; got %v", caps)
	}
	if containsStr(caps, "version 2") {
		t.Errorf("version 2 must be stripped (raw path is v0-only); got %v", caps)
	}
	// Second ref line, no caps.
	if !s.Scan() || s.Marker() != pktline.Data || string(s.Bytes()) != "2222222222222222222222222222222222222222 refs/heads/main\n" {
		t.Fatalf("second ref line = marker=%v %q", s.Marker(), s.Bytes())
	}
	// Terminating flush.
	if !s.Scan() || s.Marker() != pktline.Flush {
		t.Fatalf("expected terminating flush, got %v (bytes=%q)", s.Marker(), s.Bytes())
	}
	if s.Scan() {
		t.Errorf("unexpected trailing pkt-line: %q", s.Bytes())
	}
}

// TestEmitRefAdvertisementRaw_EmptyRepo verifies the empty-repo pseudo-ref:
// the capabilities are advertised on a line pointing the zero OID at the
// magic name "capabilities^{}" (no refs exist yet). No preamble.
func TestEmitRefAdvertisementRaw_EmptyRepo(t *testing.T) {
	adv := &gitproto.RefAdvertisement{
		Service: "git-upload-pack",
		Refs:    nil,
		Caps:    []string{"multi_ack", "side-band-64k"},
	}
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementRaw(&buf, adv, []string{"filter"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	s := pktline.NewScanner(bytes.NewReader(buf.Bytes()))
	if !s.Scan() || s.Marker() != pktline.Data {
		t.Fatalf("expected cap pseudo-ref line, got marker=%v", s.Marker())
	}
	line := string(s.Bytes())
	if !strings.HasPrefix(line, "0000000000000000000000000000000000000000 capabilities^{}\x00") {
		t.Fatalf("empty-repo pseudo-ref line = %q", line)
	}
	capPart := line[strings.Index(line, "\x00")+1:]
	caps := strings.Fields(strings.TrimRight(capPart, "\n"))
	if !containsStr(caps, "filter") || !containsStr(caps, "side-band-64k") {
		t.Errorf("caps missing expected entries; got %v", caps)
	}
	if !s.Scan() || s.Marker() != pktline.Flush {
		t.Fatalf("expected terminating flush, got %v", s.Marker())
	}
	if s.Scan() {
		t.Errorf("unexpected trailing pkt-line: %q", s.Bytes())
	}
}

// TestEmitRefAdvertisementRaw_VerbatimReemits confirms that with no extra caps
// and no version 2 in the upstream caps, the raw emitter re-emits the refs and
// upstream caps verbatim (the non-read-protected SSH fetch path).
func TestEmitRefAdvertisementRaw_VerbatimReemits(t *testing.T) {
	adv := &gitproto.RefAdvertisement{
		Service: "git-receive-pack",
		Refs: []gitproto.AdvertisedRef{
			{Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "HEAD"},
		},
		Caps: []string{"report-status", "delete-refs"},
	}
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementRaw(&buf, adv, nil); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	s := pktline.NewScanner(bytes.NewReader(buf.Bytes()))
	if !s.Scan() || s.Marker() != pktline.Data {
		t.Fatalf("expected first ref line, got marker=%v", s.Marker())
	}
	line := string(s.Bytes())
	capPart := line[strings.Index(line, "\x00")+1:]
	caps := strings.Fields(strings.TrimRight(capPart, "\n"))
	if len(caps) != 2 || caps[0] != "report-status" || caps[1] != "delete-refs" {
		t.Errorf("verbatim caps = %v, want [report-status delete-refs]", caps)
	}
	if !s.Scan() || s.Marker() != pktline.Flush {
		t.Fatalf("expected terminating flush, got %v", s.Marker())
	}
}