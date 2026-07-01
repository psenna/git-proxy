package gitproto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// TestEmitRefAdvertisementV0 verifies the v0 re-emitter: it writes the service
// banner + flush, the ref list (first ref carries capabilities after a NUL),
// and a terminating flush, with the extra capabilities (filter) appended and
// any `version 2` capability stripped (the read-protected path is v0-only, so
// the client must not see version 2 and fall back to v0 for upload-pack).
func TestEmitRefAdvertisementV0(t *testing.T) {
	adv := &gitproto.RefAdvertisement{
		Service: "git-upload-pack",
		Refs: []gitproto.AdvertisedRef{
			{Hash: "1111111111111111111111111111111111111111", Name: "HEAD"},
			{Hash: "2222222222222222222222222222222222222222", Name: "refs/heads/main"},
		},
		Caps: []string{"multi_ack", "thin-pack", "side-band-64k", "ofs-delta", "version 2", "agent=git/x"},
	}
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementV0(&buf, adv, []string{"filter"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	s := pktline.NewScanner(bytes.NewReader(buf.Bytes()))
	// Service banner.
	if !s.Scan() || s.Marker() != pktline.Data || string(s.Bytes()) != "# service=git-upload-pack\n" {
		t.Fatalf("service banner = marker=%v %q", s.Marker(), s.Bytes())
	}
	// Flush after banner.
	if !s.Scan() || s.Marker() != pktline.Flush {
		t.Fatalf("expected flush after service banner, got %v", s.Marker())
	}
	// First ref line carries caps after NUL.
	if !s.Scan() || s.Marker() != pktline.Data {
		t.Fatalf("expected first ref line, got %v", s.Marker())
	}
	line := string(s.Bytes())
	if !strings.HasPrefix(line, "1111111111111111111111111111111111111111 HEAD\x00") {
		t.Fatalf("first ref line missing NUL cap separator: %q", line)
	}
	capPart := line[strings.Index(line, "\x00")+1:]
	caps := strings.Fields(strings.TrimRight(capPart, "\n"))
	if !containsStr(caps, "filter") {
		t.Errorf("caps missing filter; got %v", caps)
	}
	if !containsStr(caps, "thin-pack") || !containsStr(caps, "side-band-64k") || !containsStr(caps, "ofs-delta") {
		t.Errorf("caps dropped original v0 caps; got %v", caps)
	}
	if containsStr(caps, "version 2") {
		t.Errorf("version 2 must be stripped (read-protected path is v0-only); got %v", caps)
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

// TestEmitRefAdvertisementV0_RoundTrip parses a real v0 advertisement and
// re-emits it, asserting the refs are preserved verbatim and only filter is
// added (the read-protected proxy re-emits refs verbatim as v0).
func TestEmitRefAdvertisementV0_RoundTrip(t *testing.T) {
	data := fixture(t, "upload-pack-info-refs.bin")
	adv, err := gitproto.ParseRefAdvertisement(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementV0(&buf, adv, []string{"filter"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	reAdv, err := gitproto.ParseRefAdvertisement(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if reAdv.Service != adv.Service {
		t.Errorf("service = %q, want %q", reAdv.Service, adv.Service)
	}
	if len(reAdv.Refs) != len(adv.Refs) {
		t.Fatalf("refs count = %d, want %d", len(reAdv.Refs), len(adv.Refs))
	}
	for i, r := range adv.Refs {
		if reAdv.Refs[i] != r {
			t.Errorf("ref[%d] = %+v, want %+v", i, reAdv.Refs[i], r)
		}
	}
	if !containsStr(reAdv.Caps, "filter") {
		t.Errorf("re-emitted caps missing filter; got %v", reAdv.Caps)
	}
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}