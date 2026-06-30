package gitproto_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
)

// fixture reads a golden protocol byte stream from test/integration/fixtures.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// The fixtures live under the integration test package directory; resolve
	// them relative to this package.
	paths := []string{
		filepath.Join("..", "integration", "fixtures", name),
		filepath.Join("..", "..", "test", "integration", "fixtures", name),
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Fatalf("fixture %s not found", name)
	return nil
}

// isHexSHA returns true if s is a 40-char lowercase hex string (a git SHA-1).
func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// TestParseRefAdvertisementUploadPack parses a recorded git-upload-pack info/refs
// stream and asserts the service, refs, and capabilities are extracted.
func TestParseRefAdvertisementUploadPack(t *testing.T) {
	data := fixture(t, "upload-pack-info-refs.bin")
	adv, err := gitproto.ParseRefAdvertisement(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.Service != "git-upload-pack" {
		t.Fatalf("service = %q, want git-upload-pack", adv.Service)
	}
	// Expect at least HEAD and refs/heads/main.
	wantRefs := map[string]bool{"HEAD": false, "refs/heads/main": false}
	for _, ref := range adv.Refs {
		if !isHexSHA(ref.Hash) {
			t.Fatalf("ref %q hash = %q, want 40-hex", ref.Name, ref.Hash)
		}
		if _, ok := wantRefs[ref.Name]; ok {
			wantRefs[ref.Name] = true
		}
	}
	for name, found := range wantRefs {
		if !found {
			t.Fatalf("ref %q missing from advertisement", name)
		}
	}
	// HEAD carries capabilities after the NUL.
	if len(adv.Caps) == 0 {
		t.Fatalf("expected capabilities, got none")
	}
	// A representative capability must be present.
	has := func(want string) bool {
		for _, c := range adv.Caps {
			if c == want || strings.HasPrefix(c, want) {
				return true
			}
		}
		return false
	}
	if !has("ofs-delta") {
		t.Fatalf("missing ofs-delta capability, got %v", adv.Caps)
	}
	if !has("agent=") {
		t.Fatalf("missing agent= capability, got %v", adv.Caps)
	}
}

// TestParseRefAdvertisementReceivePack parses a recorded git-receive-pack
// info/refs stream and asserts its receive-pack capabilities are extracted.
func TestParseRefAdvertisementReceivePack(t *testing.T) {
	data := fixture(t, "receive-pack-info-refs.bin")
	adv, err := gitproto.ParseRefAdvertisement(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if adv.Service != "git-receive-pack" {
		t.Fatalf("service = %q, want git-receive-pack", adv.Service)
	}
	has := func(want string) bool {
		for _, c := range adv.Caps {
			if c == want || strings.HasPrefix(c, want) {
				return true
			}
		}
		return false
	}
	if !has("report-status") {
		t.Fatalf("missing report-status capability, got %v", adv.Caps)
	}
}

// TestParseUploadPackRequest parses a recorded want/done request and asserts
// the wants and capabilities are extracted.
func TestParseUploadPackRequest(t *testing.T) {
	data := fixture(t, "upload-pack-request.bin")
	req, err := gitproto.ParseUploadPackRequest(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Wants) != 1 {
		t.Fatalf("wants = %v, want 1", req.Wants)
	}
	if !isHexSHA(req.Wants[0]) {
		t.Fatalf("want[0] = %q, want 40-hex", req.Wants[0])
	}
	if !req.Done {
		t.Fatalf("done = false, want true")
	}
	if len(req.Haves) != 0 {
		t.Fatalf("haves = %v, want none", req.Haves)
	}
	if len(req.Caps) == 0 {
		t.Fatalf("expected capabilities on first want, got none")
	}
	has := func(want string) bool {
		for _, c := range req.Caps {
			if c == want {
				return true
			}
		}
		return false
	}
	if !has("side-band-64k") {
		t.Fatalf("missing side-band-64k capability, got %v", req.Caps)
	}
}

// TestParseUploadPackRequestWantHave parses a synthetic negotiation with
// multiple wants, haves, and done, verifying the parser handles the full
// request shape.
func TestParseUploadPackRequestWantHave(t *testing.T) {
	// Build a realistic request with the codec.
	stream := buildWantHaveStream(t,
		"0000000000000000000000000000000000000001",
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222")
	req, err := gitproto.ParseUploadPackRequest(stream)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(req.Wants) != 2 || req.Wants[0] != "0000000000000000000000000000000000000001" {
		t.Fatalf("wants = %v", req.Wants)
	}
	if len(req.Haves) != 1 || req.Haves[0] != "2222222222222222222222222222222222222222" {
		t.Fatalf("haves = %v", req.Haves)
	}
	if !req.Done {
		t.Fatalf("done = false")
	}
	if len(req.Caps) != 2 || req.Caps[0] != "ofs-delta" || req.Caps[1] != "no-progress" {
		t.Fatalf("caps = %v", req.Caps)
	}
}