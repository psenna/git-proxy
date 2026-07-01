package gitproto_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/pathmatch"
)

// readRepoForProtection builds a source repo with a normal file (README.md), a
// nested normal file (docs/guide.md), and a secret file (secrets/secret.txt) so
// the read-protection tests can assert the secret blob is withheld while the
// normal files clone fine. Returns the source dir and the tip SHA.
func readRepoForProtection(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", dir)
	mustGit(t, dir, "config", "user.email", "test@example.com")
	mustGit(t, dir, "config", "user.name", "Test")
	writeFile(t, dir, "README.md", "# public readme\n")
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	writeFile(t, dir, "docs/guide.md", "guide content\n")
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o755); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	writeFile(t, dir, "secrets/secret.txt", "TOP-SECRET-VALUE-DO-NOT-LEAK\n")
	mustGit(t, dir, "add", "README.md", "docs/guide.md", "secrets/secret.txt")
	mustGit(t, dir, "commit", "-q", "-m", "add public and secret files")
	return dir, revParseHead(t, dir)
}

// readProtectionMirror builds a mirror over a bare upstream seeded from
// sourceDir's main branch, refreshed, and returns it.
func readProtectionMirror(t *testing.T, sourceDir string) *gitx.Mirror {
	t.Helper()
	ctx := context.Background()
	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "repo.git")
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, sourceDir, "push", "-q", "file://"+bare, "main")
	m, err := gitx.Open(ctx, "file://"+bareRoot, "repo.git", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("gitx.Open: %v", err)
	}
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return m
}

// uploadPackRequest builds a v0 upload-pack request wanting tip, advertising
// side-band-64k, thin-pack, ofs-delta, no-progress (what a real git clone
// client sends). When sideband=false, side-band-64k is omitted to exercise the
// raw packfile path.
func uploadPackRequest(t *testing.T, tip string, sideband bool) *gitproto.UploadPackRequest {
	t.Helper()
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	caps := "ofs-delta thin-pack"
	if sideband {
		caps += " side-band-64k"
	}
	caps += " no-progress"
	if err := e.EncodeString("want " + tip + " " + caps + "\n"); err != nil {
		t.Fatalf("encode want: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := e.EncodeString("done\n"); err != nil {
		t.Fatalf("encode done: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	req, err := gitproto.ParseUploadPackRequest(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return req
}

// uploadPackRequestWants builds a v0 upload-pack request wanting the given OIDs
// (one want line each; caps attach to the first). Used by the on-demand tests to
// send a BLOB oid as a want (what the agent's git sends after a
// --filter=blob:none clone when it lazily fetches a specific blob). When
// sideband=false, side-band-64k is omitted.
func uploadPackRequestWants(t *testing.T, sideband bool, wants ...string) *gitproto.UploadPackRequest {
	t.Helper()
	if len(wants) == 0 {
		t.Fatalf("uploadPackRequestWants: at least one want required")
	}
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	caps := "ofs-delta thin-pack"
	if sideband {
		caps += " side-band-64k"
	}
	caps += " no-progress"
	for i, w := range wants {
		line := "want " + w
		if i == 0 {
			line += " " + caps
		}
		line += "\n"
		if err := e.EncodeString(line); err != nil {
			t.Fatalf("encode want: %v", err)
		}
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := e.EncodeString("done\n"); err != nil {
		t.Fatalf("encode done: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	req, err := gitproto.ParseUploadPackRequest(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return req
}

// assertUploadPackErr asserts resp is a single `ERR <reason>\n` data pkt-line
// with no NAK, no packfile, and no flush — the on-demand deny response. Returns
// the decoded reason for further assertions.
func assertUploadPackErr(t *testing.T, resp []byte) string {
	t.Helper()
	r := bytes.NewReader(resp)
	s := pktline.NewScanner(r)
	if !s.Scan() {
		t.Fatalf("no ERR pkt-line; scan err=%v", s.Err())
	}
	if s.Marker() != pktline.Data {
		t.Fatalf("first pkt-line marker=%v, want Data (ERR)", s.Marker())
	}
	const prefix = "ERR "
	payload := string(s.Bytes())
	if !strings.HasPrefix(payload, prefix) || !strings.HasSuffix(payload, "\n") {
		t.Fatalf("ERR pkt-line payload = %q, want \"ERR <reason>\\n\"", payload)
	}
	if s.Scan() {
		t.Fatalf("unexpected second pkt-line after ERR (no packfile/NAK/flush expected): marker=%v bytes=%q", s.Marker(), s.Bytes())
	}
	return strings.TrimSuffix(strings.TrimPrefix(payload, prefix), "\n")
}

// demuxSidebandPack expects resp to begin with a NAK pkt-line followed by a
// side-band-64k muxed packfile and a terminating flush; it returns the demuxed
// packfile bytes (channel 1).
func demuxSidebandPack(t *testing.T, resp []byte) []byte {
	t.Helper()
	r := bytes.NewReader(resp)
	s := pktline.NewScanner(r)
	if !s.Scan() {
		t.Fatalf("no NAK pkt-line; scan err=%v", s.Err())
	}
	if s.Marker() != pktline.Data || string(s.Bytes()) != "NAK\n" {
		t.Fatalf("first pkt-line = marker=%v bytes=%q, want NAK\\n", s.Marker(), s.Bytes())
	}
	d := sideband.NewDemuxer(sideband.Sideband64k, r)
	pack, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("demux packfile: %v", err)
	}
	return pack
}

// rawPackAfterNAK expects resp to begin with a NAK pkt-line followed by a raw
// packfile (no sideband); returns the raw packfile bytes.
func rawPackAfterNAK(t *testing.T, resp []byte) []byte {
	t.Helper()
	r := bytes.NewReader(resp)
	s := pktline.NewScanner(r)
	if !s.Scan() || s.Marker() != pktline.Data || string(s.Bytes()) != "NAK\n" {
		t.Fatalf("expected NAK pkt-line first, got marker=%v bytes=%q err=%v", s.Marker(), s.Bytes(), s.Err())
	}
	// Remaining bytes are the raw packfile.
	pack, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read raw pack: %v", err)
	}
	return pack
}

// assertPackHasBlobOIDs indexes pack (inside mirrorDir) and asserts the listed
// OIDs are PRESENT and the listed OIDs are ABSENT.
func assertPackHasBlobOIDs(t *testing.T, mirrorDir string, pack []byte, wantPresent, wantAbsent []string) {
	t.Helper()
	got := indexPackGitProto(t, mirrorDir, pack)
	for _, oid := range wantPresent {
		if !got[oid] {
			t.Errorf("pack missing expected blob %s; got %v", oid, sortedKeysGitProto(got))
		}
	}
	for _, oid := range wantAbsent {
		if got[oid] {
			t.Errorf("pack MUST NOT contain withheld blob %s; got %v", oid, sortedKeysGitProto(got))
		}
	}
}

// TestServeUploadPackEnforced_DenyWithholdsSecretBlob is the core read-protection
// guarantee: with a deny matcher on "secrets/**", the served packfile MUST omit
// the secrets/secret.txt blob while keeping the README.md and docs/guide.md
// blobs and all commits/trees. The response is a v0 upload-pack stream (NAK +
// side-band-64k muxed packfile + flush) a real git client can consume.
func TestServeUploadPackEnforced_DenyWithholdsSecretBlob(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tip := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	// Resolve the blob OIDs so the test can assert presence/absence concretely.
	objs, err := m.WantedObjects(ctx, []string{tip}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	var secretOID, readmeOID, guideOID string
	for _, op := range objs {
		switch op.Path {
		case "secrets/secret.txt":
			secretOID = op.OID
		case "README.md":
			readmeOID = op.OID
		case "docs/guide.md":
			guideOID = op.OID
		}
	}
	if secretOID == "" || readmeOID == "" || guideOID == "" {
		t.Fatalf("missing blob OIDs (secret=%q readme=%q guide=%q) in %+v", secretOID, readmeOID, guideOID, objs)
	}

	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequest(t, tip, true)

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced: %v", err)
	}

	// Response must start with NAK pkt-line and end with a sideband flush-pkt.
	if !bytes.HasPrefix(out.Bytes(), []byte("0008NAK\n")) {
		t.Fatalf("response missing NAK pkt-line prefix; got %x", out.Bytes()[:min(16, out.Len())])
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("0000")) {
		t.Fatalf("sideband response not terminated by flush-pkt 0000; got %x", out.Bytes()[max(0, out.Len()-8):])
	}

	pack := demuxSidebandPack(t, out.Bytes())
	if !bytes.HasPrefix(pack, []byte("PACK")) {
		t.Fatalf("demuxed packfile missing PACK magic; got %x", pack[:min(8, len(pack))])
	}
	assertPackHasBlobOIDs(t, m.Dir(), pack,
		[]string{readmeOID, guideOID}, // public blobs present
		[]string{secretOID})           // secret blob withheld
}

// TestServeUploadPackEnforced_AllowWhenNoDeny verifies that with no deny
// patterns (empty matcher) the full packfile is served — read protection OFF
// at the path level means nothing is withheld.
func TestServeUploadPackEnforced_AllowWhenNoDeny(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tip := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	objs, err := m.WantedObjects(ctx, []string{tip}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	var secretOID, readmeOID string
	for _, op := range objs {
		switch op.Path {
		case "secrets/secret.txt":
			secretOID = op.OID
		case "README.md":
			readmeOID = op.OID
		}
	}

	matcher := pathmatch.New(nil) // no deny patterns → match nothing
	req := uploadPackRequest(t, tip, true)

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced: %v", err)
	}
	pack := demuxSidebandPack(t, out.Bytes())
	assertPackHasBlobOIDs(t, m.Dir(), pack,
		[]string{secretOID, readmeOID}, // everything present
		nil)
}

// TestServeUploadPackEnforced_NonSidebandRawPack verifies the raw (non-sideband)
// response shape: NAK pkt-line followed directly by the raw packfile. A client
// that did not negotiate side-band-64k gets the packfile unmuxed.
func TestServeUploadPackEnforced_NonSidebandRawPack(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tip := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequest(t, tip, false) // no side-band-64k

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced: %v", err)
	}
	pack := rawPackAfterNAK(t, out.Bytes())
	if !bytes.HasPrefix(pack, []byte("PACK")) {
		t.Fatalf("raw packfile missing PACK magic; got %x", pack[:min(8, len(pack))])
	}

	objs, err := m.WantedObjects(ctx, []string{tip}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	var secretOID, readmeOID string
	for _, op := range objs {
		switch op.Path {
		case "secrets/secret.txt":
			secretOID = op.OID
		case "README.md":
			readmeOID = op.OID
		}
	}
	assertPackHasBlobOIDs(t, m.Dir(), pack,
		[]string{readmeOID},
		[]string{secretOID})
}

// TestServeUploadPackEnforced_FailClosedOnBogusWant verifies fail-closed: when
// the wanted object is not in the mirror, rev-list errors and the enforce path
// returns an error (caller MUST deny, no passthrough fallback).
func TestServeUploadPackEnforced_FailClosedOnBogusWant(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, _ := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequest(t, strings.Repeat("1", 40), true) // bogus want

	var out bytes.Buffer
	err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git")
	if err == nil {
		t.Fatalf("expected fail-closed error for bogus want, got nil; response %x", out.Bytes())
	}
	// No packfile bytes must have been written (no unprotected leak).
	if out.Len() != 0 {
		t.Errorf("fail-closed path wrote %d bytes; want 0 (no partial response)", out.Len())
	}
}

// TestServeUploadPackEnforced_FailClosedOnContextCancel verifies a canceled
// context surfaces an error (no unprotected packfile served).
func TestServeUploadPackEnforced_FailClosedOnContextCancel(t *testing.T) {
	gitBinary(t)

	source, tip := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before the call

	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequest(t, tip, true)

	var out bytes.Buffer
	err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git")
	if err == nil {
		t.Fatalf("expected error on canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		// Some git invocations may wrap the cancellation; just assert it failed.
		t.Logf("fail-closed error (acceptable): %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("canceled path wrote %d bytes; want 0", out.Len())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// readRepoWithLargeFile builds a source repo whose payload file is large enough
// that `git pack-objects` produces a packfile LARGER than a single side-band-64k
// muxer frame (MaxPackedSize64k = 65520 bytes). Incompressible random bytes are
// used so compression cannot shrink the pack below the chunk threshold. Returns
// the source dir and the tip SHA.
func readRepoWithLargeFile(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", dir)
	mustGit(t, dir, "config", "user.email", "test@example.com")
	mustGit(t, dir, "config", "user.name", "Test")
	// 256 KiB of pseudo-random (deterministic) bytes — incompressible, so the
	// resulting pack exceeds the 64k muxer frame size and forces multi-chunk
	// streaming. A SHA-256 chain (each block = hash of the previous) yields
	// deterministic, high-entropy bytes that do not compress.
	const total = 256 * 1024
	payload := make([]byte, total)
	h := sha256.Sum256([]byte("git-proxy streaming test seed"))
	for off := 0; off < total; off += sha256.Size {
		h = sha256.Sum256(h[:])
		n := copy(payload[off:], h[:])
		_ = n
	}
	if err := os.WriteFile(filepath.Join(dir, "big.bin"), payload, 0o644); err != nil {
		t.Fatalf("write big.bin: %v", err)
	}
	mustGit(t, dir, "add", "big.bin")
	mustGit(t, dir, "commit", "-q", "-m", "add large incompressible file")
	return dir, revParseHead(t, dir)
}

// TestServeUploadPackEnforced_StreamsMultiChunkPack is the OOM/streaming
// regression test. The served packfile (256 KiB of incompressible data) is
// larger than both the side-band-64k muxer frame (MaxPackedSize64k = 65520) and
// the writeV0UploadPackResponse head-chunk read (4096), so the streaming path
// must split it across multiple muxer frames / io.Copy iterations. It asserts:
//
//   - The side-band-64k (muxed) path produces a response whose demuxed packfile
//     is byte-identical to the buffered PackObjects output (streaming does not
//     corrupt the pack), and the pack is larger than MaxPackedSize64k (proving
//     the multi-chunk path was actually exercised).
//   - The raw (non-sideband) path produces a response whose packfile (after the
//     NAK pkt-line) is byte-identical to the buffered PackObjects output.
//
// This keeps memory bounded by the chunk size regardless of packfile size (no
// unbounded in-memory accumulation), closing the read-path OOM gap.
func TestServeUploadPackEnforced_StreamsMultiChunkPack(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tip := readRepoWithLargeFile(t)
	m := readProtectionMirror(t, source)

	// Resolve the full OID list the enforce path would pack (no deny matcher →
	// nothing withheld, so the served pack equals the full-object pack).
	objs, err := m.WantedObjects(ctx, []string{tip}, nil)
	if err != nil {
		t.Fatalf("WantedObjects: %v", err)
	}
	allOIDs := make([]string, 0, len(objs))
	for _, op := range objs {
		allOIDs = append(allOIDs, op.OID)
	}
	// Reference packfile from the buffered path — the streaming output MUST
	// match it byte-for-byte.
	wantPack, err := m.PackObjects(ctx, allOIDs, false)
	if err != nil {
		t.Fatalf("PackObjects reference: %v", err)
	}
	if len(wantPack) <= 65520 {
		t.Fatalf("reference pack %d bytes is not larger than MaxPackedSize64k (65520); test setup insufficient to exercise multi-chunk streaming", len(wantPack))
	}

	// --- Side-band-64k (muxed) streaming path ---
	matcher := pathmatch.New(nil) // deny nothing → full pack served
	req := uploadPackRequest(t, tip, true)

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced (sideband): %v", err)
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("0008NAK\n")) {
		t.Fatalf("sideband response missing NAK pkt-line prefix; got %x", out.Bytes()[:min(16, out.Len())])
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("0000")) {
		t.Fatalf("sideband response not terminated by flush-pkt 0000; got %x", out.Bytes()[max(0, out.Len()-8):])
	}
	gotPack := demuxSidebandPack(t, out.Bytes())
	if !bytes.Equal(gotPack, wantPack) {
		t.Fatalf("sideband streamed pack = %d bytes, want %d (byte-identical to buffered PackObjects); first diff at %d",
			len(gotPack), len(wantPack), firstDiffOffset(gotPack, wantPack))
	}

	// --- Raw (non-sideband) streaming path ---
	reqRaw := uploadPackRequest(t, tip, false)
	var outRaw bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &outRaw, reqRaw, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced (raw): %v", err)
	}
	gotRawPack := rawPackAfterNAK(t, outRaw.Bytes())
	if !bytes.Equal(gotRawPack, wantPack) {
		t.Fatalf("raw streamed pack = %d bytes, want %d (byte-identical to buffered PackObjects); first diff at %d",
			len(gotRawPack), len(wantPack), firstDiffOffset(gotRawPack, wantPack))
	}
}

// firstDiffOffset returns the index of the first differing byte between a and b,
// or -1 if one is a prefix of the other (or equal). Used by the streaming test to
// pinpoint a corruption offset.
func firstDiffOffset(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

// writeFile writes content to dir/name (helper local to this file since the
// gitx_test writeFile lives in another package).
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// indexPackGitProto mirrors gitx_test.indexPack: writes pack to a temp .pack
// file, runs `git -C mirrorDir index-pack` then `verify-pack -v`, and returns
// the set of OIDs the pack carries.
func indexPackGitProto(t *testing.T, mirrorDir string, pack []byte) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	packPath := filepath.Join(dir, "test.pack")
	if err := os.WriteFile(packPath, pack, 0o600); err != nil {
		t.Fatalf("write test pack: %v", err)
	}
	cmd := exec.Command("git", "-C", mirrorDir, "index-pack", packPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("index-pack: %v\n%s", err, out)
	}
	idx := strings.TrimSuffix(packPath, ".pack") + ".idx"
	out, err := exec.Command("git", "-C", mirrorDir, "verify-pack", "-v", idx).CombinedOutput()
	if err != nil {
		t.Fatalf("verify-pack: %v\n%s", err, out)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 1 && len(f[0]) == 40 && isHex40GitProto(f[0]) {
			set[f[0]] = true
		}
	}
	return set
}

func isHex40GitProto(s string) bool {
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

func sortedKeysGitProto(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- Task 10: on-demand blob fetch classification (M7b) ---
//
// An on-demand fetch's want is a BLOB oid (the agent's git, after a
// --filter=blob:none clone, lazily fetching a specific blob). ServeUploadPack
// Enforced classifies want oids by type: a blob want is the on-demand path
// (resolve OID->path, deny with ERR if any path is denied, else serve); a
// commit/tag/tree want is the full-clone path (existing Task 9 withholding).
// Mixed wants with any denied on-demand blob REFUSE the whole fetch (fail
// closed). Fail-closed on resolve error AND on a blob want that resolves to
// no path (cannot prove it is not a denied blob).

// TestServeUploadPackEnforced_OnDemandBlob_Allow verifies an on-demand blob
// fetch for an ALLOWED blob is SERVED: the response is a normal NAK +
// side-band-64k packfile containing the requested blob (the on-demand path
// resolves the blob's path, finds it is not denied, and falls through to the
// existing packfile-assembly path).
func TestServeUploadPackEnforced_OnDemandBlob_Allow(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, _ := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	// The README.md blob is public; its path "README.md" is not under secrets/**.
	readmeOID := strings.TrimSpace(mustOutput(t, "git", "-C", h_BarePath(t, m), "rev-parse", "HEAD:README.md"))

	// Matcher denies only secrets/** ; README.md is allowed.
	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequestWants(t, true, readmeOID) // blob want

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced: %v", err)
	}
	pack := demuxSidebandPack(t, out.Bytes())
	assertPackHasBlobOIDs(t, m.Dir(), pack, []string{readmeOID}, nil)
}

// TestServeUploadPackEnforced_OnDemandBlob_DenyByPath verifies an on-demand
// blob fetch for a DENIED blob is REFUSED with an ERR pkt-line: the blob's
// path matches the deny matcher, so the proxy writes `ERR <reason>\n` and
// returns with no NAK and no packfile (the agent's git surfaces the error).
func TestServeUploadPackEnforced_OnDemandBlob_DenyByPath(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, _ := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", h_BarePath(t, m), "rev-parse", "HEAD:secrets/secret.txt"))

	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequestWants(t, true, secretOID) // blob want (denied)

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced should return nil after writing ERR, got err=%v", err)
	}
	reason := assertUploadPackErr(t, out.Bytes())
	if !strings.Contains(reason, "denied") {
		t.Errorf("ERR reason = %q, want it to mention denial", reason)
	}
	// The denied OID must NOT appear as a leakable token, and no packfile may
	// have been written. The ERR helper writes exactly one pkt-line (asserted).
	if strings.Contains(reason, "TOP-SECRET") {
		t.Errorf("ERR reason leaked secret content: %q", reason)
	}
}

// TestServeUploadPackEnforced_OnDemandBlob_UnresolvableDeny verifies the
// fail-closed decision for a blob want that resolves to NO path: a blob the
// proxy cannot map to any path must be DENIED (ERR), because the proxy cannot
// prove it is not a denied blob. An orphan blob (present in the mirror's
// object store but referenced by no tree) triggers this.
func TestServeUploadPackEnforced_OnDemandBlob_UnresolvableDeny(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, _ := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	// Write an orphan blob into the MIRROR's object store, not referenced by
	// any tree, so oidpath.Resolve returns no paths.
	cmd := exec.Command("git", "-C", m.Dir(), "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader("orphan-on-demand-blob\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hash-object -w into mirror: %v", err)
	}
	orphanOID := strings.TrimSpace(string(out))

	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequestWants(t, true, orphanOID) // blob want, no resolvable path

	var buf bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &buf, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced should return nil after writing ERR, got err=%v", err)
	}
	reason := assertUploadPackErr(t, buf.Bytes())
	if !strings.Contains(reason, "denied") {
		t.Errorf("ERR reason = %q, want it to mention denial (fail-closed for unresolvable blob)", reason)
	}
}

// TestServeUploadPackEnforced_OnDemandBlob_MixedWantWithDeniedBlob verifies
// that a request mixing a commit want (full clone) with a denied on-demand
// blob want REFUSES the whole fetch with ERR (fail-closed — never partially
// serve a fetch that contains a denied blob the agent explicitly requested).
func TestServeUploadPackEnforced_OnDemandBlob_MixedWantWithDeniedBlob(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tip := readRepoForProtection(t)
	m := readProtectionMirror(t, source)

	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", h_BarePath(t, m), "rev-parse", "HEAD:secrets/secret.txt"))

	matcher := pathmatch.New([]string{"secrets/**"})
	// commit want (full clone) + denied blob want (on-demand) in one request.
	req := uploadPackRequestWants(t, true, tip, secretOID)

	var out bytes.Buffer
	if err := gitproto.ServeUploadPackEnforced(ctx, &out, req, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced should return nil after writing ERR, got err=%v", err)
	}
	assertUploadPackErr(t, out.Bytes())
	// No packfile: the ERR is the only pkt-line (assertUploadPackErr checks).
}

// mustOutput runs a command and returns trimmed stdout, failing the test on a
// non-zero exit (local to this file; the integration package has its own).
func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, ee.Stderr)
		}
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// h_BarePath returns the filesystem path to the bare upstream the mirror was
// cloned from (re-derived from the mirror's remote). The on-demand tests use
// it to rev-parse blob OIDs directly from the upstream bare repo.
func h_BarePath(t *testing.T, m *gitx.Mirror) string {
	t.Helper()
	out, err := exec.Command("git", "-C", m.Dir(), "config", "--get", "remote.origin.url").Output()
	if err != nil {
		t.Fatalf("get remote.origin.url: %v", err)
	}
	u := strings.TrimSpace(string(out))
	// The mirror was opened with file://<bareRoot> and repo "repo.git"; the
	// remote URL is file://<bareRoot>/repo.git. Strip file:// to get the path.
	return strings.TrimPrefix(u, "file://")
}