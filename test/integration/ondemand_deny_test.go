package integration

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnDemandDeny_AdvertisesFilterAndAllowReachableSha1 asserts the
// read-protected info/refs advertisement re-emitted by the proxy carries the
// `filter` cap (so the client may request --filter=blob:none) and the
// `allow-reachable-sha1-in-want` cap. The latter is REQUIRED for the on-demand
// blob-denial flow: after a partial clone, the agent's lazy fetch of a missing
// blob sends `want <blob-oid>`, and the client refuses to even send that want
// ("Server does not allow request for unadvertised object ...") unless the
// server advertised `allow-reachable-sha1-in-want`. Without it, on-demand blob
// wants never reach the proxy and Task 10's deny path is unreachable. This test
// pins the cap so a future maintainer who drops it breaks this test (and the
// on-demand deny flow it enables).
func TestOnDemandDeny_AdvertisesFilterAndAllowReachableSha1(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	resp, err := http.Get(h.ProxyURL + "/test.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET info/refs: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	// The capabilities are on the first ref line after a NUL. Find the caps line.
	capsLine := ""
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "\x00") {
			capsLine = line
			break
		}
	}
	if capsLine == "" {
		t.Fatalf("no capability line (NUL) in read-protected advertisement:\n%s", s)
	}
	for _, want := range []string{"filter", "allow-reachable-sha1-in-want"} {
		if !strings.Contains(capsLine, want) {
			t.Errorf("read-protected advertisement missing cap %q; caps line = %q", want, capsLine)
		}
	}
}

// TestOnDemandDeny_AllowedServed_DeniedRefused is the M7b acceptance test for
// on-demand blob denial. A real `git clone --filter=blob:none` through the
// read-protected proxy leaves the clone with the denied blob absent (withheld
// from the initial packfile by Task 9) and the allowed blobs present (served
// in the initial packfile). Then:
//
//   - Reading a DENIED file (secrets/secret.txt) triggers an on-demand fetch the
//     proxy REFUSES with an `ERR <reason>\n` pkt-line (Task 10: the blob's path
//     matches the deny matcher); git surfaces the error and the content is NOT
//     retrieved. The denied blob OID stays absent from the clone's object store.
//   - Reading an ALLOWED file (docs/guide.md) succeeds and the content is
//     present (served in the initial packfile).
//   - The allowed on-demand SERVE path is then exercised end-to-end by forcing
//     the allowed blob ABSENT (unpack + delete the loose object) and reading the
//     file again: the clone's git issues an on-demand `want <blob-oid>` through
//     the proxy, the proxy classifies the blob want, resolves it to
//     "docs/guide.md", finds it is NOT denied, and SERVES the blob — the read
//     succeeds and the blob becomes present again.
//
// This closes the Task 9 gap: Task 9 withholds the denied blob from a FULL
// CLONE's packfile, but an on-demand fetch sends `want <blob-oid>` whose
// rev-list --objects yields the blob with NO path, so Task 9's matcher had
// nothing to match and the denied blob was served. Task 10 resolves the OID
// back to its path(s) and refuses denied on-demand blobs with a structured ERR
// while serving allowed ones.
//
// Note (flagged): the proxy does NOT honor `--filter=blob:none` by omitting
// allowed blobs from the initial packfile (existing Task 9 behavior, kept
// green by TestReadProtection_CloneWithholdsSecretBlob). Allowed blobs are
// therefore present right after clone, so the allowed on-demand SERVE path is
// exercised by forcing the blob absent (unpack + delete) rather than by the
// clone itself. The denied on-demand REFUSE path triggers naturally because
// the denied blob is withheld from the initial packfile.
func TestOnDemandDeny_AllowedServed_DeniedRefused(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	// Partial clone through the proxy with --no-checkout so the clone's
	// checkout does not abort on the denied blob's missing-object pre-fetch
	// (the denied blob is withheld from the initial packfile by Task 9; the
	// checkout-time pre-fetch for it would be denied by Task 10 and abort).
	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", "--filter=blob:none", "--no-checkout",
		h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (logged; --no-checkout avoids checkout abort): %v\n%s", err, out)
	}

	// Resolve the blob OIDs directly from the upstream bare repo (bypassing
	// the proxy) so assertions compare against the real object ids.
	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:secrets/secret.txt"))
	guideOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:docs/guide.md"))
	if secretOID == "" || guideOID == "" {
		t.Fatalf("could not resolve blob OIDs (secret=%q guide=%q)", secretOID, guideOID)
	}

	// Right after the clone: the denied blob is ABSENT (withheld); the allowed
	// blob is PRESENT (served in the initial packfile — existing Task 9
	// behavior, not honoring --filter=blob:none for allowed blobs).
	present := presentObjectOIDs(t, dst)
	if present[secretOID] {
		t.Fatalf("setup invariant: denied blob %s present after clone (Task 9 should have withheld it)", secretOID)
	}
	if !present[guideOID] {
		t.Fatalf("setup invariant: allowed blob %s (docs/guide.md) absent after clone (Task 9 should have served it)", guideOID)
	}

	// --- DENIED on-demand fetch is REFUSED ---
	// Reading the denied file triggers an on-demand fetch (the blob is absent);
	// the proxy refuses it with ERR (Task 10).
	secretCmd := h.Git(dst, "cat-file", "-p", "HEAD:secrets/secret.txt")
	secretOut, err := secretCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("DENY LEAK: on-demand fetch of DENIED secrets/secret.txt SUCCEEDED (must be refused); got %q", secretOut)
	}
	const canary = "TOP-SECRET-VALUE-DO-NOT-LEAK"
	if strings.Contains(string(secretOut), canary) {
		t.Errorf("DENY LEAK: secret canary appeared in the denied on-demand fetch output: %q", secretOut)
	}
	if len(secretOut) == 0 {
		t.Errorf("denied on-demand fetch produced no output; expected git to surface the proxy ERR")
	}
	// git surfaces the proxy's structured ERR reason ("access to object <oid>
	// denied by read policy") — proving the refusal is Task 10's on-demand deny,
	// not a generic/empty failure.
	if !strings.Contains(string(secretOut), "denied by read policy") {
		t.Errorf("denied on-demand fetch output = %q, want it to surface the proxy ERR reason containing %q", secretOut, "denied by read policy")
	}
	// The denied blob must STILL be absent (the refused fetch retrieved nothing).
	present = presentObjectOIDs(t, dst)
	if present[secretOID] {
		t.Errorf("DENY LEAK: denied blob %s became PRESENT after the refused on-demand fetch (must stay absent)", secretOID)
	}

	// --- ALLOWED blob content is present (served in the initial packfile) ---
	guideOut, err := h.Git(dst, "cat-file", "-p", "HEAD:docs/guide.md").Output()
	if err != nil {
		t.Fatalf("reading ALLOWED docs/guide.md failed (content should be present): %v\n%s", err, guideOut)
	}
	if string(guideOut) != "public guide\n" {
		t.Errorf("ALLOWED docs/guide.md content = %q, want %q", string(guideOut), "public guide\n")
	}

	// --- ALLOWED on-demand SERVE path, end-to-end ---
	// Force the allowed blob ABSENT (unpack the pack to loose objects, remove
	// the pack, then delete the blob's loose object) so reading the file issues
	// an on-demand `want <blob-oid>` through the proxy. The proxy must classify
	// the blob want, resolve it to "docs/guide.md", find it is NOT denied, and
	// SERVE the blob.
	if err := forceBlobAbsent(t, dst, guideOID); err != nil {
		t.Fatalf("forceBlobAbsent: %v", err)
	}
	// Sanity: the allowed blob is now absent.
	if presentObjectOIDs(t, dst)[guideOID] {
		t.Fatalf("forceBlobAbsent did not make the allowed blob %s absent", guideOID)
	}
	// Reading the allowed file now triggers an on-demand fetch that MUST SUCCEED.
	guideOut2, err := h.Git(dst, "cat-file", "-p", "HEAD:docs/guide.md").Output()
	if err != nil {
		t.Fatalf("ALLOWED on-demand fetch of docs/guide.md FAILED (should succeed): %v\n%s", err, guideOut2)
	}
	if string(guideOut2) != "public guide\n" {
		t.Errorf("ALLOWED on-demand fetch content = %q, want %q", string(guideOut2), "public guide\n")
	}
	// The allowed blob is now present again (the on-demand fetch retrieved it).
	present = presentObjectOIDs(t, dst)
	if !present[guideOID] {
		t.Errorf("allowed blob %s (docs/guide.md) ABSENT after the successful on-demand fetch (must be present)", guideOID)
	}
}

// forceBlobAbsent removes the loose object for oid from dst's object store so
// the next access triggers an on-demand fetch. It unpacks the clone's pack to
// loose objects, removes the pack, then deletes the specific loose object. The
// tree/commit objects remain (as loose objects), so `git cat-file -p
// HEAD:<path>` still resolves the path to the (now-missing) blob OID and issues
// an on-demand fetch.
func forceBlobAbsent(t *testing.T, dst, oid string) error {
	t.Helper()
	packDir := filepath.Join(dst, ".git", "objects", "pack")
	entries, err := os.ReadDir(packDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pack") {
			continue
		}
		packPath := filepath.Join(packDir, e.Name())
		f, err := os.Open(packPath)
		if err != nil {
			return err
		}
		// unpack-objects writes loose objects for every object in the pack.
		unpack := exec.Command("git", "-C", dst, "-c", "gc.auto=0", "unpack-objects")
		unpack.Stdin = f
		_, uerr := unpack.CombinedOutput()
		_ = f.Close()
		if uerr != nil {
			return err_unpack{err: uerr}
		}
	}
	// Remove all pack files (objects are now loose).
	if err := os.RemoveAll(packDir); err != nil {
		return err
	}
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		return err
	}
	// Delete the specific blob's loose object: .git/objects/<aa>/<rest>.
	looseDir := filepath.Join(dst, ".git", "objects", oid[:2])
	loosePath := filepath.Join(looseDir, oid[2:])
	if err := os.Remove(loosePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

type err_unpack struct {
	err error
}

func (e err_unpack) Error() string { return e.err.Error() }