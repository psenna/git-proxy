package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/config"
)

// policyReadDeny returns a PolicyConfig that enables proxy-level read
// protection with the given deny patterns (no engine rules — read protection is
// a proxy-level path matcher, not an engine rule).
func policyReadDeny(patterns ...string) config.PolicyConfig {
	return config.PolicyConfig{
		Read: config.ReadConfig{Deny: patterns},
	}
}

// seedProtectedFiles advances the upstream bare repo (via file://, bypassing the
// proxy) with a public file (docs/guide.md) and a secret file
// (secrets/secret.txt) carrying a canary value that must never appear in the
// clone. The harness's seedUpstream already created README.md ("# test\n").
func seedProtectedFiles(t *testing.T, h *Harness) {
	t.Helper()
	work := t.TempDir()
	mustRun(t, "git", "clone", "-q", "file://"+h.BarePath, work)
	mustRun(t, "git", "-C", work, "config", "user.email", "test@example.com")
	mustRun(t, "git", "-C", work, "config", "user.name", "Test")
	if err := os.MkdirAll(filepath.Join(work, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "docs", "guide.md"), []byte("public guide\n"), 0o644); err != nil {
		t.Fatalf("write docs/guide.md: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(work, "secrets"), 0o755); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "secrets", "secret.txt"), []byte("TOP-SECRET-VALUE-DO-NOT-LEAK\n"), 0o644); err != nil {
		t.Fatalf("write secrets/secret.txt: %v", err)
	}
	mustRun(t, "git", "-C", work, "add", "docs/guide.md", "secrets/secret.txt")
	mustRun(t, "git", "-C", work, "commit", "-q", "-m", "add guide and secret")
	mustRun(t, "git", "-C", work, "push", "-q", "origin", "main")
}

// presentObjectOIDs runs `git cat-file --batch-all-objects --batch-check
// --unordered` in dir, which lists ONLY objects present in the local object
// store (loose + packed) without triggering any promisor/on-demand fetch. It
// returns the set of present OIDs. This is the fail-safe way to inspect what the
// packfile actually delivered, without the on-demand fetch path (Task 10)
// pulling missing objects in.
func presentObjectOIDs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "cat-file", "--batch-all-objects", "--batch-check", "--unordered").Output()
	if err != nil {
		t.Fatalf("cat-file --batch-all-objects in %s: %v", dir, err)
	}
	present := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			present[f[0]] = true
		}
	}
	return present
}

// TestReadProtection_CloneWithholdsSecretBlob is the v1 acceptance test for
// read protection. A real `git clone --filter=blob:none` through the
// read-protected proxy must receive a packfile that OMITS the denied secret
// blob (the agent can never read it from the served packfile) while delivering
// the non-denied blobs (README.md, docs/guide.md). The proxy re-emits the
// upstream advertisement as v0 + filter cap and assembles the packfile itself,
// withholding blobs whose path matches the deny matcher.
//
// What is asserted (the packfile-withholding guarantee, Task 9's scope):
//   - The denied secret blob OID is NOT in the clone's local object store right
//     after clone (inspected via --batch-all-objects, which does not trigger the
//     on-demand fetch path that is Task 10's territory).
//   - The non-denied blob OIDs (README.md, docs/guide.md) ARE present, proving
//     the proxy delivered the rest of the repo.
//   - The secret canary string never appears in the received packfile bytes.
//
// What is deliberately NOT asserted here (out of v1 / Task 10's scope):
//   - The on-demand lazy fetch of a denied blob (e.g. `git cat-file -p <oid>`)
//     is denied. Task 9 withholds the blob from the served packfile; the on-demand
//     fetch path is implemented and denied by Task 10 (M7b). Until Task 10, a
//     direct `git cat-file -p <denied-oid>` may still pull the blob via the lazy
//     promisor fetch — that is the next milestone's fix, documented in the report.
//   - A populated working tree: `git clone --filter=blob:none` of a
//     read-protected repo fails the checkout pre-fetch for the denied blob (it
//     is missing and the on-demand fetch is denied), which aborts checkout
//     before any file is written. The non-denied blobs ARE delivered (present in
//     the object store) and can be materialized with `git restore --source=HEAD`
//     once the denied blob is handled. A plain (non-filter) clone of a
//     read-protected repo is NOT supported in v1 (the missing denied blob breaks
//     checkout with no promisor fallback); use --filter=blob:none. This is the
//     documented plain-clone limitation.
func TestReadProtection_CloneWithholdsSecretBlob(t *testing.T) {
	h := StartWithPolicy(t, "test.git", policyReadDeny("secrets/**"))
	seedProtectedFiles(t, h)

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	// Partial clone through the proxy. Checkout aborts on the denied blob's
	// missing-object pre-fetch, so a non-zero exit is expected and acceptable;
	// the clone still creates the repo and indexes the served packfile.
	cmd := h.Git(clone, "clone", "--filter=blob:none", h.UpstreamURL+"/test.git", dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("clone exit (expected — denied blob withheld): %v\n%s", err, out)
	}

	// Resolve the blob OIDs directly from the upstream bare repo (bypassing the
	// proxy) so the assertions compare against the real object ids.
	secretOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:secrets/secret.txt"))
	readmeOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:README.md"))
	guideOID := strings.TrimSpace(mustOutput(t, "git", "-C", h.BarePath, "rev-parse", "HEAD:docs/guide.md"))

	// Inspect the clone's local object store WITHOUT triggering any on-demand
	// fetch (--batch-all-objects lists only objects already present).
	present := presentObjectOIDs(t, dst)

	if present[secretOID] {
		t.Errorf("DENY LEAK: denied secret blob %s is present in the clone's object store (packfile withholding failed)", secretOID)
	}
	if !present[readmeOID] {
		t.Errorf("non-denied blob %s (README.md) missing from clone — other files must clone fine", readmeOID)
	}
	if !present[guideOID] {
		t.Errorf("non-denied blob %s (docs/guide.md) missing from clone — other files must clone fine", guideOID)
	}

	// Belt-and-suspenders: the secret canary must not appear anywhere in the
	// received packfile bytes (the on-demand fetch path is not exercised here —
	// this greps the pack data the proxy actually served).
	const canary = "TOP-SECRET-VALUE-DO-NOT-LEAK"
	if packs, _ := filepath.Glob(filepath.Join(dst, ".git", "objects", "pack", "*.pack")); len(packs) > 0 {
		for _, p := range packs {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Logf("read pack %s: %v", p, err)
				continue
			}
			if strings.Contains(string(b), canary) {
				t.Errorf("DENY LEAK: secret canary found in served packfile %s", p)
			}
		}
	}
}

// TestReadProtection_OffClonesFully verifies that with read protection OFF (no
// policy.read.deny), a plain clone through the proxy produces a full working
// clone including the secret file — the existing passthrough behavior is
// preserved and a non-denied repo clones fully. This guards against a
// regression where read-protection wiring accidentally withholds objects when
// it should be off, and confirms push/auth/passthrough tests stay green.
func TestReadProtection_OffClonesFully(t *testing.T) {
	// No read deny patterns → read protection OFF → passthrough.
	h := StartWithPolicy(t, "test.git", config.PolicyConfig{})
	seedProtectedFiles(t, h)

	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	h.RunGit(t, clone, "clone", "-q", h.UpstreamURL+"/test.git", dst)

	// The secret file must be present with its content (no withholding).
	b, err := os.ReadFile(filepath.Join(dst, "secrets", "secret.txt"))
	if err != nil {
		t.Fatalf("secret file missing from plain clone (read protection off): %v", err)
	}
	if string(b) != "TOP-SECRET-VALUE-DO-NOT-LEAK\n" {
		t.Errorf("secret content = %q, want the full secret", string(b))
	}
	// The public files clone fully too.
	if g, err := os.ReadFile(filepath.Join(dst, "docs", "guide.md")); err != nil || string(g) != "public guide\n" {
		t.Errorf("docs/guide.md = %q err=%v, want %q", string(g), err, "public guide\n")
	}
}