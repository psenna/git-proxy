# Read-Protected Plain-Clone Rejection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a read-protected fetch would withhold a denied-path blob and the client did not request a filtered (partial) fetch, refuse with an actionable `ERR` pkt-line pointing at `--filter=blob:none` instead of serving a structurally-incomplete packfile that fails with a cryptic `missing blob object`.

**Architecture:** A conditional reject inside the existing `ServeUploadPackEnforced` withhold path (after the withheld-blob set is computed, before packfile assembly) — only fires when `withheld > 0 && !clientRequestedFilter(req.Caps)`. It reuses the existing `writeUploadPackErr` helper and mirrors the proven on-demand-deny response shape (write `ERR` to `w`, return a populated `UploadPackEnforceResult` + nil error so the caller's audit mapping records the deny). A new `DeniedReason` field carries the actionable reason into `Proxy.UploadPack`, where the audit-verdict switch is reordered to prefer it over the generic reasons.

**Tech Stack:** Go 1.x, standard `git` CLI (driven via `os/exec` in `internal/gitx` and integration tests), `internal/gitproto/pktline` for pkt-line I/O, `internal/pathmatch` for the deny matcher. Tests are plain `go test` (table-driven unit tests + real-`git` integration tests under `test/integration`).

## Global Constraints

(Copied verbatim from the spec + repo `CLAUDE.md`.)

- Fail-closed: a denied blob is never served in any code path; no passthrough fallback when read protection is on.
- No-leak contract: deny reasons contain no upstream credentials, no secret content, no internal paths/OIDs beyond what is needed. The actionable reason is a single fixed string: `read-protected repository requires a partial clone; retry with --filter=blob:none`.
- OID integrity is preserved: commits and trees stay intact; NO tree/commit rewriting (the "make plain clones transparent" alternative is explicitly rejected).
- v1 invariants preserved: withholding logic, the on-demand blob-deny path, ref advertisement (still advertises `filter`), push enforcement, and passthrough when read protection is off are all unchanged.
- TDD: red → green → commit. Pure logic gets table-driven unit tests; protocol/end-to-end paths get integration tests with a real `git` client.
- One issue per PR; Conventional Commits; every commit green.
- CI gates mandatory before merge: `go vet`, `golangci-lint`, `go build`, `go test`, `govulncheck`. `main` is protected.
- The user has asked that NO commits be made during planning; the plan's `git commit` steps are to be executed by the implementer at implementation time, not now.

## File Structure

- `internal/gitproto/uploadpack_enforce.go` (modify) — add the `DeniedReason` field to `UploadPackEnforceResult`, the `clientRequestedFilter` helper, the `errPlainCloneNeedsFilter` const, and the post-withhold conditional reject. This is the core of the fix.
- `internal/gitproto/uploadpack_enforce_test.go` (modify) — add the `uploadPackRequestFilter` test helper; flip the two deny-matcher packfile tests to use it (Task 1); add the new plain-clone-ERR unit test (Task 2).
- `internal/gitproto/proxy.go` (modify) — reorder the audit-verdict switch in `Proxy.UploadPack` so a non-empty `result.DeniedReason` wins over the generic withheld/on-demand reasons.
- `test/integration/read_protection_test.go` (modify) — add `TestReadProtection_PlainCloneRejectedWithActionableError` driving a real `git` plain clone through the read-protected proxy and asserting the actionable error + audit deny reason.
- `docs/deploy-docker.md` (modify) — add a note near §3 that once `secrets/**` exists, a plain clone is rejected with the actionable message (pointing at `--filter=blob:none`); the existing partial-clone walkthrough is unchanged.

Each file has one responsibility and the change is localized; no new files, no restructuring.

---

## Task 1: Add a `filter`-cap request helper and switch the two deny-matcher packfile tests to it

**Why first:** The fix (Task 2) changes behavior so a non-`filter` request with a reachable denied blob returns `ERR` instead of a withheld packfile. Two existing tests (`DenyWithholdsSecretBlob`, `NonSidebandRawPack`) assert the withheld-packfile path using a non-`filter` request — they would break. This task flips them to a `filter` request *first*, while the old code is still in place. Under the old code `filter` is ignored and the packfile is still withheld, so these tests stay green. This is a pure, green test refactor that prepares the ground for Task 2.

**Files:**
- Modify: `internal/gitproto/uploadpack_enforce_test.go` (add helper after `uploadPackRequest`, ~line 92; change two call sites at ~line 253 and ~line 325)

**Interfaces:**
- Consumes: existing `uploadPackRequest(t, tip, sideband)` helper and `*gitproto.UploadPackRequest.Caps []string`.
- Produces: `uploadPackRequestFilter(t, tip, sideband) *gitproto.UploadPackRequest` — same as `uploadPackRequest` but with the `filter` capability advertised (partial-clone request), matching what a real `git clone --filter=blob:none` sends.

- [ ] **Step 1: Add the `uploadPackRequestFilter` helper**

Insert immediately after the closing `}` of `uploadPackRequest` (around line 92, before the `uploadPackRequestWants` doc comment):

```go
// uploadPackRequestFilter is uploadPackRequest for a partial-clone fetch: the
// request advertises the `filter` capability, exactly as a real
// `git clone --filter=blob:none` does. Used by the deny-matcher packfile tests,
// which must exercise the partial-clone (withhold) path rather than the
// plain-clone ERR path that a non-filter request now triggers.
func uploadPackRequestFilter(t *testing.T, tip string, sideband bool) *gitproto.UploadPackRequest {
	t.Helper()
	req := uploadPackRequest(t, tip, sideband)
	// splitCaps (which parsed req.Caps) splits on whitespace, so a real
	// "filter blob:none" cap appears as two entries. Appending them here
	// reproduces that tokenization; clientRequestedFilter matches on "filter".
	req.Caps = append(req.Caps, "filter", "blob:none")
	return req
}
```

- [ ] **Step 2: Switch `TestServeUploadPackEnforced_DenyWithholdsSecretBlob` to the filter request**

In `TestServeUploadPackEnforced_DenyWithholdsSecretBlob` (around line 253), change:

```go
	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequest(t, tip, true)
```

to:

```go
	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequestFilter(t, tip, true) // partial-clone request → withhold path
```

- [ ] **Step 3: Switch `TestServeUploadPackEnforced_NonSidebandRawPack` to the filter request**

In `TestServeUploadPackEnforced_NonSidebandRawPack` (around line 325), change:

```go
	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequest(t, tip, false) // no side-band-64k
```

to:

```go
	matcher := pathmatch.New([]string{"secrets/**"})
	req := uploadPackRequestFilter(t, tip, false) // partial-clone request, no side-band-64k → raw withhold path
```

- [ ] **Step 4: Run the enforce tests — they must PASS under the old code**

Run: `go test ./internal/gitproto/ -run 'TestServeUploadPackEnforced_(DenyWithholdsSecretBlob|NonSidebandRawPack)' -v`
Expected: PASS for both. The old code ignores the `filter` cap and still withholds the secret blob from the served packfile, so these tests' existing assertions still hold.

- [ ] **Step 5: Run the full gitproto package to confirm no regressions**

Run: `go test ./internal/gitproto/`
Expected: PASS (all existing tests green; the new helper is unused elsewhere).

- [ ] **Step 6: Commit**

```sh
git add internal/gitproto/uploadpack_enforce_test.go
git commit -m "test: switch deny-matcher packfile tests to a filter (partial-clone) request

Prepare for the plain-clone rejection fix: the two deny-matcher packfile
tests (DenyWithholdsSecretBlob, NonSidebandRawPack) currently use a non-filter
request, which the fix will make return ERR. Switch them to a filter request
(partial-clone path) so they keep exercising the withhold-packfile behavior.
Green under the existing code, which ignores the filter cap."
```

---

## Task 2: Reject plain clones of read-protected repos with an actionable ERR (enforce side)

**Files:**
- Modify: `internal/gitproto/uploadpack_enforce.go` — add `DeniedReason` to the struct, the `errPlainCloneNeedsFilter` const, the `clientRequestedFilter` helper, and the conditional reject.
- Modify: `internal/gitproto/uploadpack_enforce_test.go` — add `TestServeUploadPackEnforced_PlainCloneDeniedWithError`.

**Interfaces:**
- Consumes: `req.Caps []string` (from `UploadPackRequest`), the existing `writeUploadPackErr(w, reason) error` helper, the existing `withheld`/`deniedPaths` locals in `ServeUploadPackEnforced`, and the existing `assertUploadPackErr(t, resp) string` test helper.
- Produces:
  - `UploadPackEnforceResult.DeniedReason string` — new field; set to `errPlainCloneNeedsFilter` on the plain-clone reject path, empty otherwise. Consumed by `Proxy.UploadPack` in Task 3.
  - `clientRequestedFilter(caps []string) bool` — unexported helper.
  - `errPlainCloneNeedsFilter` — unexported string const.

- [ ] **Step 1: Write the failing test**

Append to `internal/gitproto/uploadpack_enforce_test.go`:

```go
// TestServeUploadPackEnforced_PlainCloneDeniedWithError verifies the fix: a
// read-protected fetch whose reachable set contains a denied-path blob, made
// WITHOUT the `filter` capability (a plain clone), is REFUSED with an
// actionable `ERR <reason>\n` pkt-line — not a structurally-incomplete packfile
// the client would reject with a cryptic "missing blob object". The reason
// points the agent at --filter=blob:none and leaks no paths/OIDs/secrets.
// The matching fetch WITH `filter` still serves the withheld packfile
// (partial-clone path), asserted as a regression guard.
func TestServeUploadPackEnforced_PlainCloneDeniedWithError(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tip := readRepoForProtection(t)
	m := readProtectionMirror(t, source)
	matcher := pathmatch.New([]string{"secrets/**"})

	// --- Plain clone: no `filter` capability → refused with ERR. ---
	plainReq := uploadPackRequest(t, tip, true) // no filter
	var out bytes.Buffer
	res, err := gitproto.ServeUploadPackEnforced(ctx, &out, plainReq, m, matcher, "repo.git")
	if err != nil {
		t.Fatalf("ServeUploadPackEnforced plain clone: %v (ERR write should succeed; expected nil error)", err)
	}
	reason := assertUploadPackErr(t, out.Bytes())
	const wantReason = "read-protected repository requires a partial clone; retry with --filter=blob:none"
	if reason != wantReason {
		t.Fatalf("ERR reason = %q, want %q", reason, wantReason)
	}
	if res.DeniedReason != wantReason {
		t.Errorf("result.DeniedReason = %q, want %q", res.DeniedReason, wantReason)
	}
	// No secret canary in the response (no-leak).
	if strings.Contains(out.String(), "TOP-SECRET-VALUE-DO-NOT-LEAK") {
		t.Errorf("DENY LEAK: secret canary present in plain-clone ERR response")
	}

	// --- Regression: the same fetch WITH `filter` serves the withheld packfile. ---
	var outFilt bytes.Buffer
	filtReq := uploadPackRequestFilter(t, tip, true)
	if _, err := gitproto.ServeUploadPackEnforced(ctx, &outFilt, filtReq, m, matcher, "repo.git"); err != nil {
		t.Fatalf("ServeUploadPackEnforced filter clone: %v", err)
	}
	if !bytes.HasPrefix(outFilt.Bytes(), []byte("0008NAK\n")) {
		t.Fatalf("filter-clone response should start with a NAK pkt-line + packfile (not ERR); got %x", outFilt.Bytes()[:min(16, outFilt.Len())])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/gitproto/ -run TestServeUploadPackEnforced_PlainCloneDeniedWithError -v`
Expected: FAIL — the old code serves a withheld packfile (starts with `0008NAK\n`), so `assertUploadPackErr` fails with "first pkt-line marker=Data, want Data (ERR)"... actually it fails because the first pkt-line is `NAK\n`, not `ERR ...`. Either way: FAIL (no `ERR` prefix).

- [ ] **Step 3: Add the `DeniedReason` field to `UploadPackEnforceResult`**

In `internal/gitproto/uploadpack_enforce.go`, change the struct (lines 24–27):

```go
type UploadPackEnforceResult struct {
	DeniedPaths []string // blob paths withheld from the packfile (Task 9)
	DeniedOIDs  []string // on-demand blob OIDs refused with ERR (Task 10)
}
```

to:

```go
type UploadPackEnforceResult struct {
	DeniedPaths  []string // blob paths withheld from the packfile (Task 9)
	DeniedOIDs   []string // on-demand blob OIDs refused with ERR (Task 10)
	DeniedReason string   // actionable plain-clone rejection reason (empty otherwise)
}
```

- [ ] **Step 4: Add the `errPlainCloneNeedsFilter` const and `clientRequestedFilter` helper**

Add immediately after the `UploadPackEnforceResult` struct's closing `}` (before the `ServeUploadPackEnforced` doc comment):

```go
// errPlainCloneNeedsFilter is the actionable, fail-closed reason emitted when a
// read-protected fetch would withhold a denied-path blob but the client did not
// request a filtered (partial) fetch. A plain clone cannot tolerate the
// withheld blobs (a tree referencing a missing blob), so the proxy refuses
// rather than serving a structurally-incomplete packfile the client would reject
// with a cryptic "missing blob object". Generic: no credentials, no secret
// content, no paths/OIDs.
const errPlainCloneNeedsFilter = "read-protected repository requires a partial clone; retry with --filter=blob:none"

// clientRequestedFilter reports whether the agent's upload-pack request asked
// for a filtered (partial) fetch — i.e. it advertised the `filter` capability.
// A plain clone/fetch does not, and cannot tolerate the blobs read protection
// withholds, so the caller refuses it with an actionable ERR rather than
// serving a structurally-incomplete packfile.
//
// req.Caps entries are "name" or "name=value"; splitCaps splits on whitespace,
// so a real `filter blob:none` cap appears as two entries ("filter" and
// "blob:none"). Matching the "filter" name in either the bare or name=value
// form covers both tokenizations.
func clientRequestedFilter(caps []string) bool {
	for _, c := range caps {
		if c == "filter" || strings.HasPrefix(c, "filter=") {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Insert the conditional reject after the withhold loop**

In `ServeUploadPackEnforced`, locate the block right after the withhold summary log (the existing `if withheld > 0 { log.Printf(...) }` at lines 157–159) and immediately before `packReader, packWait, err := mirror.PackObjectsStream(...)` (line 171). Insert between them:

```go
	// Plain-clone rejection: if any blob was withheld and the client did not
	// request a filtered (partial) fetch, the served packfile would be
	// structurally incomplete (a tree referencing a missing blob) and the
	// client would fail with a cryptic "missing blob object". Refuse the fetch
	// with an actionable ERR pointing at --filter=blob:none instead. Fail-closed:
	// the denied blob is never served. This mirrors the on-demand deny pattern
	// (write ERR to w, return a populated result + nil error so the caller's
	// audit mapping records the deny).
	if withheld > 0 && !clientRequestedFilter(req.Caps) {
		log.Printf("gitproto: upload-pack enforce: refusing plain clone of read-protected repo %q (%d denied blob(s)); client must use --filter=blob:none", repo, withheld)
		reason := errPlainCloneNeedsFilter
		if err := writeUploadPackErr(w, reason); err != nil {
			return UploadPackEnforceResult{DeniedPaths: deniedPaths, DeniedReason: reason}, err
		}
		return UploadPackEnforceResult{DeniedPaths: deniedPaths, DeniedReason: reason}, nil
	}
```

- [ ] **Step 6: Run the new test to verify it passes**

Run: `go test ./internal/gitproto/ -run TestServeUploadPackEnforced_PlainCloneDeniedWithError -v`
Expected: PASS.

- [ ] **Step 7: Run the full gitproto package — all tests must pass**

Run: `go test ./internal/gitproto/`
Expected: PASS. The two deny-matcher packfile tests pass via the filter request (Task 1); `AllowWhenNoDeny`, `StreamsMultiChunkPack`, `FailClosed*`, and the on-demand tests are unaffected (no withheld denied blob reachable on a non-filter path that expects a packfile — `AllowWhenNoDeny` and `StreamsMultiChunkPack` use `pathmatch.New(nil)`, so `withheld == 0` and the new branch never fires).

- [ ] **Step 8: Run the linters/build gates**

Run: `go vet ./internal/gitproto/ && golangci-lint run ./internal/gitproto/ && go build ./...`
Expected: all pass (no unused imports; `strings` is already imported in this file).

- [ ] **Step 9: Commit**

```sh
git add internal/gitproto/uploadpack_enforce.go internal/gitproto/uploadpack_enforce_test.go
git commit -m "feat(gitproto): reject plain clones of read-protected repos with actionable ERR

A plain (non --filter) clone of a read-protected repo made the proxy assemble
a packfile that withholds secrets/** blobs while keeping the trees that
reference them, so the client failed with a cryptic 'missing blob object'. The
proxy now detects a plain clone that would withhold a denied-path blob
(withheld > 0 and no `filter` cap in the request) and refuses with an actionable
ERR pointing at --filter=blob:none, reusing writeUploadPackErr and mirroring the
on-demand deny response shape. Adds DeniedReason to UploadPackEnforceResult so
the caller can record the actionable reason in the audit log. Fail-closed: a
denied blob is never served. OID integrity and all v1 invariants preserved."
```

---

## Task 3: Surface the actionable reason in the audit log (caller side) + end-to-end integration test

**Files:**
- Modify: `internal/gitproto/proxy.go` — reorder the audit-verdict switch in `Proxy.UploadPack` so `result.DeniedReason` wins.
- Modify: `test/integration/read_protection_test.go` — add `TestReadProtection_PlainCloneRejectedWithActionableError`.

**Interfaces:**
- Consumes: `UploadPackEnforceResult.DeniedReason` (produced in Task 2); `port.AuditEvent{Service, Verdict, Reasons, DeniedPaths, DeniedOIDs}`; integration helpers `StartWithPolicyAndAudit(t, repo, pol, auditFile)`, `policyReadDeny(patterns...)`, `seedProtectedFiles(t, h)`, `h.Git(dir, args...)`, `readAuditEvents(t, path)`, `hasAuditEvent(events, pred)`, `auditFile(t)`.
- Produces: the actionable reason in the audit event for a plain-clone rejection; the end-to-end acceptance test.

- [ ] **Step 1: Write the failing integration test**

Append to `test/integration/read_protection_test.go` (add `"os"` and `"github.com/psenna/git-proxy/internal/port"` to the import block if not already present — `"os"`, `"strings"`, `"path/filepath"`, `"testing"`, `"os/exec"`, `config` are already imported; add `port`):

```go
// TestReadProtection_PlainCloneRejectedWithActionableError is the end-to-end
// acceptance test for the plain-clone rejection fix. A plain (non --filter)
// clone of a read-protected repo (policy.read.deny: secrets/**) whose
// reachable set contains a denied blob is REFUSED by the proxy with an
// actionable error pointing the agent at --filter=blob:none — NOT the cryptic
// client-side "missing blob object" the old broken-packfile behavior caused.
// The audit log records a deny with the actionable reason and no secret
// content.
func TestReadProtection_PlainCloneRejectedWithActionableError(t *testing.T) {
	auditPath := auditFile(t)
	h := StartWithPolicyAndAudit(t, "test.git", policyReadDeny("secrets/**"), auditPath)
	seedProtectedFiles(t, h)

	// Plain clone through the proxy: must fail with the actionable error.
	clone := t.TempDir()
	dst := filepath.Join(clone, "repo")
	cmd := h.Git(clone, "clone", h.UpstreamURL+"/test.git", dst)
	out, err := cmd.CombinedOutput()
	if err == nil {
		// A plain clone that produced a working tree would mean the denied blob
		// leaked — fail loudly.
		if b, rerr := os.ReadFile(filepath.Join(dst, "secrets", "secret.txt")); rerr == nil {
			t.Fatalf("DENY LEAK: plain clone succeeded and secret file present: %q", b)
		}
		t.Fatalf("plain clone of read-protected repo unexpectedly succeeded")
	}
	outStr := string(out)
	if !strings.Contains(outStr, "requires a partial clone") || !strings.Contains(outStr, "--filter=blob:none") {
		t.Fatalf("plain clone output missing actionable reason; got:\n%s", outStr)
	}
	if strings.Contains(outStr, "missing blob object") {
		t.Errorf("plain clone surfaced the old cryptic 'missing blob object' error; got:\n%s", outStr)
	}
	const canary = "TOP-SECRET-VALUE-DO-NOT-LEAK"
	if strings.Contains(outStr, canary) {
		t.Errorf("DENY LEAK: secret canary in clone output: %q", outStr)
	}

	// Audit: a git-upload-pack deny event with the actionable reason and no
	// secret content.
	events := readAuditEvents(t, auditPath)
	if !hasAuditEvent(events, func(e port.AuditEvent) bool {
		return e.Service == "git-upload-pack" &&
			e.Verdict == "deny" &&
			len(e.Reasons) > 0 &&
			strings.Contains(e.Reasons[0], "requires a partial clone") &&
			strings.Contains(e.Reasons[0], "--filter=blob:none")
	}) {
		t.Errorf("no audit git-upload-pack deny event with the actionable reason; events=%+v", events)
	}
	for _, e := range events {
		for _, r := range e.Reasons {
			if strings.Contains(r, canary) {
				t.Errorf("DENY LEAK: secret canary in audit reason %q", r)
			}
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./test/integration/ -run TestReadProtection_PlainCloneRejectedWithActionableError -v`
Expected: FAIL. Before the `proxy.go` change in Step 3, the audit records the generic `"blob withheld by read policy"` (because `result.DeniedPaths` is non-empty and `DeniedReason` is ignored by the caller), so the `hasAuditEvent` assertion on the actionable reason fails. (The clone output assertion may already pass after Task 2, since the ERR is written to the client regardless of the audit mapping — but the audit-reason assertion fails, which is enough to make the test red.)

- [ ] **Step 3: Reorder the audit-verdict switch in `Proxy.UploadPack`**

In `internal/gitproto/proxy.go`, locate the success-branch verdict mapping (around lines 224–235):

```go
	verdict := "allow"
	var reasons []string
	if len(result.DeniedOIDs) > 0 {
		verdict = "deny"
		reasons = []string{"on-demand blob denied by read policy"}
	} else if len(result.DeniedPaths) > 0 {
		verdict = "deny"
		reasons = []string{"blob withheld by read policy"}
	}
	p.recordAudit(ctx, "git-upload-pack", agent, repo, verdict, reasons, nil,
		result.DeniedPaths, result.DeniedOIDs, false)
	return nil
```

Replace the `if/else if` with a `switch` that prefers `DeniedReason`:

```go
	verdict := "allow"
	var reasons []string
	switch {
	case result.DeniedReason != "":
		verdict = "deny"
		reasons = []string{result.DeniedReason}
	case len(result.DeniedOIDs) > 0:
		verdict = "deny"
		reasons = []string{"on-demand blob denied by read policy"}
	case len(result.DeniedPaths) > 0:
		verdict = "deny"
		reasons = []string{"blob withheld by read policy"}
	}
	p.recordAudit(ctx, "git-upload-pack", agent, repo, verdict, reasons, nil,
		result.DeniedPaths, result.DeniedOIDs, false)
	return nil
```

- [ ] **Step 4: Run the integration test to verify it passes**

Run: `go test ./test/integration/ -run TestReadProtection_PlainCloneRejectedWithActionableError -v`
Expected: PASS — the clone surfaces the actionable reason (not `missing blob object`), and the audit records a `git-upload-pack` deny with that reason and no secret canary.

- [ ] **Step 5: Run the full test suite + gates to confirm no regressions**

Run: `go test ./... && go vet ./... && golangci-lint run ./... && go build ./...`
Expected: all pass. The existing read-protection integration tests (`TestReadProtection_CloneWithholdsSecretBlob`, `TestReadProtection_OffClonesFully`, the on-demand deny tests) are unaffected — they use `--filter=blob:none` or have read protection off.

- [ ] **Step 6: Commit**

```sh
git add internal/gitproto/proxy.go test/integration/read_protection_test.go
git commit -m "feat(gitproto): record actionable reason in audit for plain-clone rejection

Proxy.UploadPack now prefers UploadPackEnforceResult.DeniedReason over the
generic withheld/on-demand reasons when building the audit event, so a plain
clone of a read-protected repo records the actionable --filter=blob:none reason
in the audit log (verdict=deny, no secret content). Adds the end-to-end
integration test TestReadProtection_PlainCloneRejectedWithActionableError
driving a real git plain clone through the read-protected proxy."
```

---

## Task 4: Document the plain-clone rejection in the Docker deploy walkthrough

**Files:**
- Modify: `docs/deploy-docker.md` — add a note near §3 ("Use git through the proxy") and update the limitation sentence at line 206.

**Interfaces:** None (docs only).

- [ ] **Step 1: Add a note after the clone command in §3**

In `docs/deploy-docker.md`, the §3 clone block is (lines ~134–138):

```sh
git -c "$GIT_PROXY_HEADER" clone $PROXY/demo/demo.git
cd demo
git -c "$GIT_PROXY_HEADER" remote set-url origin $PROXY/demo/demo.git
```

Insert a note immediately after that block:

```markdown
> **Read-protected repos:** once any file under `secrets/**` exists in the
> repo (see the read-protection walkthrough below), a **plain** clone like the
> one above is rejected by the proxy with an actionable error pointing you at
> `--filter=blob:none` — the proxy withholds the denied blobs and a plain clone
> cannot tolerate the resulting missing objects. Use
> `git -c "$GIT_PROXY_HEADER" clone --filter=blob:none $PROXY/demo/demo.git`
> for read-protected repos. The plain clone works until a `secrets/**` file is
> pushed.
```

- [ ] **Step 2: Update the limitation sentence at line 206**

Change (line 206):

```markdown
A plain (non-`--filter`) clone of a read-protected repo is not supported in v1
— use `--filter=blob:none`.
```

to:

```markdown
A plain (non-`--filter`) clone of a read-protected repo is rejected in v1 with
an actionable error pointing at `--filter=blob:none` (the proxy withholds the
denied blobs and a plain clone cannot tolerate the missing objects); use
`--filter=blob:none`.
```

- [ ] **Step 3: Commit**

```sh
git add docs/deploy-docker.md
git commit -m "docs: note plain clones of read-protected repos are rejected with an actionable error

Update the Docker deploy walkthrough: once a secrets/** file exists, a plain
clone is rejected with an actionable --filter=blob:none message rather than the
old cryptic client-side 'missing blob object'. Point users at the partial-clone
command for read-protected repos."
```

---

## Self-Review (run after writing the plan)

**1. Spec coverage:**
- "conditional reject (Approach 1)" → Task 2, Step 5. ✓
- behavior matrix (on/yes/no → ERR; on/yes/yes → withhold; on/no/no → serve; off → passthrough) → Task 2 unit test covers on/yes/no (ERR) and on/yes/yes (withhold regression); `AllowWhenNoDeny` (existing) covers on/no/no; passthrough tests cover off. ✓
- `DeniedReason` field + caller prefers it → Task 2 Step 3, Task 3 Step 3. ✓
- error message exact string + no-leak → Task 2 Step 4 (const), Step 1 (no-canary assertion), Task 3 Step 1 (no-canary in clone output + audit). ✓
- HTTP + SSH coverage via shared `ServeUploadPackEnforced` → single change point; no per-transport test required (both frontends route through it; existing integration tests cover HTTP, the shared function covers SSH implicitly). ✓
- `filter` tokenization pinned by integration test → `clientRequestedFilter` handles both forms; the integration test drives a real `git` plain clone (no filter) and the existing `TestReadProtection_CloneWithholdsSecretBlob` drives a real `git --filter=blob:none` (filter present), so both tokenizations are exercised by real git. ✓
- docs update → Task 4. ✓
- CI gates → Task 2 Step 8, Task 3 Step 5. ✓
- "What does NOT change" — no changes to withholding/on-demand/ref-ad/push/OID-integrity/passthrough; the plan only adds a conditional branch and a field. ✓

**2. Placeholder scan:** No TBD/TODO/"add error handling"/"similar to Task N". All code blocks contain real code. ✓

**3. Type consistency:**
- `UploadPackEnforceResult.DeniedReason string` — defined Task 2 Step 3, set Task 2 Step 5, consumed Task 3 Step 3. Consistent. ✓
- `clientRequestedFilter(caps []string) bool` — defined Task 2 Step 4, used Task 2 Step 5. ✓
- `errPlainCloneNeedsFilter` const — defined Task 2 Step 4, used Task 2 Step 5 and matched in Task 2 Step 1 / Task 3 Step 1 (string literal `"...requires a partial clone; retry with --filter=blob:none"`). The tests match on substrings (`requires a partial clone`, `--filter=blob:none`) rather than the exact const, so a const rename won't silently break tests, but the full string in Task 2 Step 1's `wantReason` must equal the const exactly — it does. ✓
- `uploadPackRequestFilter(t, tip, sideband)` — defined Task 1 Step 1, used Task 1 Steps 2–3 and Task 2 Step 1. ✓
- `port.AuditEvent` fields `Service`, `Verdict`, `Reasons` — confirmed against `internal/port/audit.go` and existing `audit_test.go` usage (`e.Service == "git-upload-pack" && e.Verdict == "deny"`). ✓
- `h.Git(dir, args...) *exec.Cmd`, `h.UpstreamURL`, `StartWithPolicyAndAudit`, `policyReadDeny`, `seedProtectedFiles`, `readAuditEvents`, `hasAuditEvent`, `auditFile` — all confirmed against `test/integration/read_protection_test.go`, `ondemand_deny_test.go`, and `audit_test.go`. ✓

No issues found. Plan is complete.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-17-read-protected-plain-clone-reject.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?