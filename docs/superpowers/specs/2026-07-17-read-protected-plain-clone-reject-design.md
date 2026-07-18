# Design: Reject plain clones of read-protected repos with a clear error

Date: 2026-07-17
Status: Approved (brainstorming) — pending implementation plan
Scope: One focused fix to the read-protected fetch path; no new subsystems.

## Context / problem

When `policy.read.deny: ["secrets/**"]` is enabled, the proxy assembles the
packfile itself (`ServeUploadPackEnforced` in `internal/gitproto/uploadpack_enforce.go`)
and withholds blobs whose path matches `secrets/**`, while keeping the commits
and trees that reference those blobs intact. This preserves OID integrity (the
agent sees the same OIDs upstream stores) but leaves tree entries pointing at
blobs that are not in the packfile.

A **plain** clone (`git clone …`, no `--filter`) does not tolerate missing
blobs: the client receives a tree that references a withheld blob, fails to
find it on unpack, and prints a cryptic, proxy-unattributable error:

```
fatal: missing blob object 'd011d03fb5d08aed23a0b11a7c8b5b57a990674a'
fatal: remote did not send all necessary objects
```

A **partial** clone (`--filter=blob:none`) works: the client expects missing
blobs, lazily fetches them on demand, and the proxy denies the on-demand
fetches of denied-path blobs with a structured `ERR` pkt-line (the existing
`onDemandBlobDenyReason` path). The current v1 doc
(`docs/deploy-docker.md`, line 206) acknowledges the limitation:

> A plain (non-`--filter`) clone of a read-protected repo is not supported in v1
> — use `--filter=blob:none`.

The defect is that, for a plain clone, the proxy **silently serves a
structurally-incomplete packfile** instead of refusing with a clear, actionable
error. The worst outcome: fail-open into a broken packfile with a confusing
client-side message.

## Goal

When a read-protected fetch would withhold a denied-path blob **and** the client
did not request a filtered (partial) fetch, the proxy refuses the fetch with a
clear, actionable `ERR` pkt-line pointing the agent at `--filter=blob:none`,
and never serves a broken packfile. The fix is fail-closed (a denied blob is
never served) and preserves every v1 invariant: OID integrity, the withholding
logic, the on-demand deny path, ref advertisement, push enforcement, and
passthrough when read protection is off.

## Non-goals

- Making plain clones "just work" without leaking secrets. This requires
  rewriting tree/commit OIDs (a placeholder blob cannot be served under the
  real OID — git verifies object hashes on unpack), which diverges clone OIDs
  from upstream and breaks push round-trip (the agent's commits would sit on
  rewritten parents that do not exist upstream, requiring an OID translation
  map + un-rewrite on the push path). Explicitly rejected as out of scope; see
  "Alternatives considered."
- A blanket rejection of every non-filtered upload-pack when read protection is
  on. Over-rejects plain fetches of secret-free branches. Rejected.
- v2 fetch support for the read-protected path (already a documented v1
  follow-up; out of scope here).

## Design

### Approach: conditional reject (Approach 1)

Reject only when a denied-path blob is **actually in the reachable wanted set**
**and** the client did not request `filter`. The proxy already computes the
wanted set and identifies withheld blobs (`uploadpack_enforce.go:103–159`); the
new check runs immediately after that loop, before `PackObjectsStream`
(line 171):

```go
if withheld > 0 && !clientRequestedFilter(req.Caps) {
    reason := "read-protected repository requires a partial clone; retry with --filter=blob:none"
    err := writeUploadPackErr(w, reason)
    return UploadPackEnforceResult{DeniedPaths: deniedPaths, DeniedReason: reason}, err
}
```

A new helper discriminates partial-clone requests from plain ones:

```go
// clientRequestedFilter reports whether the agent's upload-pack request asked
// for a filtered (partial) fetch — i.e. it advertised the `filter` capability.
// A plain clone/fetch does not, and cannot tolerate the blobs read protection
// withholds, so the caller refuses it with an actionable ERR rather than
// serving a structurally-incomplete packfile.
func clientRequestedFilter(caps []string) bool { ... }
```

### Behavior matrix

| Read protection | `secrets/**` reachable? | `filter` in request | Result |
|---|---|---|---|
| off | — | — | passthrough (unchanged) |
| on | no | no | serve normally (no false reject) |
| on | yes | no | **ERR with actionable reason** (the fix) |
| on | yes | yes | withhold + partial clone (unchanged) |
| on | no | yes | serve normally (unchanged) |

Every row is fail-closed: a denied blob is never served.

### Caller / audit interaction

`Proxy.UploadPack` (`internal/gitproto/proxy.go:212–221`) maps any error from
`ServeUploadPackEnforced` to a `deny` audit event and records `DeniedPaths`.
Today it records the generic reason `"upload-pack enforce failed"` for *all*
enforce errors. To keep the audit actionable and distinguish a deliberate
plain-clone rejection from an internal failure:

- Add a `DeniedReason string` field to `UploadPackEnforceResult`.
- In `ServeUploadPackEnforced`, the plain-clone rejection sets
  `DeniedReason` to the actionable message and returns a non-nil error (the
  `ERR` pkt-line has already been written to `w`).
- In `Proxy.UploadPack`'s error branch, prefer `result.DeniedReason` over the
  generic `"upload-pack enforce failed"` when non-empty, so the audit reads
  e.g. `"read-protected repository requires a partial clone; retry with
  --filter=blob:none"`.

This mirrors the existing on-demand blob-deny pattern
(`uploadpack_enforce.go:97–101`), which writes an `ERR` to `w` and then returns
an error; the response has already started, so git receives the structured
`ERR` pkt-line (not a bare 500). That pattern is already exercised by existing
tests, so the new path inherits a proven response shape.

### Error message + no-leak contract

The reason is a single fixed string:
`"read-protected repository requires a partial clone; retry with --filter=blob:none"`.

It reveals no credentials, no secret content, and no paths/OIDs — the same
no-leak contract as the existing on-demand reason (`"access to object %s
denied by read policy"`). That read protection is on is already implied by the
`filter` capability in the ref advertisement, so the message leaks nothing new.
Reuses the existing `writeUploadPackErr` helper — no new protocol code.

### Transport coverage (HTTP + SSH)

`ServeUploadPackEnforced` is the shared path used by both the HTTP frontend
(`internal/transport/http/frontend.go`) and the SSH frontend
(`internal/transport/ssh/frontend.go`). One change covers both transports — no
per-transport work. Both frontends route read-protected upload-pack through
this function.

### `filter` capability tokenization

The proxy advertises `filter` to the client; a `--filter=blob:none` clone sends
the `filter` capability back in its request caps (`req.Caps`), and a plain
clone does not. The exact token form (`filter` vs `filter=blob:none` vs
`"filter blob:none"`) is protocol-version-dependent and must be pinned by a
real-`git` integration test during implementation (see Testing). The
`clientRequestedFilter` helper is the single place that knows this shape, so
tokenization changes are localized.

## Files touched

- `internal/gitproto/uploadpack_enforce.go` — add `clientRequestedFilter`, the
  post-withhold conditional reject, and `DeniedReason` field on
  `UploadPackEnforceResult`.
- `internal/gitproto/proxy.go` — in `UploadPack`'s enforce error branch,
  prefer `result.DeniedReason` over the generic reason when non-empty.
- `internal/gitproto/uploadpack_enforce_test.go` — table-driven unit tests
  (see Testing).
- `internal/gitproto/proxy_*_test.go` — extend the audit-reason assertion if
  needed to cover the new `DeniedReason`.
- `test/integration/` — a new/extended integration test driving a real `git`
  client (see Testing).
- `docs/deploy-docker.md` — note near §3 that once `secrets/**` exists, plain
  clones are rejected with an actionable message pointing to
  `--filter=blob:none` (the partial-clone walkthrough in §3 already uses
  `--filter=blob:none` and is unchanged).

## What does NOT change

- The withholding logic and the on-demand blob-deny path.
- The ref advertisement (still advertises `filter`).
- Push enforcement (`receive-pack`).
- OID integrity — commits and trees stay intact; no rewriting.
- Passthrough when read protection is off.
- v2 fetch (still a documented v1 follow-up).

## Testing (TDD — red → green → commit, per CLAUDE.md)

Unit (`internal/gitproto/uploadpack_enforce_test.go`, table-driven):

1. Denied-path blob reachable + no `filter` → expect an `ERR` pkt-line with the
   actionable reason, no packfile written, deny result, `DeniedReason` set.
2. Denied-path blob reachable + `filter` → existing withholding behavior
   preserved (no `ERR`; packfile assembled with the blob withheld).
3. No denied blob reachable + no `filter` → served normally (no false reject;
   no `ERR`).
4. Read protection off (matcher nil) → unchanged (the enforce path is not
   reached; covered by existing passthrough tests, kept for regression).
5. Pin the exact `filter` tokenization in `clientRequestedFilter` (both the
   plain-clone absence and the partial-clone presence forms).

Integration (`test/integration/`, real `git` client):

6. Push a `secrets/**` file through the proxy, then a plain
   `git clone $PROXY/demo/demo.git` → assert the client surfaces the
   actionable message (NOT `missing blob object`).
7. `git clone --filter=blob:none $PROXY/demo/demo.git` of the same repo →
   succeeds; `git cat-file -p HEAD:secrets/...` is denied on demand with the
   existing on-demand reason.
8. Audit log for the plain-clone rejection records `verdict: deny` with the
   actionable `DeniedReason` and no secret/credential content (no-leak canary:
   the redacted blob content does not appear).

CI gates (mandatory, per CLAUDE.md): `go vet`, `golangci-lint`, `go build`,
`go test`, `govulncheck`. `main` is protected; one issue per PR; Conventional
Commits with every commit green.

## Alternatives considered

1. **Make plain clones work transparently (OID rewriting).** Rewrite trees to
   drop the denied entry or point at a redacted placeholder. Rejected: changes
   tree/commit OIDs (a placeholder blob cannot be served under the real OID —
   git verifies object hashes on unpack, which would require an infeasible
   second preimage), diverging clone OIDs from upstream and breaking push
   round-trip (agent commits would sit on rewritten parents absent upstream,
   requiring an OID translation map + un-rewrite on the push path). Violates
   the v1 "commits and trees intact" invariant. The user explicitly
   reconsidered this after seeing the cost.
2. **Blanket reject (Approach 2).** Refuse any non-filtered upload-pack when
   read protection is on, before any computation. Rejected: over-rejects plain
   fetches of secret-free branches — a real UX regression for the common case.
3. **Reject at advertisement time (Approach 3).** Refuse non-filtered fetches at
   `info/refs`/negotiation start. Not cleanly distinguishable that early (the
   server cannot know whether the client will request a filter until it sees
   the wants); collapses into Approach 2. Rejected.
4. **Improve the error message only.** Emit a helpful `ERR` but keep serving
   the broken packfile. Rejected: still serves a structurally-incomplete
   packfile; the conditional-reject approach supersedes it by refusing cleanly.

## Open questions for implementation

- The exact `filter` tokenization in `req.Caps` (resolved by the integration
  test above; localized to `clientRequestedFilter`).
- Whether `DeniedReason` should also surface on the on-demand deny path for
  audit parity (optional follow-up; not required for this fix — the on-demand
  path already records `DeniedOIDs` with a distinct reason).