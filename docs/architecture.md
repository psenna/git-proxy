---
layout: default
title: Architecture
---

# Architecture (v1, as shipped)

This document describes git-proxy **as built** in the v1 release. Every claim is
grounded in the code at this commit; where the original design sketch (`v1.md`)
diverges from the as-built shape, the docs describe as-built and flag the
divergence (see also `docs/extensibility.md`, which flags the same for the
extension seams).

git-proxy is a policy-enforcing gateway that sits between AI coding agents and
upstream Git repositories. The agent talks to the proxy over HTTP or SSH; the
proxy forwards allowed traffic to the upstream and denies (or withholds)
traffic that violates policy. **The agent never sees upstream credentials —
the proxy holds them.** Security decisions default to deny (fail-closed).

## Layer diagram

```
                       Agent (git over HTTP or SSH)
                         │            │
            ┌────────────┘            └─────────────┐
            ▼                                         ▼
   internal/transport/http                     internal/transport/ssh
        (Frontend)                                (Frontend)
            │                                         │
            │   each frontend holds its OWN *gitproto.Proxy
            │   (built via gitproto.New(up)) ─────────┤
            ▼                                         ▼
   ┌──────────────────────────────────────────────────────────┐
   │                internal/gitproto.Proxy                   │
   │   the protocol core: pkt-line framing, upload-pack,      │
   │   receive-pack, packfile assembly, report-status         │
   │                                                          │
   │   enforcement hooks (set by the frontends):              │
   │     SetEnforcement(engine, mirrorOpener, maxBytes)      │
   │     SetReadDeny(*pathmatch.Matcher)                      │
   │     SetAuditSink(AuditSink, transport)                   │
   │     SetAlertSink(AlertSink)     SetDryRun(bool)          │
   └──────┬───────────────┬──────────────┬──────────────┬────┘
          │               │              │              │
          ▼               ▼              ▼              ▼
   policy.Engine    gitx.Mirror     port.Upstream   port.AuditSink
   (pure, fail-     (bare clone,    (the upstream   port.AlertSink
    closed)         read-only       git server)    (best-effort,
                    inspection)                     no-leak)
```

**As-built vs `v1.md` divergence (flagged):** `v1.md` sketched a `port.GitConn`
abstraction between the transport and the protocol core. **The shipped code does
not use it.** Each frontend holds a concrete `*gitproto.Proxy` and calls it
directly; the HTTP and SSH frontends share *the same* proxy handler set
(upload-pack/receive-pack) and only differ in transport-specific framing
(SSH ref advertisement, SSH upload-pack body framing). `internal/port/gitconn.go`
defines a `GitConn` interface that is **unused** in production code — a dead
abstraction reserved from the sketch, slated for removal. This is the same
divergence `docs/extensibility.md` flags for the extension seams.

## Decision flows

### Push (`git-receive-pack`)

```
agent -> frontend -> Proxy.ReceivePack(buffered body)
   1. Buffer the full request body (bounded by push.max_packfile_bytes,
      default 256 MiB; oversize -> deny, fail-closed).
   2. Refresh the inspection mirror (bare clone of the upstream, read-only)
      and ingest the pushed packfile into it.
   3. Ancestry walk: for each ref update, Force = !IsAncestor(old, new)
      (zero OIDs normalized; ancestry error -> deny, fail-closed).
   4. policy.Engine.Eval(PushRequest{RefUpdates, Commits, ChangedFiles})
      -> Decision{Verdict, Reasons}. Pure: no I/O, no time.Now.
   5. Branch on verdict:
        Allow  -> forward the buffered body to the upstream (the real allow
                  signal is the upstream ref advancing, asserted in tests).
        Deny   -> write a report-status `ng <ref> <reason>` pkt-line
                  (side-band-64k muxed on channel 1; report-status-v2 detected)
                  and DO NOT forward. Upstream ref is unchanged.
   6. Record an audit event (allow | deny) and, on deny, fire an alert.
      Audit + alert are best-effort: a sink failure never changes the verdict
      or blocks the op.
```

Reasons sent to the agent are **agent-facing and redacted**: no upstream
credentials, no raw secret values (the matched secret is masked as `REDACTED`),
no blob content. Upstream credential leakage is prevented by a `redactCreds`
regex over gitx error strings.

### Fetch (`git-upload-pack`) — read protection

Read protection is a **proxy-level** path matcher (not an engine rule). When
`policy.read.deny` is configured, the proxy does NOT forward the upload-pack
request; it **assembles the packfile itself**:

```
agent -> frontend -> Proxy.UploadPack
   1. Fetch the upstream ref advertisement as v0 (strip version 2) and
      re-emit it with the `filter` + `allow-reachable-sha1-in-want` caps.
   2. Parse the agent's wants/haves.
   3. For a full-clone / commit-tree want:
        rev-list --objects over the mirror -> cat-file --batch-check to type
        each object -> WITHHOLD blobs whose path matches the deny matcher.
        pack-objects on the explicit (non-denied) OID list, ALWAYS non-thin
        (--thin would re-include withheld blobs as delta bases), streamed via
        an io.Pipe (memory bounded by chunk size; fail-closed streaming).
        Serve v0: NAK + side-band-64k packfile on channel 1.
   4. For an on-demand BLOB want (a `want <blob-oid>` for an unadvertised
        object, the partial-clone lazy-fetch path):
        oidpath.Resolve walks the trees to map the OID -> its path(s);
        if ANY resolving path is denied -> REFUSE the whole fetch with an
        `ERR <reason>` pkt-line (no packfile served); a blob want that
        resolves to NO path is also denied (cannot prove it is not a denied
        blob). Commits/tags/trees use the full-clone withholding path above.
   5. Record an audit event (deny carries DeniedPaths / DeniedOIDs) + alert.
```

**v1 scope / limitations (read protection):** protocol **v0 only** (the proxy
strips version 2). A **plain (non-`--filter`) clone of a read-protected repo is
unsupported** — the missing denied blob breaks checkout with no promisor
fallback; use `git clone --filter=blob:none`. Multi-round fetch over SSH is out
of scope (the SSH upload-pack framer terminates at `done`, single-round).
**Read-protection dry-run is out of v1 scope** — read protection
withholds/denies blobs regardless of dry-run (it never serves a denied blob to
"observe"). These are documented limitations, not bugs.

## Seams (`internal/port`)

All extension points are interfaces in `internal/port`:

| Seam | Interface | v1 implementation |
|------|-----------|-------------------|
| Upstream git server | `Upstream` | `internal/upstream/plain` (smart-HTTP git) |
| SCM capabilities (optional) | `PRSupport` | `internal/upstream/github` skeleton (`ErrNotImplemented`) |
| Push rule | `Rule` | `internal/policy/rules`: history_protect, branch_pattern, commit_message, path_acl, secret_scan |
| Agent auth | `Authenticator` | `internal/auth/token` (Bearer), `internal/auth/keyauth` (SSH key) |
| Upstream credentials | `CredentialStore` | `internal/credentials/file` |
| Secret scanner | `SecretScanner` | `internal/secret/regex` |
| Audit sink | `AuditSink` | `internal/audit/file` (append-only JSONL) |
| Alert sink | `AlertSink` | `internal/alert/webhook`, `internal/alert/log`, `MultiAlertSink` |
| Transport | `Transport` | `"http"`, `"ssh"` (tag on audit events) |

**Two registries** (mirrors of each other):
- `internal/policy` — `RuleFactory = func(RuleConfig) port.Rule`; rules
  self-register via `init()` + `policy.RegisterRule`; `policy.LookupRule` /
  `Resolve`. `RuleConfig` lives in `internal/policy` (the consumer package).
- `internal/upstream` — `UpstreamFactory = func(UpstreamConfig)
  (port.Upstream, error)`; adapters self-register via `init()` +
  `upstream.Register`; `upstream.Build` (empty `Kind` -> `"plain"` default,
  unknown `Kind` -> error, **fail-closed — no silent fallback**).
  `UpstreamConfig` lives in `internal/upstream` (the consumer package);
  `internal/config` is a pure YAML leaf that gains `Kind` and does NOT import
  `internal/upstream` (no cycle).

**The engine is pure.** `internal/policy` has no I/O and no `time.Now`; audit
and alert recording (I/O, time) live in `internal/gitproto` and the sinks. The
engine is **fail-closed**: an erroring/unknown rule or an inspection failure
(mirror open/refresh/ingest, ancestry/commit/blob extraction, oversize,
unparseable) denies — only a *clean* engine Deny is a policy deny.

**Core never depends on PRSupport.** Only `internal/port` may define
`PRSupport` and only `internal/upstream/github` may implement it; the core
(`internal/gitproto`, `internal/transport`, top-level `internal/policy`,
`cmd/git-proxy`) must never reference `PRSupport` — code wanting the capability
type-asserts at runtime (`if prs, ok := up.(port.PRSupport); ok { ... }`). This
invariant is enforced by `internal/port/prsupport_core_isolation_test.go`, a
`go/parser` AST-scan test (`filepath.WalkDir` recursive for gitproto/transport/
cmd, top-level-only for policy so `policy/rules` — which may legitimately
type-assert PRSupport in a future rule — is excluded).

### Dry-run (proxy-level, not engine-level)

Dry-run is **proxy-level**, not engine-level: the engine stays pure and returns
its true verdict regardless. When `p.dryRun` AND a *clean* engine Deny
(`enErr == nil && dec.Verdict == Deny`), the proxy **forwards** the buffered
push instead of writing the deny response, and records an audit event with the
*true* verdict `deny` + `AuditEvent.DryRun = true` (so the log distinguishes
enforced-deny from would-be-deny-forwarded). **Dry-run softens policy denies
only, NOT inspection failures** — every inspection-error deny branch returns
before the clean-deny gate and still fail-closes. This is the
observe-everything mode: pair `mode: collect_all` (engine reports all
violations, not just the first) with `dry_run: true`.

### Audit & alerts — best-effort + no-leak

Both audit and alerts are **best-effort / non-fatal**: a sink failure (file
write error, webhook 500/timeout/unreachable) is logged and swallowed; the
verdict and the git op proceed regardless. Audit is written before the alert is
fired, so the durable audit record survives even if the alert sink is
unreachable.

Both are **leak surfaces** (disk + outbound webhook) and carry only redacted,
generic data: `Reasons` are redacted `port.Reason.Message` (secrets masked as
`REDACTED`, upstream creds stripped via `redactCreds`); `DeniedPaths` /
`DeniedOIDs` carry paths and OIDs only — **never blob content, raw secret
values, upstream URLs/credentials, or packfile bytes.** Canary assertions in
the integration tests string-match the secret value against the audit file and
the raw webhook POST body.

## Testing strategy

- **Unit tests per package.** The policy engine, pathmatch, gitx, the rules,
  the sinks, and the protocol framing each have focused unit tests. The
  engine tests are pure (no real git).
- **Real-git integration tests** (`test/integration/`, no mocks) via
  `test/integration/harness.go` (+ `harness_ssh.go`). The harness spins up a
  fresh upstream bare repo, a fresh proxy, a fresh audit file per test, and
  drives real `git` through the proxy. `harness.Git()` applies the
  `url.<proxy>.insteadOf <upstream>` rewrite **and** the Bearer header, so
  proxy-routed ops go through the proxy authenticated (raw `exec.Command` is
  used only for the deliberate no-token auth probe). Upstream ref states are
  asserted by reading the upstream bare repo directly (`git -C <upstream>
  rev-parse`), not by proxying.
- The v1 capstone `test/integration/e2e_test.go::TestE2E_V1Capstone` exercises
  the full v1 contract in a single real-git flow (auth, clean push reaching
  the upstream, force-push rejection with the upstream unchanged, secret_scan
  denial, read-protection withholding, attributable audit events + no-leak
  canary); each step's comment maps it to the milestone it proves. The
  per-feature tests (passthrough, push_enforce, push_rules, read_protection,
  ondemand_deny, audit, dryrun_alerts, ssh_frontend, auth) are the per-milestone
  acceptance and stay green alongside the capstone.

CI runs five gates on Go 1.26 (toolchain) with a source-built golangci-lint
v1.64.8: `go vet`, `golangci-lint run`, `go build`, `go test -race`,
`govulncheck`.

## Milestone table

| Milestone | Scope | PR | main SHA |
|-----------|-------|----|----------|
| M0 | CI / quality pipeline + scaffold | #16 | `178d004` |
| M1 | Passthrough skeleton + harness | #17 (+fix #18) | `d225b83` |
| M2 | Protocol layer (pkt-line, upload-pack/receive-pack) | #19 | `e22997b` |
| M3 | Auth & credentials | #20 | `6dde997` |
| M4a | Policy engine + registry | #21 | `b9bc2ca` |
| M4b | history_protect + branch_pattern rules | #22 | `4995043` |
| M5a | Push enforcement core (mirror, ancestry, report-status) | #23 | `9915639` |
| M5b/M6 | commit_message + path_acl + secret_scan rules | #24 | `ebf1bff` |
| M7a | Read protection: object withholding | #25 | `b4dac87` |
| M7b | On-demand blob denial | #26 | `a62e79a` |
| M8 | SSH frontend | #27 | `0eb6076` |
| M9a | Audit log | #28 | `330b94c` |
| M9b | Dry-run + alerts | #29 | `8640a32` |
| M10 | Extensibility + GitHub worked example | #30 | `de43ab9` |
| v1 | E2E capstone + docs (this task) | #31 | _pending_ |

## v1 scope and documented limitations

- Read protection is **protocol v0 only** (version 2 stripped).
- A **plain clone of a read-protected repo is unsupported** — use
  `--filter=blob:none` (the missing denied blob breaks checkout with no promisor
  fallback).
- **Multi-round fetch over SSH is out of scope** (single-round only; the SSH
  upload-pack framer terminates at `done`).
- **Read-protection dry-run is out of v1 scope** (read protection withholds
  regardless of dry-run).
- The **GitHub adapter is a skeleton** — git-protocol delegation is real
  (GitHub serves smart-HTTP), but `PRSupport` (`BranchProtection`, `EnsurePR`)
  returns `ErrNotImplemented`; the real GitHub REST integration is v2.
- `internal/port/gitconn.go` is a **dead abstraction** reserved from the `v1.md`
  sketch and unused in production code; it is slated for removal (flagged for
  the final review).