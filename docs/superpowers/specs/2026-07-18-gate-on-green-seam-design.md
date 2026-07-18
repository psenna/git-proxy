# Gate-on-Green Seam Design

> Status: design only — no code. This is the deferred follow-up the broker
> plan (PR12) explicitly left for a later PR. The seam it depends on (`Checks`
> on `port.PRSupport`, `port.CheckSummary`) shipped in PR6/PR7 and is reused
> here without rework.

**Goal:** let git-proxy refuse a merge (and, optionally, a push to a protected
branch) when the relevant ref's CI is not green — the "gate on green" policy the
agent-facing broker plan deferred ("decide later").

## Why a seam, not a feature

The hard part — querying upstream CI state — is already built:
`port.PRSupport.Checks(ctx, repo, ref) (CheckSummary, error)` and
`port.CheckSummary{Overall, Checks, Workflows}` (PR6 port types, PR7 GitHub
adapter wired to the REST client). Both gate paths below **reuse** `Checks` /
`CheckSummary`; they add no new upstream-facing seam. What each path decides is
*where* the gate runs and *what triggers it*.

## Path A — broker merge-gate (preferred follow-up)

The cheapest, most contained option. The broker already exposes `POST
/{repo}/prs/{number}/merge`. Gate it:

```go
// in handleMerge, after authOK + before MergePR:
if b.requireGreenOnMerge {
    pr, err := b.prs.GetPR(ctx, repo, number)
    if err != nil { b.opFail(w, r, agent.Name, repo, op, err); return }
    summary, err := b.prs.Checks(ctx, repo, pr.Head)
    if err != nil { b.opFail(w, r, agent.Name, repo, op, err); return }
    if summary.Overall != "success" {
        b.opFail(w, r, agent.Name, repo, op, fmt.Errorf("ci not green: %s", summary.Overall))
        return  // writeError maps the generic error → 409 "not mergeable"-style; see below
    }
}
```

- **Guard:** a new `BrokerConfig.RequireGreenOnMerge bool` (config leaf +
  `broker.Config`). Default false (opt-in), so existing deployments are
  unchanged. ~15 lines plus config plumbing.
- **Status mapping:** a non-green merge should surface a distinct, agent-actionable
  status. Reuse the existing sentinel machinery — return `port.ErrNotMergeable`
  (or a new `port.ErrCINotGreen` sentinel mapped to 409/422 in `writeError`)
  rather than a free-form error (which `writeError` would turn into a generic
  400). Prefer a small new sentinel so the reason is precise and the no-leak
  contract stays explicit.
- **No new seam.** `Checks` is already on `PRSupport`; the broker already
  type-asserts it. `mergeable: null` is preserved (`PRState.Mergeable *bool`),
  so the agent sees "unknown" and the gate treats a non-`"success"` `Overall`
  (including `"pending"`, `"unknown"`, `"failure"`) as not-green → block. This
  is fail-closed: a CI state we cannot confirm green does not merge.
- **Scope:** broker-only. The git-protocol core is untouched; the core-isolation
  invariant (`internal/port/prsupport_core_isolation_test.go`) is unaffected
  because `internal/broker` is outside the scanned set.

This is the recommended first step: small, contained, no core change, and it
covers the "agent asks the proxy to merge" case directly.

## Path B — push-time gate (heavier, deferred separately)

Gate a *push* to a protected branch on CI green, enforced at receive-pack time
by the policy engine (alongside the existing `history_protect` /
`branch_pattern` rules). This requires a new self-registering rule
`gate_on_green` in `internal/policy/rules` (which is allowed to type-assert
`PRSupport` — the isolation test scans top-level `internal/policy` only, not
`rules/`).

### Known seam gap (must be closed first)

`RuleFactory` does not receive the upstream:

```go
// internal/policy/engine.go:150
type RuleFactory func(cfg RuleConfig) port.Rule

// internal/policy/engine.go:207
type RuleConfig struct {
    Enabled bool           `yaml:"enabled"`
    Agents  []string       `yaml:"agents"`
    Repos   []string       `yaml:"repos"`
    Params  map[string]any `yaml:"params"`
}
```

A `gate_on_green` rule needs `port.Upstream` (to type-assert `PRSupport` and
call `Checks` on the pushed ref's new SHA). Neither `RuleConfig` nor `RuleFactory`
carries it today. The follow-up must thread `port.Upstream` into the rule
construction path.

### Threading constraint (binding — core isolation)

Top-level `internal/policy` is in the scanned core set, so the threaded value
**must be `port.Upstream`, not `port.PRSupport`**. The `gate_on_green` rule
type-asserts `PRSupport` off the `port.Upstream` itself (inside
`internal/policy/rules`, which may reference `PRSupport`), and fails closed
(`ErrNotImplemented` / type-assertion failure → deny) when the upstream is not
an SCM adapter. This keeps the policy *engine* free of any SCM-specific
assumption — only the rule knows about PRs/CI.

A minimal change shape (to be validated against the real engine in the follow-up
PR):

- Extend `RuleFactory` to receive the upstream, e.g.
  `type RuleFactory func(cfg RuleConfig, up port.Upstream) port.Rule`, OR add an
  `Upstream port.Upstream` field to `RuleConfig` populated by `Resolve`. The
  former changes every existing rule factory signature; the latter is additive
  (existing rules ignore the new field) and preferable.
- `policy.Resolve` (and the harness `policy.Resolve(pol.ToPolicy(), nil)`) must
  receive and pass the `port.Upstream` main.go already builds. This is a small,
  backward-compatible plumbing change.
- `internal/policy/rules/gate_on_green.go` (new) type-asserts `PRSupport`,
  reads the pushed ref's new SHA from the rule's hook, calls `Checks`, and denies
  when `Overall != "success"`.

### Reuse / no rework

Both paths call the same `Checks(ctx, repo, ref) → CheckSummary` and branch on
the same `Overall` word set (`"none"|"pending"|"failure"|"success"|"unknown"`).
The roll-up precedence (failure > pending > success > unknown) is decided once
in `internal/upstream/github/rest` (`rollupCI`), so both gates agree on what
"green" means. No second roll-up, no second CI client.

## Sequencing recommendation

1. **PR (small):** `BrokerConfig.RequireGreenOnMerge` + broker merge-gate +
   new `port.ErrCINotGreen` (or reuse `ErrNotMergeable`) + tests. Closes the
   agent-merge case. No core change.
2. **PR (medium):** thread `port.Upstream` into `RuleFactory`/`RuleConfig`
   (additive) + extend the isolation test if needed to assert top-level
   `internal/policy` still references only `port.Upstream`, never `PRSupport`.
3. **PR (medium):** `gate_on_green` rule in `internal/policy/rules` + rule
   tests. Closes the push-to-protected-branch case.

## Open questions

- **"green" definition:** is `"none"` (no CI configured) green? Today `rollupCI`
  returns `"none"` for a ref with zero runs. A gate that blocks on `"none"` is
  stricter (every protected branch MUST have CI); a gate that treats `"none"`
  as green is lenient (no CI = no gate). Decide per-deployment, plausibly a rule
  param (`require_checks: true|false`) rather than hard-coded.
- **`"pending"` semantics:** a merge-gate should likely *retry-or-block* on
  `"pending"`, not hard-fail. The broker merge-gate can return 422/409 with a
  reason that tells the agent to wait and retry; a push-time gate has no
  interactive retry path, so `"pending"` must decide block-vs-allow carefully.
- **rate limits / failures:** `Checks` returning `ErrRateLimited`/`ErrUpstream`
  at gate time is fail-closed (block) — surface the generic reason, never retry
  inside the gate (no client-side retry, per the broker plan's rate-limit note).