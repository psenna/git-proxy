---
layout: default
title: Extensibility
---

# Extending git-proxy

git-proxy is extensible by interface: every pluggable seam lives in `internal/port`
(an interface definition) plus a package that implements it and self-registers via
`init()`. Config selects an implementation by name; the registry resolves it at
startup. "New integrations = implement an interface + register." This document is
the worked example for each seam, grounded in the code as of v1 (M10).

> The as-built architecture is the source of truth here, not the original design
> sketch in `v1.md`. Where they diverge, this document describes what the code
> actually does and flags the divergence. The notable one: `v1.md` sketches
> frontends as "implement `Transport` producing `GitConn`"; the as-built HTTP and
> SSH frontends do **not** use `port.GitConn` — each holds a `*gitproto.Proxy`
> directly (see [Frontend](#frontend) below). `internal/port/gitconn.go` is a
> reserved, currently-unused type; treat it as superseded.

## Seams at a glance

| Seam | Interface | Registry | Config key | Reference impl |
|---|---|---|---|---|
| Policy rule | `port.Rule` | `policy.RegisterRule` | `policy.rules.<name>` | `internal/policy/rules/secret_scan.go` |
| SCM provider | `port.Upstream` (+ optional `port.PRSupport`) | `upstream.Register` | `upstream.kind` | `internal/upstream/plain`, `internal/upstream/github` |
| Issue tracker | `port.Upstream` (+ optional `port.IssueSupport`) | `upstream.Register` | `issue_upstream.kind` | `internal/upstream/github` (v1) |
| Frontend | `port.Transport` | (constructed in `main.go`) | `listen` / `ssh.listen` | `internal/transport/http`, `internal/transport/ssh` |
| Auth method | `port.Authenticator` | (constructed in `main.go`) | `auth.tokens` / `ssh.authorized_keys` | `internal/auth/token`, `internal/auth/keyauth` |
| Secret scanner | `port.SecretScanner` | (constructed in the rule) | (inside `secret_scan` rule config) | `internal/secret/regex` |
| Credential store | `port.CredentialStore` (+ `port.RepoMatcher` for `public_repos`) | (constructed in `main.go`) | `upstream.credentials_file` / `issue_upstream.credentials_file` / `public_repos` | `internal/credentials/profile`, `internal/credentials/repomatch` |
| Audit sink | `port.AuditSink` | (constructed in `main.go`) | `audit.file` | `internal/audit/file` |
| Alert sink | `port.AlertSink` | (constructed in `main.go`) | `alerts.webhook` | `internal/alert/webhook`, `internal/alert/log`, `internal/alert` (Multi) |

The policy rule registry and the upstream/SCM registry are the two **self-registering**
registries (an `init()` in the implementation package calls `Register`). The other
seams are constructed explicitly in `cmd/git-proxy/main.go` because there is exactly
one active instance per process and selection is by config presence, not by name.

---

## Policy rule

A policy rule decides allow/deny for a push (`EvaluatePush`) or fetch
(`EvaluateFetch`). The engine is pure: no I/O, no `time.Now`, no git binary. Rules
self-register by name and the engine resolves them from `policy.rules` in config.

**To add one:**

1. New file in `internal/policy/rules/` implementing `port.Rule`:
   ```go
   type MyRule struct{ cfg port.RuleConfig }
   func (r *MyRule) Name() string                                   { return "my_rule" }
   func (r *MyRule) EvaluatePush(ctx context.Context, req port.PushRequest) port.Decision { ... }
   func (r *MyRule) EvaluateFetch(ctx context.Context, req port.FetchRequest) port.Decision { ... }
   ```
2. Self-register in an `init()`:
   ```go
   func init() {
       policy.RegisterRule("my_rule", func(cfg policy.RuleConfig) port.Rule {
           return &MyRule{cfg: cfg}
       })
   }
   ```
3. Unit tests (pure — table-driven, no mocks). Fail-closed: a config/parse error
   inside the factory or rule must produce a deny, never an allow.
4. Reference by name in config:
   ```yaml
   policy:
     mode: first_deny
     rules:
       my_rule:
         params: { ... }
   ```

`policy.RegisterRule(name, RuleFactory)` where `RuleFactory = func(cfg RuleConfig) port.Rule`
(`internal/policy/engine.go:150`). `RuleConfig` carries the rule name + a
`Params map[string]any` decoded from YAML. See `internal/policy/rules/secret_scan.go`
for the full pattern (regex + entropy scanner, default-on, redacted snippets).

---

## SCM provider (the GitHub adapter as the worked example)

An SCM adapter is how the proxy talks to an upstream git server. The core depends
**only** on `port.Upstream` (the git smart-HTTP protocol: `ListRefs`,
`ListRefsService`, `UploadPack`, `ReceivePack`). An adapter that also speaks an SCM
API (GitHub, GitLab) additionally implements the **optional** `port.PRSupport`
sub-interface (branch protection, pull requests); the core never depends on
`PRSupport` — only type-asserting code does (`if prs, ok := up.(port.PRSupport); ok { ... }`).

**To add one** (worked example = the GitHub skeleton at `internal/upstream/github`):

1. New package under `internal/upstream/` implementing `port.Upstream`. For a
   GitHub-style provider that serves standard smart-HTTP git, the git-protocol
   methods **delegate** to the plain HTTP transport (GitHub serves `/info/refs`,
   `/git-upload-pack`, `/git-receive-pack` verbatim) — delegation is real, not a
   stub:
   ```go
   package github

   import (
       "github.com/psenna/git-proxy/internal/port"
       "github.com/psenna/git-proxy/internal/upstream"
       "github.com/psenna/git-proxy/internal/upstream/plain"
   )

   var (
       _ port.Upstream    = (*Adapter)(nil)
       _ port.PRSupport   = (*Adapter)(nil)
       _ port.IssueSupport = (*Adapter)(nil) // optional: the issue-tracker capability
   )

   type Adapter struct {
       *plain.Upstream // promotes ListRefs/ListRefsService/UploadPack/ReceivePack
   }

   func New(cfg upstream.UpstreamConfig) *Adapter {
       return &Adapter{Upstream: plain.New(cfg.URL, cfg.CredentialsStore)}
   }
   ```
2. Implement the SCM-specific capabilities (optional) by satisfying `port.PRSupport`,
   returning `port.ErrNotImplemented` until the real REST calls land:
   ```go
   func init() {
       upstream.Register("github", func(cfg upstream.UpstreamConfig) (port.Upstream, error) {
           return New(cfg), nil
       })
   }

   // BranchProtection: GitHub REST GET /repos/{owner}/{repo}/branches/{branch}/protection
   func (a *Adapter) BranchProtection(context.Context, string, string) (port.BranchProtection, error) {
       return port.BranchProtection{}, port.ErrNotImplemented
   }
   // EnsurePR: GitHub REST POST /repos/{owner}/{repo}/pulls
   func (a *Adapter) EnsurePR(context.Context, string, string, string, string) (port.PR, error) {
       return port.PR{}, port.ErrNotImplemented
   }
   ```
3. Self-register via `init()` calling `upstream.Register(name, UpstreamFactory)`
   where `UpstreamFactory = func(cfg UpstreamConfig) (port.Upstream, error)`
   (`internal/upstream/registry.go`). `UpstreamConfig` carries `Kind`, `URL`,
   `CredentialsStore`, and `Params`.
4. Register the package in `cmd/git-proxy/main.go` with a blank import so its
   `init()` runs:
   ```go
   _ "github.com/psenna/git-proxy/internal/upstream/github" // register via init()
   ```
5. Select by name in config:
   ```yaml
   upstream:
     kind: github
     url: "https://github.example.com"
   ```

`upstream.Build` (`internal/upstream/registry.go`) resolves the factory for
`upstream.kind` (empty defaults to `"plain"` — backward compatible) and
fail-closes on an unknown kind (no silent fallback). Duplicate registration panics
(matching the rule registry).

**The core never depends on `PRSupport` or `IssueSupport`** — enforced by a
`go/parser` AST-scan test (`internal/port/prsupport_core_isolation_test.go`) that
fails if any production file in `internal/gitproto`, `internal/transport`,
`internal/policy`, or `cmd` references either capability identifier. (The scan
walks `gitproto`, `transport`, and `cmd` recursively so the frontend subpackages
`transport/http` and `transport/ssh` are covered; `policy` is scanned top-level
only so `policy/rules` — which may legitimately type-assert a capability in a
future rule — is excluded.) `cmd/git-proxy/main.go` passes a `port.Upstream` (or
`nil`) for the issue upstream and never names `IssueSupport`; the type-asserts
live in `internal/broker`, which is outside the scanned core set.

---

## Issue tracker (`port.IssueSupport`)

Issues are a **distinct, optional** capability — an adapter may offer issues
without offering PRs (a future Jira adapter implements `IssueSupport` only).
Crucially, the issue tracker is sourced from a **separately-configured
`issue_upstream`**, decoupled from the SCM `upstream` that backs `PRSupport`:

- v1 sets **both** to `kind: github` (the GitHub adapter implements both
  `PRSupport` and `IssueSupport`; two `*Adapter` instances are built — one as the
  SCM upstream, one as the issue upstream — sharing the same URL/creds file). PRs
  and issues both come from GitHub.
- The same seam lets a future deployment set `upstream.kind: github` (SCM/PRs) +
  `issue_upstream.kind: jira` (issues) with **no core change** — mirroring how
  `PRSupport` already lets a future GitLab adapter slot in.

`port.IssueSupport` (`internal/port/issues.go`) is nine methods:
`CreateIssue`, `GetIssue`, `ListIssues`, `CommentIssue`, `CloseIssue`,
`ReopenIssue`, `EditIssue`, `AddLabels`, `RemoveLabel`, with `Issue` (the create
result) and `IssueState` (the read shape) types. It reuses the existing `port`
sentinels — no new ones — so the broker's no-leak `writeError` mapping is
unchanged (404/403/422/429/502/501 all map generically).

**To add one** (worked example = the GitHub adapter, which implements
`IssueSupport` alongside `PRSupport`):

1. In your adapter package, satisfy `port.IssueSupport` (a `var _ port.IssueSupport
   = (*Adapter)(nil)` compile check) and implement the nine methods. Each builds a
   REST client from the per-repo token (fail-closed via the same `tokenFor` the
   `PRSupport` methods use — never anonymous) and calls the matching REST op. The
   github adapter maps `rest.Issue`→`port.Issue` and `rest.IssueState`→
   `port.IssueState` explicitly so the `rest` package stays a pure client with no
   `port` import for its response shapes.
2. The package is already registered (the same `init()` that registers it as an
   SCM provider). `upstream.Build` resolves it by `issue_upstream.kind`.
3. `cmd/git-proxy/main.go` builds the issue upstream only when
   `issue_upstream.kind` is set: it resolves a second `port.CredentialStore` from
   `issue_upstream.credentials_file` and calls `upstream.Build` a second time,
   passing the result (or `nil`) to the broker. **`main.go` never references
   `port.IssueSupport`** — it hands the broker a `port.Upstream`; the broker
   type-asserts `IssueSupport` off it.
4. Select in config:
   ```yaml
   issue_upstream:
     kind: github
     url: "https://github.com"
     credentials_file: /credentials.yaml
   ```

**The broker consumes `IssueSupport` additively** (`internal/broker`): `New` takes
an `issueUp port.Upstream` (may be `nil`); it type-asserts `IssueSupport` off it
**non-fatal** — `issueUp == nil` or it lacks `IssueSupport` → `b.issues = nil`,
no error. The `PRSupport` startup fail-closed is **unchanged** (the broker still
refuses to start if the *SCM* upstream lacks `PRSupport`). With `b.issues == nil`,
every issue route returns **501 per-op** (issues are opt-in), while PR/CI routes
keep working — auth still gates first (401 before 501, so a missing Bearer never
leaks "issues are configured"). Nine issue routes are exposed
(`POST /{repo}/issues`, `GET /{repo}/issues[/{number}[/{comments|close|reopen|edit|labels[/remove]}]]`);
handlers reuse the same `authOK`→`issuesOK`→decode→call→`audit`/`opFail` flow as
the PR handlers. `EditIssue` sends only non-empty fields (pointer-omitted JSON)
so an agent never blanks a field by accident; `RemoveLabel` URL-encodes the label
on the upstream path (the broker takes it in the JSON body, so path-encoding
concerns stay inside the REST client).

---

## Frontend

A frontend terminates one transport (HTTP, SSH) and routes the git pack commands
through a `*gitproto.Proxy`. **As-built deviation from `v1.md`:** frontends do not
use `port.GitConn`; each holds its own `*gitproto.Proxy` and calls
`Proxy.UploadPack` / `Proxy.ReceivePack` directly. `port.GitConn`
(`internal/port/gitconn.go`) is reserved and currently unused — do not build new
frontends against it.

**To add one:**

1. New package under `internal/transport/` implementing `port.Transport`
   (`Serve(ctx) error`).
2. Hold a `*gitproto.Proxy` (built via `gitproto.New(up)`), expose
   `SetEnforcement`, `SetReadDeny`, `SetAuditSink`, `SetAlertSink`, `SetDryRun`
   thin wrappers (exactly like `internal/transport/http/frontend.go` and
   `internal/transport/ssh/frontend.go`), so `main.go` wires the SAME
   engine/mirror/readDeny/audit/alerts/dry-run into every transport.
3. Resolve the agent identity into the request context via `auth.WithAgent`
   (so the proxy's audit/alert recording attributes the op).
4. Construct it in `cmd/git-proxy/main.go`, wire the shared enforcement state, and
   run `Serve` alongside the other frontends.

Reference: `internal/transport/http/frontend.go` (HTTPS smart-HTTP, three
endpoints), `internal/transport/ssh/frontend.go` (SSH, raw v0 advertisement, key
auth). Both feed the same `*gitproto.Proxy` handlers — there is no SSH-specific
enforcement bypass.

---

## Auth method

An authenticator maps a presented credential to an `auth.AgentIdentity`.
`port.Authenticator.Authenticate(ctx, token) (auth.AgentIdentity, error)`.
Fail-closed: an unknown credential returns an error.

**To add one:**

1. New package implementing `port.Authenticator`.
2. Construct it in `main.go` from the relevant config block and pass it to the
   frontend. HTTP uses Bearer tokens (`internal/auth/token`, `auth.tokens`); SSH
   uses public keys (`internal/auth/keyauth`, `ssh.authorized_keys`, keyed by
   `ssh.FingerprintSHA256`). The `auth.AgentIdentity` + `auth.WithAgent`/`FromContext`
   mechanism unifies them so the protocol/audit layers are auth-method-agnostic.

There is no auth registry: auth is per-transport and selected by config presence,
constructed explicitly in `main.go`.

---

## Secret scanner

`port.SecretScanner` scans blob content for secrets. It is constructed inside the
`secret_scan` rule (not a top-level seam) and plugged into the rule's config.

**To add one:** implement `port.SecretScanner` (e.g. a new package under
`internal/secret/`), then have the `secret_scan` rule (or a new rule) construct it
from its rule params. Reference: `internal/secret/regex` (regex + Shannon entropy,
skips binary blobs, redacts matched secrets in reasons).

---

## Credential store

`port.CredentialStore` is the vault of per-repo upstream credentials the proxy
attaches on the proxy→upstream leg. The agent never sees these. The v1
implementation is `internal/credentials/profile` — a YAML **list** of named
profiles, not the older file-based JSON vault (the `internal/credentials/file`
package is deleted). The surface is **frozen**: `port.Credentials` and
`port.CredentialStore` are unchanged — there is no `Anonymous` field; the
deny/anonymous decision is the frontend's via `internal/access` (below), not a
store flag.

**Schema** (`credentials.yaml`):

```yaml
credentials:
  - name: company_abc            # required, matches ^[A-Za-z_][A-Za-z0-9_]*$
    description: "Main org token" # optional, human-only (logged in warnings)
    username: ci-bot
    password: hunter2            # git-HTTP Basic
    token: ghp_broker_token      # broker REST (Bearer); empty = git-only
    repos: ["mycompany/*"]       # patterns matched against the upstream repo path
```

- **List layout** under `credentials:`; each profile has `name`, optional
  `description`, `username`, `password`, `token`, and `repos` (a list of
  patterns). The proxy reads the file once at startup (env is resolved at
  startup, not per-request).
- **Env override — env > file > empty.** The env-var name is the profile name
  **UPPERCASED** (e.g. `name: company_abc` → `COMPANY_ABC_USERNAME`,
  `COMPANY_ABC_PASSWORD`, `COMPANY_ABC_TOKEN`). A set-and-non-empty env var
  overrides the file value; an empty env var is treated as unset so an operator
  can blank a file secret by setting the env var to `""`.
- **Per-org wildcards** like `mycompany/*` are allowed (matched via stdlib
  `path.Match`, where `*` is one path segment). A bare `*` or any `**` is
  rejected — the proxy refuses to start.
- **Startup validation** is split:
  - **Fatal** (returns an error, proxy refuses to start): the file cannot be
    read/parsed; a profile name is empty or fails `^[A-Za-z_][A-Za-z0-9_]*$`; a
    duplicate name (case-insensitive); a profile with no `repos`; a malformed
    pattern (bare `*`, `**`, `path.Match` syntax error); or the same exact repo
    or same wildcard pattern in two profiles.
  - **Warning** (non-fatal, proxy starts): a secretless profile (password AND
    token both empty after env resolution) or a one-legged profile (token set,
    password empty, or vice versa). The warning names the **env-var NAMES** and
    the **description** — never the resolved secret.
- **Secretless profile → `(zero, false)`.** A profile whose resolved password
  and token are both empty still matches its `repos`, but `CredentialsFor`
  returns `(zero, false)`, so the deny decision falls through to `public_repos`
  (deny-by-default). A profiled repo (with a usable secret) returns its creds
  and the request is allowed.

**`public_repos` + `port.RepoMatcher` (deny-by-default tri-state).** Separately
from the credential vault, `config.yaml` may declare a top-level
`public_repos:` list of upstream repo patterns the proxy serves to anonymous
(uncredentialed) agents for **read-only** (clone/fetch) access. The list is
validated at startup by `internal/credentials/repomatch.NewBoolMatcher`, which
returns a `port.RepoMatcher` (`Match(repo string) bool`); a nil/absent
`public_repos` means a matcher that matches nothing. `cmd/git-proxy/main.go`
passes the matcher to both frontends. The frontends call
`access.Decide(creds, public, repo, isWrite)` from `internal/access`, a
fail-closed tri-state:

- `creds.CredentialsFor(repo)` ok → **Allow** (the upstream leg attaches Basic
  auth from the profile).
- no creds, **read**, and `public.Match(repo)` → **Allow** (anonymous
  read-only; the upstream leg attaches nothing).
- no creds + **write**, or no creds + no public match → **Deny** (403 HTTP /
  structured ERR + non-zero exit SSH; the upstream is never contacted).

So a repo with no credential profile and no `public_repos` entry is denied
before any upstream call — **deny-by-default**. A `public_repos` repo + push is
denied (writes always require a credential, even for public repos). 401
(missing/invalid agent Bearer) precedes 403 (HTTP).

**`internal/credentials/repomatch`** is the shared repo-key matcher used by both
the profile store (resolving a repo to its profile) and the `public_repos`
allowlist (`NewBoolMatcher`). It is **deliberately separate** from
`internal/pathmatch`: `pathmatch` is gitignore-style in-repo **file-path**
matching (e.g. `secrets/**` withheld from a fetch); `repomatch` is
**repo-key** matching via stdlib `path.Match` (e.g. `mycompany/*` selects a
profile). Different domains, different semantics.

**To add one:** implement `port.CredentialStore`
(`CredentialsFor(repo) (Credentials, bool)`), construct it in `main.go` from
`upstream.credentials_file`, and pass it both to the upstream adapter (via
`upstream.UpstreamConfig.CredentialsStore`) and to the frontends (for the
info/refs reverse-proxy leg). A secret-manager backend (Vault, AWS Secrets
Manager, …) lands later behind the same interface. Reference:
`internal/credentials/profile` (YAML profile vault, env-over-file),
`internal/credentials/repomatch` (shared repo-key matcher),
`internal/access/access.go` (`Decide` — the deny-by-default tri-state).

---

## Audit sink / Alert sink

`port.AuditSink` records every policy decision; `port.AlertSink` fires a
notification on every deny (enforced or dry-run). Both are best-effort / non-fatal
(a sink failure never changes the verdict or blocks the op) and no-leak (only
generic redacted reasons / paths / OIDs — never blob content, raw secrets, upstream
creds, or packfile bytes).

**To add one:** implement the interface, construct it in `main.go` from its config
block, and wire it into both frontends via `SetAuditSink` / `SetAlertSink`.
`internal/alert` provides a `MultiAlertSink` so several alert sinks fan out (each
best-effort). Reference: `internal/audit/file` (append-only JSONL),
`internal/alert/webhook` (HTTP POST), `internal/alert/log` (stderr).

---

## Adding it all up

The two registries (rules, upstreams) use the same shape — a `Factory` type, a
`Register` that panics on duplicate, a `Build`/`Resolve` that fail-closes on
unknown names, and self-registration via `init()`. The other seams are constructed
explicitly in `main.go` because they have one active instance selected by config
presence rather than by name. To ship a new integration end-to-end you typically
add one rule + one SCM adapter + (if needed) one credential store, register the two
self-registering packages via blank imports in `main.go`, and select them in
config — no core changes required.