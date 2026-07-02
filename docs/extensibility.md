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
| Frontend | `port.Transport` | (constructed in `main.go`) | `listen` / `ssh.listen` | `internal/transport/http`, `internal/transport/ssh` |
| Auth method | `port.Authenticator` | (constructed in `main.go`) | `auth.tokens` / `ssh.authorized_keys` | `internal/auth/token`, `internal/auth/keyauth` |
| Secret scanner | `port.SecretScanner` | (constructed in the rule) | (inside `secret_scan` rule config) | `internal/secret/regex` |
| Credential store | `port.CredentialStore` | (constructed in `main.go`) | `upstream.credentials_file` | `internal/credentials/file` |
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
       _ port.Upstream  = (*Adapter)(nil)
       _ port.PRSupport = (*Adapter)(nil)
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

**The core never depends on `PRSupport`** — enforced by a compile-check test
(`internal/port/upstream_prsupport_seam_test.go`) that fails if any file in
`internal/gitproto`, `internal/transport`, `internal/policy`, or `cmd` references
`port.PRSupport`.

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
attaches on the proxy→upstream leg. The agent never sees these.

**To add one:** implement `port.CredentialStore` (`CredentialsFor(repo) (Credential, bool)`),
construct it in `main.go` from `upstream.credentials_file`, and pass it both to the
upstream adapter (via `upstream.UpstreamConfig.CredentialsStore`) and to the
frontends (for the info/refs reverse-proxy leg). Reference:
`internal/credentials/file` (file-based JSON vault; a secret-manager backend lands
later behind the same interface).

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