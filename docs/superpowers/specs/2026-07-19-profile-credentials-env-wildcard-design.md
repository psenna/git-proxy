# Profile-based credentials with env override, wildcard fallback, and public-clone allowlist — Design

**Goal:** Replace the per-repo credentials map with a list of credential *profiles*, each sourcing its secret from environment variables (with an optional file-literal fallback) and matching a list of repositories that may include per-org wildcard fallbacks; add an explicit public-clone allowlist in `config.yaml` and flip the default for unconfigured repos from anonymous passthrough to **deny** — all while preserving the proxy's no-leak and fail-closed security posture and keeping `port.Credentials` and `port.CredentialStore` unchanged.

**Architecture:** A new `port.CredentialStore` implementation (`internal/credentials/profile`) parses `credentials.yaml` as a list of profiles, resolves each field via **env > file literal > empty** (uppercasing the profile name to form env-var names), and builds an exact-repo table plus a wildcard matcher. A separate, shared matcher (`internal/credentials/repomatch`) is built from a new top-level `public_repos` list in `config.yaml` and passed to the git-leg frontends. The frontend decides a tri-state per request using the **unchanged** `CredentialsFor` (creds / no-creds) and the public-repos matcher: *attach creds*, *anonymous read*, or *deny*. `main.go` switches its import to the new profile package and wires the public-repos matcher; `port.Credentials`, `port.CredentialStore`, `plain.applyCreds`, `gitx`, and the broker are unchanged.

**Tech stack:** Go stdlib only (`os`, `path`, `strings`, `regexp`, `gopkg.in/yaml.v3`). No new dependencies.

## Context

Today `internal/credentials/file/store.go` parses `credentials.yaml` as a map keyed by exact repo path → `{username, password, token}`:

```yaml
credentials:
  "orgA/repo1.git": { username: x-access-token, password: ghp_..., token: ghp_... }
```

`CredentialsFor(repo)` is a plain `map[repo]Credentials` lookup (`store.go:62`), so:

- No wildcard support — `mycompany/*` would create a literal key `"mycompany/*"` that never matches `mycompany/repo1.git`.
- Secrets must be written into the file (the deploy/docker demo `sed`-substitutes a Gitea token into `credentials.yaml`), which is awkward for compose-based deploys and means a secret sits on disk.
- Every repo under an org must be enumerated individually, even when one PAT covers the whole org.
- **Unconfigured repos clone anonymously** — `handleInfoRefs` (`frontend.go:182`) and the read-protected variant (`:208`) call `applyUpstreamCreds` which attaches Basic only when `ok`; when `ok=false` they reverse-proxy to upstream with no auth. `handleService` goes through `plain.applyCreds`, same behavior. A repo with no credentials entry is an open anonymous relay to the upstream — the wrong default for a security gateway.

The user wants three changes, brainstormed and decided:

1. **New layout** — `credentials.yaml` becomes a list of profiles; each profile has a `name` (the env stem), an optional `description`, an optional literal `username`/`password`/`token`, and a `repos` list.
2. **Env override + wildcard fallback** — every field resolves from env first (file literal as fallback); the profile `name` is **uppercased** to form env-var names; the `repos` list supports per-org wildcard entries (`mycompany/*`) as a fallback when no exact entry matches; a startup warning is logged if any wildcard is configured.
3. **Deny-by-default + public allowlist** — a repo with no credential profile is **denied** (no anonymous passthrough). An explicit `public_repos` list in `config.yaml` grants **read-only** anonymous access to listed repos.

## Decisions (locked with the user)

| Decision | Choice |
|---|---|
| Layout migration | **Replace entirely** — the old per-repo map is removed; `credentials.yaml` is the list-of-profiles form only. |
| Wildcard scope | **Per-org prefix only** — `*` matches one path segment (no slashes) via `path.Match`. No bare `*`, no `**`. |
| Missing secret at startup | **Validate all profiles, log warnings for non-functional creds, do not refuse to start; fail per request.** Structural config errors remain fatal. A file literal is allowed and overridden by env. |
| Package | **New `internal/credentials/profile`** (profiles) + **`internal/credentials/repomatch`** (shared matcher); delete `internal/credentials/file`; `main.go` switches its import. |
| Env-overridable fields | **All three** — `username`, `password`, `token` all resolve via `<NAME>_<FIELD>` env, falling back to the file literal. |
| Env stem casing | **The profile `name` is uppercased** to form env-var names: `name: company_abc` reads `COMPANY_ABC_TOKEN`. Duplicate detection compares uppercased names. |
| Wildcard startup warning | **Log one summary warning at startup if any wildcard is configured** (in profiles or `public_repos`). |
| Profile description | **Optional `description` field**, human-readable; surfaced in startup warnings. |
| Unconfigured-repo default | **Deny** (no anonymous passthrough); only `public_repos` repos may be cloned without creds, **read-only**. |
| Allowlist design | **`public_repos` in `config.yaml` + a separate shared matcher** passed to the git-leg frontends. `port.Credentials` and `port.CredentialStore` stay frozen; the frontend does the tri-state using the unchanged `CredentialsFor` + the matcher. |

## Non-goals

- Bare catch-all `*` and multi-segment `**` patterns (deferred — see Future).
- A secret-manager backend (Vault, AWS SM). The `port.CredentialStore` seam already supports this as a separate implementation; out of scope here.
- Hot reload / rotation without restart. Env is snapshotted at startup; rotation = restart.
- Changing `port.Credentials`, `port.CredentialStore`, `plain.applyCreds`, `gitx`, or the broker. The cred-attach path is untouched; only the git-leg frontend handlers gain a tri-state branch, and `config`/`main.go` gain the `public_repos` wiring.

---

## Config layout

`credentials.yaml` — profiles only:

```yaml
credentials:
  - name: company_abc              # required, unique; UPPERCASED for env: COMPANY_ABC_*
    description: "Company ABC prod PAT"   # optional, human-readable
    username: x-access-token        # optional literal (non-secret); git-HTTPS Basic user
    password: ghp_abc_pat          # optional literal secret
    token: ghp_abc_pat             # optional literal secret
    repos:
      - mycompany/repo1.git         # exact
      - mycompany/repo2.git
      - mycompany/*                # wildcard fallback (one segment, no slashes)
  - name: COMPANY_XYZ
    description: "XYZ CI bot"
    username: x-access-token
    repos:
      - otherorg/*
```

`config.yaml` — gains a top-level `public_repos`:

```yaml
# Repos that may be cloned/fetched ANONYMOUSLY (read-only). A repo here with no
# matching credential profile is served with no Basic auth. Push (receive-pack)
# to any repo always requires a credential, even one listed here. Absent → no
# anonymous clones; every repo needs a profile.
public_repos:
  - publicorg/awesome.git
  - publicorg/*
```

Field defaults: `description`, `username`, `password`, `token` are all optional. `name` and `repos` are required per profile. `public_repos` is optional (absent → no anonymous clones).

## Field resolution — env > file > empty

For each field (`username`, `password`, `token`), per profile, resolved at startup:

1. If env var `<NAME>_<FIELD>` is set and non-empty → use it. `<NAME>` is `strings.ToUpper(profile.Name)`.
2. Else if the file literal for that field is set → use it.
3. Else → empty.

Env names are **uppercased from the profile name**, case-sensitive after uppercasing: `name: company_abc` reads `COMPANY_ABC_USERNAME`, `COMPANY_ABC_PASSWORD`, `COMPANY_ABC_TOKEN`. `name: COMPANY_ABC` reads the same. The same file works for local dev (literal PAT inline, no env) and prod (env set in compose overrides the file). One uniform rule for all three fields; `username` is non-secret so it usually stays in the file, but env works if an operator wants it there.

## Repo matching

A single shared matcher (`internal/credentials/repomatch`) backs both the profile `repos` lists and `public_repos`. Rules:

- **Exact** entry (no `*`): literal string match.
- **Wildcard** entry (contains `*`): matched with `path.Match(pattern, repo)`. `*` matches a single path segment and **does not cross `/`**. So `mycompany/*` matches `mycompany/repo1.git` and `mycompany/repo2.git`, but **not** `mycompany/team/repo1.git`. Both `mycompany/*` and `mycompany/*.git` are valid (the latter is more precise; the former is simpler and recommended).
- **No bare `*`, no `**`.** A pattern that is exactly `*` or that contains `**` is a startup config error (rejected) — these are the broad-global-token shapes that would re-introduce the multi-repo fail-closed regression.
- **Precedence** (deterministic, documented): exact match wins over any wildcard; among matching wildcards, the **longest pattern string** wins (most specific); ties (same-length different patterns both matching) broken by **earliest declared**.

The profile store uses the matcher to map a repo → its profile (and resolved creds); the frontend uses a `bool`-valued matcher built from `public_repos` to decide anonymous-read eligibility.

## Startup behavior

### Fatal at startup (refuse to start) — structural config errors

These are misconfigurations, not missing secrets, and are rejected at startup (the profile store's `New` or the public-repos matcher's `New` returning an error → main.go exits), consistent with the existing file store and `upstream.Build`:

- Unparseable / unreadable credentials YAML (existing behavior).
- Profile missing `name`, or `name` empty.
- `name` is not a valid env-var name: must match `^[A-Za-z_][A-Za-z0-9_]*$` (any case as written; uppercased for env lookup).
- Duplicate `name` across profiles, compared **case-insensitively after uppercasing** (so `company_abc` and `COMPANY_ABC` collide → fatal).
- Profile missing `repos`, or `repos` empty.
- Malformed wildcard pattern (`path.Match` returns a syntax error), bare `*`, or any pattern containing `**` — in either a profile's `repos` or in `public_repos`.
- The same exact repo string listed in two different profiles.
- The same wildcard pattern listed in two different profiles.
- The same exact repo or wildcard pattern listed twice within `public_repos`.

### Non-fatal at startup (log warnings) — non-functional credentials and wildcards

- **Wildcard warning (new).** If any wildcard pattern is configured anywhere (in any profile's `repos` or in `public_repos`), `main.go` logs **one** summary warning aggregating both sources, e.g.:
  `warning: wildcard repo matchers configured — profiles: "mycompany/*" (company_abc — Company ABC prod PAT), "otherorg/*" (COMPANY_XYZ — XYZ CI bot); public_repos: "publicorg/*" — matching repos receive that profile's PAT (or anonymous read for public_repos); verify least-privilege`.
  The warning includes each profile wildcard's owning `name` + `description` so the operator can identify blast radius. To aggregate, the profile store and the public-repos matcher each expose their wildcard patterns; `main.go` combines and logs once. Non-fatal.
- **Non-functional credential warning.** For each profile, after resolving all fields (env > file > empty): if **both** `password` and `token` are empty → log a warning: `profile "company_abc" (Company ABC prod PAT) has no usable credential; set COMPANY_ABC_PASSWORD/COMPANY_ABC_TOKEN (or a file value); repos under it will not be credentialed`. Names env-var **names** (uppercased) and the `description`, never any value. (Logged by the store during `New`.)
- **One-legged profile info.** If exactly one of `password`/`token` is set → log an info line naming the profile + description (e.g. `profile "company_abc" has token but no password — broker-only; git-HTTP clone will not be credentialed`). Informational.

The proxy starts regardless of missing secrets or wildcards.

### Per-request behavior — tri-state (deny / anonymous-read / attach)

This is the core behavior change. The git leg now distinguishes three states per request, using the **unchanged** `CredentialsFor(repo) (Credentials, bool)` plus the public-repos matcher:

| State | Condition | Git-leg behavior |
|---|---|---|
| **Attach creds** | `CredentialsFor` returns `ok=true` (repo has a profile with a secret) | Attach Basic on the proxy→upstream leg and proxy (existing behavior, unchanged for read and write). A profiled repo is **never** served anonymously — the profile wins over `public_repos`. |
| **Anonymous read** | `ok=false` **and** `public_repos` matches the repo **and** the op is a read (info/refs for upload-pack, or git-upload-pack) | Proxy to upstream with **no Basic auth** (the existing no-cred path, now gated by the allowlist). |
| **Deny** | `ok=false` and (the op is a write — info/refs for receive-pack or git-receive-pack — **or** `public_repos` does not match) | Respond **403** with a fixed generic reason (`"repository not served by this proxy"`); **do not** reach upstream. |

Notes:
- **Push always requires a credential.** A repo on `public_repos` with no profile → anonymous read OK, but push → 403. (Matches GitHub's public-read / authenticated-write model.)
- **A secretless profile** (a profile whose `password` and `token` are both empty after resolution) returns `ok=false` from `CredentialsFor` — it contributes no credentials. Its repos therefore fall through to the `public_repos` decision (anonymous read if listed, deny otherwise). The startup non-functional warning flags the missing secret. "Profile wins over public_repos" applies to profiled-**with-secret** repos (`ok=true`); a secretless profile does not claim its repos.
- **Unauthenticated requests** (no/invalid Bearer) are rejected with 401 *before* the repo check, so a 403 never leaks "which repos exist" to an unauthenticated caller.

## Why `port.Credentials` and `port.CredentialStore` stay frozen

Because `public_repos` lives in `config.yaml` and the frontend consults a separate matcher, the credential store only answers "what creds for this repo?" with its existing two-state `(Credentials, bool)`. The deny-vs-anonymous decision is the frontend's, using the matcher. So:

- `port.Credentials` — **unchanged** (no `Anonymous` field).
- `port.CredentialStore` interface — **unchanged**; every test fake compiles unmodified.
- `internal/upstream/plain` `applyCreds`, `internal/transport/http` `applyUpstreamCreds`, `internal/gitx/mirror.go` — **unchanged**. They already attach Basic only when `ok` and do nothing when `ok=false`; the tri-state is decided in the frontend *before* they're reached (deny → no upstream call; anonymous read → `ok=false` → they attach nothing, exactly as today).
- **Broker** — **unchanged.** `tokenFor` already fail-closes on `!ok` and on empty `Token`; a `public_repos` repo (no profile) → `!ok` → `ErrUnauthorized`. The public-repos matcher is not consulted by the broker; `public_repos` is git-leg-only.

## Consumer changes (git-leg frontends only)

- **`internal/transport/http` `New`** gains a `publicRepos port.RepoMatcher` param (nil → no public repos → every no-cred repo denied). `handleInfoRefs`, `handleInfoRefsReadProtected`, `handleService`: before proxying, compute the tri-state from `CredentialsFor` + `publicRepos` + the service type; deny with 403 (generic reason, no upstream call) when appropriate, else proxy (attaching creds when `ok`, anonymous when `!ok && publicRepos.Match && read`.
- **`internal/transport/ssh` `New`** gains the same `publicRepos port.RepoMatcher` param; its git ops get the same tri-state.
- **`port.RepoMatcher`** — a new tiny interface in `internal/port`: `Match(repo string) bool`. The shared `match` matcher satisfies it; the frontends depend on `port` (already do), not on `internal/credentials`. `main.go` builds the matcher from `cfg.PublicRepos` and passes it as `port.RepoMatcher`.
- **No other consumer changes.** `plain`, `gitx`, `config` (besides the new field), the broker, and every `CredentialStore` fake are untouched.

## Package + wiring

- **`internal/credentials/repomatch`** (new): a generic exact+wildcard matcher (`Matcher[V]` with `New(pairs []Pair[V]) (*Matcher[V], error)` and `Match(repo) (V, bool)`; precedence exact > longest wildcard > earliest). Pattern validation (`path.Match` syntax; reject bare `*` and `**`). Exposes `WildcardPatterns()` for the startup warning.
- **`internal/credentials/profile`** (new): parses the `credentials.yaml` list layout, resolves env (uppercased stem, env > file > empty), builds a `repomatch.Matcher[*profile]`, runs startup validation, logs the non-functional-credential and one-legged-profile warnings, and exposes `New(path) (*Store, error)` + `CredentialsFor(repo) (port.Credentials, bool)` + `WildcardPatterns()` (with profile name/description, for the aggregated warning).
- **Delete `internal/credentials/file`** and its tests.
- **`internal/port/credentials.go`**: add the `RepoMatcher` interface (one method). `Credentials` and `CredentialStore` unchanged.
- **`internal/config/config.go`**: add `PublicRepos []string \`yaml:"public_repos"\`` (top-level). Optional; validated by the matcher builder (pattern syntax), not by `Validate` (which just holds the strings).
- **`cmd/git-proxy/main.go`**: switch the credential import from `internal/credentials/file` to `internal/credentials/profile` (`profile.New(cfg.Upstream.CredentialsFile)`, `profile.New(cfg.IssueUpstream.CredentialsFile)` — same `New(path)` signature). Build `publicRepos port.RepoMatcher` from `cfg.PublicRepos` via `match.New[struct{}](…)` (or a `BoolMatcher` adapter); pass it to `http.New` and `ssh.New`. Log the aggregated wildcard warning if either the profile store or the public-repos matcher has wildcards. `main.go` still never references `port.PRSupport`/`port.IssueSupport`.

## Security posture

- **No-leak**: secrets resolve from env (prod) or the local file (dev); the store never logs or returns a secret value. Startup warnings name env-var **names** and `description`s, never values. Broker error reasons stay generic class strings. The deny-403 reason is a fixed string. Audit carries no credential content. Unauthenticated → 401 before any repo check.
- **Fail-closed**: a missing secret → no creds → the repo is governed by `public_repos` (deny unless listed). An unconfigured repo → deny (no open relay). `public_repos` is opt-in and read-only. The broker never goes anonymous.
- **Bounded blast radius — no regression**: wildcards are opt-in (`mycompany/*`) and there is **no bare `*`**, so a broad PAT is never attached to an arbitrary unknown repo. The multi-repo fail-closed regression discussed earlier is not re-introduced. The startup wildcard warning makes blast radius visible. Exact entries can still pin a distinct PAT per repo for least-privilege. `public_repos` wildcards broaden **read** only — lower risk than a credential wildcard, and still surfaced by the warning.

## Migration

- **`deploy/docker/credentials.yaml`** → new list layout (profiles only; no `public_repos` here). The demo repo `demo/demo.git` is **profiled** (it has creds), so the deny-by-default change does **not** affect it — the demo still clones/pushes as today. The README's `sed -i "s/REPLACE_WITH_GITEA_ACCESS_TOKEN/$TOKEN/" credentials.yaml` step becomes setting `GITEA_PASSWORD`/`GITEA_TOKEN` in `docker-compose.yml` under the `git-proxy` service `environment:` (env overrides the file). No `public_repos` needed for the demo. Update `deploy/docker/README.md` and `docs/deploy-docker.md`.
- **`example/github-claude-code/credentials.yaml`** → new list layout; `${GITHUB_REPO}` is profiled, so unaffected by deny-by-default. `.env`/compose sets the `COMPANY_*` env (or a literal inline for local). If the agent should also clone a public repo not in credentials, add it to `public_repos` in `config.yaml`. Update `example/github-claude-code/README.md`'s "Fill in your secrets" section and `config.yaml`.
- **Docs**: `docs/extensibility.md` credential-store section (new layout, env override + uppercasing, wildcard semantics, the new packages, the `public_repos` allowlist + deny-by-default, `port.RepoMatcher`); `docs/deploy-docker.md`; example README + config; `agent/skills/use-git-proxy/SKILL.md` operator-facing credential notes.
- **Tests**:
  - Rewrite the store's unit tests for the new layout (profiles only).
  - Add coverage for: env-over-file precedence; **uppercasing** (`name: company_abc` reads `COMPANY_ABC_TOKEN`; `company_abc` and `COMPANY_ABC` collide fatally); profile matching precedence (exact > longest wildcard > earliest); no-match → `(zero, false)`; secretless profile → `(zero, false)`; every fatal structural error; the **non-functional-credential warning** and the **one-legged-profile info** (assert logged, `New` does **not** error); `description` surfaced in warnings.
  - `internal/credentials/repomatch` unit tests: exact > longest wildcard > earliest; `*` one-segment semantics; reject bare `*`/`**`/malformed; `WildcardPatterns()`.
  - **Frontend (http + ssh) tri-state**: deny 403 for unconfigured (and assert the upstream is **not** called — e.g. an httptest server that fails the test if hit); anonymous read proxies with no `Authorization` header to upstream; anonymous push → 403; profiled → Basic attached. Unauthenticated → 401 before the repo check (no 403 leak).
  - **Audit existing git-leg tests** for any that relied on anonymous passthrough for an un-profiled repo (the old `ok=false` → proxy behavior). Those now get a 403; give them a profile or a `public_repos` entry. The broker `fakeGHVault` is unaffected (returns creds for its repo; the broker never goes anonymous and never consults `public_repos`).
  - Integration: existing broker integration test updated to the new `credentials.yaml` layout; `fakeGHVault` unchanged; confirm broker still attaches `Bearer ghp_test` upstream and never forwards the agent token (the store change is below this layer; the broker path is unchanged).

## Test plan

- **Unit (`internal/credentials/repomatch`)**: table-driven — exact beats wildcard; longest wildcard wins; earliest-declared tiebreak; `mycompany/*` matches `mycompany/repo.git`, rejects `mycompany/team/repo.git` and `otherorg/repo.git`; no-match → false; `path.Match` syntax error, bare `*`, `**` → `New` errors; `WildcardPatterns()` returns the wildcards in declaration order.
- **Unit (`internal/credentials/profile`)**: field resolution (env > file > empty; env-empty-string falls back to file; uppercasing); matching (exact > longest wildcard > earliest); tri-state (`(creds, true)` for profiled-with-secret, `(zero, false)` for secretless profile and no-match); startup fatal (each structural error, incl. case-insensitive dup name); startup non-fatal (no-secret warning with uppercased env names + description; one-legged info; both logged and `New` returns nil error); `WildcardPatterns()` carries profile name/description.
- **Frontend (http + ssh)**: tri-state as above; assert no upstream call on deny; assert no `Authorization` header on anonymous read; assert Basic attached for profiled; assert 401 (not 403) for unauthenticated.
- **main.go smoke**: proxy starts with no `public_repos` (all no-cred denied) and with `public_repos` set; aggregated wildcard warning logged when either source has wildcards.
- **CI gates (every commit)**: `go vet`, `golangci-lint`, `go build`, `go test ./... -race`, `govulncheck`. Conventional Commits (`feat(credentials): …`, `feat(config): …` for `public_repos`, `feat(transport): …` for the frontend tri-state).

## Notes / risks

- **Behavior change for unconfigured repos is intentional and security-positive**, but it is a behavior change: any deployment that today relies on the proxy anonymously relaying a repo not in `credentials.yaml` will get 403 after this. The fix is to add the repo to `public_repos` (read) or a profile (read+write). The Gitea demo and the github example are unaffected (their repos are profiled).
- **Frontend constructor signature changes** (`http.New`/`ssh.New` gain a `port.RepoMatcher` param). `main.go` is the only production caller; direct test constructors are updated. This is the only consumer-facing surface change.
- **`public_repos` is read-only.** A repo listed there with no profile can be cloned/fetched anonymously but **not** pushed (push → 403). "Anonymous read + credentialed write for the same repo" is not supported in v1 — listing a repo in both a profile and `public_repos` means the profile wins (fully credentialed); to get anonymous read you list it in `public_repos` only and accept pushes aren't served. Deferred (would need the store/matcher to know the service type).
- **Aggregated wildcard warning** requires the profile store and the public-repos matcher to expose their wildcard patterns to `main.go`, which logs once. If that coupling is unwanted, each component can log its own warning (two lines) — functionally equivalent, slightly noisier.
- **`repomatch` is deliberately separate from the existing `internal/pathmatch`.** `pathmatch` is a gitignore-style **file-path** matcher (in-repo paths like `secrets/**`, with depth/anchoring rules and `**` multi-segment support) used by `path_acl`/read-deny. Repo keys need stdlib `path.Match` semantics (`*` = exactly one path segment, no `/`; `**` not supported) and exact-segment anchoring. Different domains, different semantics — reusing `pathmatch` would import the wrong matching rules. The new `internal/credentials/repomatch` uses `path.Match` directly.

## Out of scope / future

- **Bare `*` and `**`** — deliberately excluded to keep blast radius bounded. If needed later: `**` for multi-segment, and an explicit opt-in (e.g. `allow_catchall: true`) for bare `*`, with a startup warning. Same matcher, extended.
- **Anonymous-read + credentialed-write for the same repo** — deferred (needs service-type awareness in the matcher decision).
- **Secret-manager backend** — a separate `port.CredentialStore` (e.g. `internal/credentials/vault`) alongside this one; config selects by presence. The seam already supports it.
- **Hot reload / rotation without restart** — env is snapshotted at startup. A future store could re-read per request or on SIGHUP; deferred.
- **`issue_upstream.credentials_file`** — already supported (same `profile.New` call in main.go); the same layout/rules (profiles only) apply to the issue upstream's credential file. `public_repos` does not apply to the broker (the broker never goes anonymous).