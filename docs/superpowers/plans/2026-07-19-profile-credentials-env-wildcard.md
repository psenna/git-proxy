# Profile-based credentials with env override, wildcard fallback, and public-clone allowlist — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the design in `docs/superpowers/specs/2026-07-19-profile-credentials-env-wildcard-design.md` — a profile-based credential store (env-over-file secrets, uppercased env stems, per-org wildcard fallback, optional `description`), a `public_repos` allowlist in `config.yaml`, and a deny-by-default git leg (unconfigured repos → 403, `public_repos` grants read-only anonymous access) — without changing `port.Credentials`, `port.CredentialStore`, `plain`, `gitx`, or the broker.

**Architecture:** New `internal/credentials/repomatch` (repo-key matcher via `path.Match`), new `internal/credentials/profile` (the new `port.CredentialStore`), new `internal/access` (shared tri-state `Decide`), a `port.RepoMatcher` interface, a `public_repos` field in `config`, and a deny-check inserted into the http+ssh frontend handlers. `main.go` switches `credfile`→`profile`, builds the public-repos matcher, passes it to both frontends, and logs an aggregated wildcard warning.

**Tech Stack:** Go stdlib (`os`, `path`, `strings`, `regexp`), `gopkg.in/yaml.v3`, `golang.org/x/crypto/ssh` (existing). No new third-party deps.

## Global Constraints

Binding for every task (from CLAUDE.md, the spec, and the user's standing rules):

- **One issue per PR. TDD red→green→commit.** Every commit passes `go vet`, `golangci-lint`, `go build`, `go test ./... -race`, `govulncheck`. `main` is protected; Conventional Commits.
- **Commit messages end** `Co-Authored-By: Claude <noreply@anthropic.com>`; **PR bodies end** with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- **No-leak.** Deny reasons are fixed generic strings (`"repository not served by this proxy"`). Startup warnings name env-var **names** + profile `description`s, never secret values. The agent Bearer is never forwarded. Audit carries no credential content.
- **Fail-closed.** Missing secret → per-request deny (never anonymous-for-private). Unconfigured repo → 403. `public_repos` is **read-only** (push to a public-only repo → 403). The broker never goes anonymous; `public_repos` is git-leg-only.
- **Frozen surfaces.** `port.Credentials` and `port.CredentialStore` are **unchanged** (no `Anonymous` field). `internal/upstream/plain.applyCreds`, `internal/transport/http.applyUpstreamCreds`, `internal/gitx`, and `internal/broker` are **unchanged** — they already attach Basic only when `ok` and no-op on `!ok`; the tri-state is a deny-check inserted in the frontend handlers.
- **Core isolation.** `main.go` never references `port.PRSupport`/`port.IssueSupport`; `internal/gitproto`, `internal/transport/**`, top-level `internal/policy`, and `cmd/git-proxy` must not reference either capability identifier (existing `internal/port/prsupport_core_isolation_test.go` stays green). New packages (`repomatch`, `profile`, `access`) do not import those identifiers.
- **Standing rule — NEVER commit** `deploy/docker/credentials.yaml` (the user's real Gitea token lives there, uncommitted) or `deploy/docker/demo/` (the user's clone). Converting the demo credentials file to the new layout commits only the **placeholder template** (see Task 5).
- **Reference** the spec for full semantics; this plan does not duplicate it.

---

## File map

New:
- `internal/credentials/repomatch/repomatch.go` + `_test.go` — repo-key matcher (`path.Match`).
- `internal/credentials/profile/store.go` + `_test.go` — the new `port.CredentialStore`.
- `internal/access/access.go` + `_test.go` — shared tri-state `Decide`.

Modified:
- `internal/port/credentials.go` — add `RepoMatcher` interface (one method).
- `internal/transport/http/frontend.go` — `New` gains `publicRepos port.RepoMatcher`; deny-check in `handleInfoRefs`, `handleInfoRefsReadProtected`, `handleService`.
- `internal/transport/ssh/frontend.go` — `New` gains `creds port.CredentialStore` + `publicRepos port.RepoMatcher`; deny-check before the ref advertisement.
- `internal/config/config.go` — add `PublicRepos []string`.
- `cmd/git-proxy/main.go` — switch `credfile`→`profile`; build public-repos matcher from `cfg.PublicRepos`; pass `creds`+`publicRepos` to both frontends; log aggregated wildcard warning; build issue-upstream creds via `profile.New`.
- `example/github-claude-code/credentials.yaml` + `config.yaml` — new layout + `public_repos`.
- `deploy/docker/credentials.yaml` (template only) + `deploy/docker/README.md` + `docs/deploy-docker.md` — new layout + env-based token.
- `docs/extensibility.md`, `example/github-claude-code/README.md`, `agent/skills/use-git-proxy/SKILL.md` (+ resync the example's copy) — docs.
- Integration harnesses: `test/integration/harness.go`, `test/integration/harness_ssh.go`, and tests relying on anonymous passthrough — pass creds/publicRepos so test repos stay reachable.

Deleted:
- `internal/credentials/file/` (store.go + store_test.go) — removed in Task 5 once `main.go` no longer imports it.

---

## Task 1: `internal/credentials/repomatch` + `port.RepoMatcher` + `internal/access`

**Files:**
- Create: `internal/credentials/repomatch/repomatch.go`, `internal/credentials/repomatch/repomatch_test.go`
- Create: `internal/access/access.go`, `internal/access/access_test.go`
- Modify: `internal/port/credentials.go` (add `RepoMatcher`)

**Interfaces:**
- Produces: `repomatch.Matcher[V]` with `New[V](pairs []Pair[V]) (*Matcher[V], error)` and `Match(repo) (V, bool)`; `repomatch.Pair[V]{Pattern string, Value V}`; precedence exact > longest wildcard > earliest-declared; rejects bare `*`, `**`, `path.Match` syntax errors. Exposes `WildcardPatterns() []string`. Plus `repomatch.NewBoolMatcher(patterns []string) (port.RepoMatcher, error)` for the public-repos case.
- Produces: `port.RepoMatcher` interface `{ Match(repo string) bool }` in `internal/port/credentials.go`.
- Produces: `access.Decide(creds port.CredentialStore, public port.RepoMatcher, repo string, isWrite bool) access.Decision` where `Decision` is `DecisionAllow` / `DecisionDeny`.

- [ ] **Step 1: Write failing tests for repomatch.**

`internal/credentials/repomatch/repomatch_test.go` — table-driven:
- exact beats wildcard: pairs `[{ "a/b.git", 1 }, { "a/*", 2 }]`, `Match("a/b.git")` → `(1, true)`.
- longest wildcard wins: `[{ "a/*", 1 }, { "a/b/*.git", 2 }]`, `Match("a/b/x.git")` → `(2, true)`; `Match("a/c.git")` → `(1, true)`.
- earliest-declared tiebreak: same-length wildcards `[{ "a/x*", 1 }, { "a/y*", 2 }]` both could match `a/xyz.git` → first declared `(1, true)`.
- `*` one segment: `Match("a/b.git")` for pattern `a/*` → true; `Match("a/b/c.git")` for `a/*` → false; `Match("other/x.git")` for `a/*` → false.
- no-match → `(zero, false)`.
- `New` errors on: bare `*`, any pattern containing `**`, `path.Match` syntax error (unclosed `[`).
- `WildcardPatterns()` returns wildcard patterns (those containing `*`) in declaration order.
- `NewBoolMatcher(["public/*"])` returns a `port.RepoMatcher` whose `Match("public/r.git")` is true and `Match("other/r.git")` is false; errors on bare `*`/`**`/malformed.

- [ ] **Step 2: Run, verify fail.** `go test ./internal/credentials/repomatch/` → build failure (package missing).

- [ ] **Step 3: Implement `repomatch`.**

`repomatch.go`:
```go
package repomatch

import (
    "fmt"
    "path"
    "sort"

    "github.com/psenna/git-proxy/internal/port"
)

type Pair[V any] struct {
    Pattern string
    Value   V
}

type entry[V any] struct {
    pattern string
    wildcard bool
    order   int
    value   V
}

type Matcher[V any] struct {
    exact   map[string]V
    wildcards []entry[V] // sorted by precedence: longest pattern first, then order
}

func New[V any](pairs []Pair[V]) (*Matcher[V], error) {
    m := &Matcher[V]{exact: make(map[string]V)}
    for i, p := range pairs {
        if err := validate(p.Pattern); err != nil {
            return nil, fmt.Errorf("repomatch: pattern %q: %w", p.Pattern, err)
        }
        if isWildcard(p.Pattern) {
            m.wildcards = append(m.wildcards, entry[V]{pattern: p.Pattern, wildcard: true, order: i, value: p.Value})
        } else {
            m.exact[p.Pattern] = p.Value
        }
    }
    sort.SliceStable(m.wildcards, func(i, j int) bool {
        if len(m.wildcards[i].pattern) != len(m.wildcards[j].pattern) {
            return len(m.wildcards[i].pattern) > len(m.wildcards[j].pattern) // longest first
        }
        return m.wildcards[i].order < m.wildcards[j].order // earliest declared
    })
    return m, nil
}

func (m *Matcher[V]) Match(repo string) (V, bool) {
    var zero V
    if v, ok := m.exact[repo]; ok { return v, true }
    for _, e := range m.wildcards {
        if ok, _ := path.Match(e.pattern, repo); ok { return e.value, true }
    }
    return zero, false
}

func (m *Matcher[V]) WildcardPatterns() []string {
    out := make([]string, len(m.wildcards))
    for i, e := range m.wildcards { out[i] = e.pattern }
    return out
}

func isWildcard(p string) bool { return strings.Contains(p, "*") }

func validate(p string) error {
    if p == "" { return fmt.Errorf("empty pattern") }
    if p == "*" { return fmt.Errorf("bare * catch-all not allowed") }
    if strings.Contains(p, "**") { return fmt.Errorf("** not allowed (use single-segment *)") }
    if _, err := path.Match(p, ""); err != nil { return err } // syntax check
    return nil
}

// NewBoolMatcher builds a port.RepoMatcher (bool) from patterns.
func NewBoolMatcher(patterns []string) (port.RepoMatcher, error) {
    pairs := make([]Pair[struct{}], len(patterns))
    for i, p := range patterns { pairs[i] = Pair[struct{}]{Pattern: p} }
    m, err := New(pairs)
    if err != nil { return nil, err }
    return boolMatcher{m: m}, nil
}

type boolMatcher struct{ m *Matcher[struct{}] }
func (b boolMatcher) Match(repo string) bool { _, ok := b.m.Match(repo); return ok }
```
(Add `import "strings"`.)

- [ ] **Step 4: Add `port.RepoMatcher`.** In `internal/port/credentials.go`, append:
```go
// RepoMatcher tests whether a repository path matches an allowlist (e.g. the
// public_repos config). A nil RepoMatcher matches nothing.
type RepoMatcher interface {
    Match(repo string) bool
}
```

- [ ] **Step 5: Write failing tests for `access.Decide`.**

`internal/access/access_test.go` — table-driven with a fake `CredentialStore` and fake `RepoMatcher`:
- profiled (creds `ok=true`) → `DecisionAllow` (both read and write).
- no creds, read, public matches → `DecisionAllow`.
- no creds, write, public matches → `DecisionDeny` (push needs creds).
- no creds, read, public does NOT match → `DecisionDeny`.
- no creds, write, public does NOT match → `DecisionDeny`.
- nil creds + nil public → `DecisionDeny` (read and write).
- nil public but creds `ok` → `DecisionAllow`.

- [ ] **Step 6: Implement `access`.**

`internal/access/access.go`:
```go
package access

import "github.com/psenna/git-proxy/internal/port"

type Decision int
const (
    DecisionAllow Decision = iota
    DecisionDeny
)

// Decide is the shared tri-state for the git leg. Allow means "proceed; the
// upstream path attaches Basic iff CredentialsFor returns ok" (so a profiled
// repo is credentialed and an anonymous-read repo attaches nothing). Deny
// means respond 403 and do not reach upstream. isWrite is true for receive-pack
// (push); pushes always require a credential, even for public_repos repos.
func Decide(creds port.CredentialStore, public port.RepoMatcher, repo string, isWrite bool) Decision {
    if creds != nil {
        if _, ok := creds.CredentialsFor(repo); ok {
            return DecisionAllow
        }
    }
    if isWrite {
        return DecisionDeny
    }
    if public != nil && public.Match(repo) {
        return DecisionAllow
    }
    return DecisionDeny
}
```

- [ ] **Step 7: Run all, verify pass.** `go vet ./internal/credentials/repomatch/... ./internal/access/... && golangci-lint run ./internal/credentials/repomatch/... ./internal/access/... && go test -race ./internal/credentials/repomatch/... ./internal/access/...`. (No consumer yet — exported APIs, so no unused warnings.)

- [ ] **Step 8: Commit.** `feat(credentials): add repomatch matcher, port.RepoMatcher, and access tri-state helper`

---

## Task 2: `internal/credentials/profile` (the new credential store)

**Files:**
- Create: `internal/credentials/profile/store.go`, `internal/credentials/profile/store_test.go`

**Interfaces:**
- Consumes: `repomatch.Matcher[V]`, `port.Credentials`, `port.CredentialStore`.
- Produces: `profile.New(path string) (*Store, error)`; `Store.CredentialsFor(repo) (port.Credentials, bool)`; `Store.WildcardPatterns() []profileWildcard` (pattern + name + description, for the aggregated warning). Resolves env > file > empty, uppercasing `name`. Startup: fatal on structural errors, log warnings on non-functional creds / one-legged profiles.

- [ ] **Step 1: Write failing tests for the profile store.**

`store_test.go` — table-driven + a temp-file helper:
- **Field resolution**: profile `{name: "company_abc", password: "lit-pass", token: "lit-tok"}` with env `COMPANY_ABC_TOKEN=set-tok` set → `CredentialsFor` returns token `set-tok` (env wins), password `lit-pass` (env unset). Env `COMPANY_ABC_PASSWORD=p` set → password `p`. Env set to empty string → falls back to file. Both env+file unset → empty.
- **Uppercasing**: `{name: "company_abc"}` reads `COMPANY_ABC_TOKEN` (assert a test that sets `company_abc_TOKEN` does NOT get read; setting `COMPANY_ABC_TOKEN` does).
- **Matching**: profiles `[{name: A, repos: ["mycompany/repo1.git"]}, {name: B, repos: ["mycompany/*"]}]`; `CredentialsFor("mycompany/repo1.git")` → A's creds (exact wins); `CredentialsFor("mycompany/repo2.git")` → B's creds (wildcard); `CredentialsFor("other/x.git")` → `(zero, false)`.
- **Tri-state out of the store**: profiled-with-secret → `(creds, true)`; secretless profile (both empty) → `(zero, false)`; no profile → `(zero, false)`.
- **Startup fatal** (each returns an error from `New`): bad `name` (empty, invalid chars `^[A-Za-z_][A-Za-z0-9_]*$`), dup `name` case-insensitive (`company_abc` and `COMPANY_ABC`), empty `repos`, malformed pattern, bare `*`, `**`, dup exact repo across profiles, dup wildcard across profiles.
- **Startup non-fatal** (`New` returns nil error, warning logged): profile with no secret → warning text contains `COMPANY_ABC_PASSWORD`/`COMPANY_ABC_TOKEN` (uppercased) and the `description`, never any value. One-legged profile (token set, password empty) → info line. Capture logs via `log.SetOutput` on a `bytes.Buffer` (or a test hook) and assert.
- **`WildcardPatterns()`** returns each wildcard with its profile `name` + `description`.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement the profile store.**

`store.go`:
```go
package profile

import (
    "fmt"
    "log"
    "os"
    "regexp"
    "strings"

    "gopkg.in/yaml.v3"

    "github.com/psenna/git-proxy/internal/credentials/repomatch"
    "github.com/psenna/git-proxy/internal/port"
)

type rawProfile struct {
    Name        string   `yaml:"name"`
    Description string   `yaml:"description"`
    Username    string   `yaml:"username"`
    Password    string   `yaml:"password"`
    Token       string   `yaml:"token"`
    Repos       []string `yaml:"repos"`
}

type vaultFile struct {
    Credentials []rawProfile `yaml:"credentials"`
}

type profileWildcard struct {
    Pattern     string
    Name        string
    Description string
}

type Store struct {
    matcher *repomatch.Matcher[*resolved]
    wildcards []profileWildcard
}

type resolved struct {
    creds port.Credentials
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func New(path string) (*Store, error) {
    s := &Store{}
    if path == "" { return s, nil } // no credentials file → empty store
    data, err := os.ReadFile(path)
    if err != nil { return nil, fmt.Errorf("profile: read %s: %w", path, err) }
    var vf vaultFile
    if err := yaml.Unmarshal(data, &vf); err != nil {
        return nil, fmt.Errorf("profile: parse %s: %w", path, err)
    }
    seenNames := make(map[string]bool)
    pairs := make([]repomatch.Pair[*resolved], 0)
    for _, rp := range vf.Credentials {
        if rp.Name == "" || !nameRe.MatchString(rp.Name) {
            return nil, fmt.Errorf("profile: invalid name %q (must match ^[A-Za-z_][A-Za-z0-9_]*$)", rp.Name)
        }
        up := strings.ToUpper(rp.Name)
        if seenNames[up] {
            return nil, fmt.Errorf("profile: duplicate name %q (case-insensitive)", rp.Name)
        }
        seenNames[up] = true
        if len(rp.Repos) == 0 {
            return nil, fmt.Errorf("profile %q: repos is empty", rp.Name)
        }
        c := port.Credentials{
            Username: envOr(up+"_USERNAME", rp.Username),
            Password: envOr(up+"_PASSWORD", rp.Password),
            Token:    envOr(up+"_TOKEN", rp.Token),
        }
        r := &resolved{creds: c}
        for _, pat := range rp.Repos {
            // repomatch.New validates each pattern (bare *, **, syntax); but it
            // validates the whole set at once — collect then build once below.
            pairs = append(pairs, repomatch.Pair[*resolved]{Pattern: pat, Value: r})
            if strings.Contains(pat, "*") {
                s.wildcards = append(s.wildcards, profileWildcard{Pattern: pat, Name: rp.Name, Description: rp.Description})
            }
        }
        // non-functional / one-legged warnings
        switch {
        case c.Password == "" && c.Token == "":
            log.Printf("profile %q (%s) has no usable credential; set %s_PASSWORD/%s_TOKEN (or a file value); repos under it will not be credentialed",
                rp.Name, rp.Description, up, up)
        case c.Password == "" :
            log.Printf("profile %q (%s) has token but no password — broker-only; git-HTTP clone will not be credentialed", rp.Name, rp.Description)
        case c.Token == "":
            log.Printf("profile %q (%s) has password but no token — git-only; broker ops will not be credentialed", rp.Name, rp.Description)
        }
    }
    m, err := repomatch.New(pairs) // also enforces dup-exact / dup-wildcard across profiles + per-pattern syntax
    if err != nil { return nil, err }
    s.matcher = m
    return s, nil
}

// envOr returns the env var (non-empty) or the file fallback.
func envOr(name, fallback string) string {
    if v, ok := os.LookupEnv(name); ok && v != "" {
        return v
    }
    return fallback
}

func (s *Store) CredentialsFor(repo string) (port.Credentials, bool) {
    if s.matcher == nil { return port.Credentials{}, false }
    r, ok := s.matcher.Match(repo)
    if !ok { return port.Credentials{}, false }
    if r.creds.Password == "" && r.creds.Token == "" {
        return port.Credentials{}, false // secretless profile → no creds (deny falls through to public_repos)
    }
    return r.creds, true
}

func (s *Store) WildcardPatterns() []profileWildcard { return s.wildcards }
```

Note: `repomatch.New` rejects duplicate exact repos and duplicate wildcard patterns across all pairs (add that check to `repomatch.New` if not present — Task 1's `New` should error when the same exact pattern or same wildcard pattern appears twice; add a `seen` map in `New`). Update Task 1's `New` to detect dup exact keys and dup wildcard patterns and return an error.

- [ ] **Step 4: Run, verify pass.** `go vet ./internal/credentials/profile/... && golangci-lint run ./internal/credentials/profile/... && go test -race ./internal/credentials/profile/...`.

- [ ] **Step 5: Commit.** `feat(credentials): add profile credential store with env override and wildcard repos`

---

## Task 3: HTTP frontend tri-state (deny-by-default)

**Files:**
- Modify: `internal/transport/http/frontend.go` (`New` signature + deny-checks)
- Modify: `cmd/git-proxy/main.go:110` (pass `nil` publicRepos for now)
- Modify: `test/integration/harness.go` (Start, StartWithAuth, StartWithPolicy pass creds/publicRepos)
- Modify: any `test/integration/*_test.go` relying on anonymous passthrough

**Interfaces:**
- Consumes: `access.Decide`, `port.RepoMatcher` (new `publicRepos` field + `creds` already present).
- Produces: `httpfront.New(ln, up, upstreamURL, repos, auth, creds, publicRepos port.RepoMatcher) *Frontend`.

- [ ] **Step 1: Write failing test for the deny-by-default.**

Add to `internal/transport/http/frontend_test.go` (or `test/integration`): boot a frontend with a cred store that has NO entry for `other/x.git` and `publicRepos=nil`; an authenticated `GET /other/x.git/info/refs?service=git-upload-pack` → **403** with body `repository not served by this proxy`, and the upstream `httptest.Server` is **never** hit (wrap its handler to fail the test if called). Then with `publicRepos` matching `other/*` → the upstream IS hit and no `Authorization` header is sent (anonymous read). Then with `publicRepos` matching but a `git-receive-pack` POST → 403 (push needs creds), upstream not hit.

- [ ] **Step 2: Run, verify fail.** (Constructor signature mismatch / no deny.)

- [ ] **Step 3: Implement the deny-check in the HTTP frontend.**

`frontend.go`: add `publicRepos port.RepoMatcher` to the `Frontend` struct and `New`. Insert a deny-check at the top of `handleInfoRefs`, `handleInfoRefsReadProtected`, and `handleService`:
```go
isWrite := r.URL.Query().Get("service") == "git-receive-pack" // for info/refs
if access.Decide(f.creds, f.publicRepos, repo, isWrite) == access.DecisionDeny {
    f.denyRepo(w, r)
    return
}
```
For `handleService`, `isWrite = service == "git-receive-pack"`. For `handleInfoRefsReadProtected` (always upload-pack) `isWrite = false`. Add:
```go
func (f *Frontend) denyRepo(w http.ResponseWriter, r *http.Request) {
    // Fixed generic reason — no repo path, no OID, no credential (no-leak).
    http.Error(w, `{"error":"repository not served by this proxy"}`, http.StatusForbidden)
}
```
(Keep the existing `applyUpstreamCreds`/proxy flow after the check; on Allow, an anonymous-read repo has `ok=false` so `applyUpstreamCreds` no-ops — unchanged.) Ensure the deny happens **after** `authenticate` (401 before 403 — no leak to unauthenticated callers): the handlers run after `authenticate` already returned the agent in `serveHTTP`, so ordering is correct; verify in the test that an unauthenticated request gets 401, not 403.

- [ ] **Step 4: Update `main.go:110`** to pass `nil` as the new `publicRepos` arg (real wiring in Task 5): `httpfront.New(ln, up, cfg.Upstream.URL, cfg.Repos, auth, creds, nil)`.

- [ ] **Step 5: Update the HTTP integration harnesses** so test repos stay reachable under deny-by-default:
  - `harness.go:123` (Start / passthrough): build `publicRepos port.RepoMatcher` = `repomatch.NewBoolMatcher([]string{repo})` and pass it (anonymous read). If the passthrough suite also **pushes**, give it a dummy cred store for the repo instead (so writes are allowed) — audit `test/integration/passthrough_*_test.go` and choose per test; default to a cred store if any test pushes.
  - `harness.go:184` (StartWithAuth): already passes `store` (creds) → repo is profiled → Allow. Add `nil` publicRepos arg (no change to reachability).
  - `harness.go:297` (StartWithPolicy): currently `nil` creds. Push-policy tests push through the proxy; with deny-by-default a no-cred push → 403 and never reaches the enforcement engine. Pass a **dummy cred store** for the repo (e.g. a `port.CredentialStore` fake returning a throwaway `Credentials` for the test repo) so pushes are Allowed and reach enforcement. Add `nil`/`publicRepos` as appropriate.
  - Audit every `test/integration/*_test.go` that clones/pushes a repo not covered by creds: give it creds or a publicRepos entry. Search: `grep -rn "git-upload-pack\|git-receive-pack\|info/refs\|clone" test/integration/*_test.go`.

- [ ] **Step 6: Run full suite, verify pass.** `go vet ./... && golangci-lint run ./... && go build ./... && go test -race ./... && govulncheck ./...`.

- [ ] **Step 7: Commit.** `feat(transport): deny unconfigured repos on the HTTP git leg (public_repos allowlist)`

---

## Task 4: SSH frontend tri-state

**Files:**
- Modify: `internal/transport/ssh/frontend.go` (`New` gains `creds port.CredentialStore` + `publicRepos port.RepoMatcher`; deny-check before ref advertisement)
- Modify: `cmd/git-proxy/main.go:246` (pass `creds, nil`)
- Modify: `test/integration/harness_ssh.go:125` (+ ssh tests)

**Interfaces:**
- Produces: `sshfront.New(ln, up, repos, authn, hostKeyPath, creds port.CredentialStore, publicRepos port.RepoMatcher) (*Frontend, error)`.

- [ ] **Step 1: Write failing test.** Boot the SSH frontend with `creds=nil`, `publicRepos=nil`; an authenticated `git-upload-pack` of an unconfigured repo → the session is rejected with an ERR pkt-line / non-zero exit and the upstream is not contacted. With `publicRepos` matching → read succeeds (anonymous). A `git-receive-pack` with `publicRepos` matching but no creds → rejected (push needs creds).

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement.** Add `creds port.CredentialStore` and `publicRepos port.RepoMatcher` fields + `New` params. In the session handler, after parsing the requested service (`git-upload-pack` vs `git-receive-pack` from the exec command) and resolving the repo, call:
```go
isWrite := service == "git-receive-pack"
if access.Decide(f.creds, f.publicRepos, repo, isWrite) == access.DecisionDeny {
    // write an ERR pkt-line and exit non-zero; do not fetch the advertisement
    // or hand to f.proxy. (no-leak: generic reason)
    ...
    return
}
```
Proceed to the existing ref-advertisement + `f.proxy` flow on Allow (the proxy attaches creds via `up` iff `up.creds.CredentialsFor(repo)` ok; for an anonymous-read repo `up.creds` returns false → no attach — unchanged). Note: `up` (built in main.go with `CredentialsStore: creds`) already carries the same `creds`, so the attach path is consistent with the decide path.

- [ ] **Step 4: Update `main.go:246`** → `sshfront.New(sshLn, up, cfg.Repos, sshAuthn, cfg.SSH.HostKey, creds, nil)`.

- [ ] **Step 5: Update `harness_ssh.go:125`** to pass a cred store or publicRepos so the SSH test repo is reachable (mirror the HTTP harness choices; SSH push tests need a cred store).

- [ ] **Step 6: Run full suite.** `go vet ./... && golangci-lint run ./... && go build ./... && go test -race ./... && govulncheck ./...`.

- [ ] **Step 7: Commit.** `feat(transport): deny unconfigured repos on the SSH git leg`

---

## Task 5: `config.PublicRepos` + `main.go` wiring + delete `file` + example files

**Files:**
- Modify: `internal/config/config.go` (+ `_test.go`) — `PublicRepos []string`
- Modify: `cmd/git-proxy/main.go` — switch `credfile`→`profile`; build publicRepos matcher; pass to frontends; aggregated wildcard warning; issue-upstream creds via `profile.New`
- Delete: `internal/credentials/file/` (store.go + store_test.go)
- Modify: `example/github-claude-code/credentials.yaml`, `example/github-claude-code/config.yaml`
- Modify: `deploy/docker/credentials.yaml` (TEMPLATE only — see standing rule), `deploy/docker/config.yaml`, `deploy/docker/README.md`, `docs/deploy-docker.md`
- Modify: integration test credential fixtures (any `credentials.yaml` written by tests) → new layout

- [ ] **Step 1: Write failing test for `config.PublicRepos`.** `internal/config/config_test.go`: a YAML with `public_repos: ["public/*", "org/r.git"]` parses into `cfg.PublicRepos` with those values; absent → `nil`.

- [ ] **Step 2: Implement.** In `internal/config/config.go`, add `PublicRepos []string \`yaml:"public_repos"\`` to the top-level `Config` struct. No `Validate` change (patterns are validated by the matcher builder in main.go).

- [ ] **Step 3: Switch `main.go` to `profile` and wire publicRepos.**
  - Change import `credfile "github.com/psenna/git-proxy/internal/credentials/file"` → `credprofile "github.com/psenna/git-proxy/internal/credentials/profile"` and `repomatch "github.com/psenna/git-proxy/internal/credentials/repomatch"`.
  - Replace `credfile.New(cfg.Upstream.CredentialsFile)` with `credprofile.New(cfg.Upstream.CredentialsFile)`.
  - Replace `credfile.New(cfg.IssueUpstream.CredentialsFile)` (line ~299) with `credprofile.New(...)`.
  - Build the public-repos matcher once:
    ```go
    var publicRepos port.RepoMatcher
    if len(cfg.PublicRepos) > 0 {
        m, err := repomatch.NewBoolMatcher(cfg.PublicRepos)
        if err != nil {
            return fmt.Errorf("public_repos: %w", err)
        }
        publicRepos = m
    }
    ```
  - Pass `publicRepos` to `httpfront.New(...)` (replacing the `nil` from Task 3) and `creds, publicRepos` to `sshfront.New(...)` (replacing Task 4's `nil`).
  - Aggregated wildcard warning (after building the profile stores + the publicRepos matcher):
    ```go
    var ww []string
    for _, w := range credProfileStore.WildcardPatterns() {
        ww = append(ww, fmt.Sprintf("%q (%s — %s)", w.Pattern, w.Name, w.Description))
    }
    if len(cfg.PublicRepos) > 0 {
        // list public_repos wildcards (the ones containing *)
        for _, p := range cfg.PublicRepos {
            if strings.Contains(p, "*") { ww = append(ww, fmt.Sprintf("%q (public_repos)", p)) }
        }
    }
    if len(ww) > 0 {
        log.Printf("git-proxy: WARNING: wildcard repo matchers configured — %s — matching repos receive that profile's PAT (or anonymous read for public_repos); verify least-privilege", strings.Join(ww, ", "))
    }
    ```
    (Reuse the SCM profile store's `WildcardPatterns()`; if the issue-upstream store also has wildcards, include them too — same loop.)

- [ ] **Step 4: Delete `internal/credentials/file/`.** `git rm internal/credentials/file/store.go internal/credentials/file/store_test.go`. Confirm `grep -rn "credentials/file" --include=*.go .` returns nothing (all references were `main.go`, now switched).

- [ ] **Step 5: Convert example credentials files.**
  - `example/github-claude-code/credentials.yaml` → new list layout with a placeholder profile (e.g. `name: GITHUB`, `username: x-access-token`, `password: ghp_yourPAT`, `token: ghp_yourPAT`, `repos: ["<OWNER>/<REPO>.git"]`). Document env override (`GITHUB_PASSWORD`/`GITHUB_TOKEN`) in the README.
  - `example/github-claude-code/config.yaml` → add a `public_repos:` block (commented example; the agent's repo is profiled so it isn't needed, but show the knob).

- [ ] **Step 6: Convert the deploy/docker credentials TEMPLATE (standing-rule care).**
  - `deploy/docker/credentials.yaml` currently has the user's **real Gitea token** in the working copy (uncommitted, `M`). **NEVER commit that token.** Convert only the committed **placeholder** template: `git show HEAD:deploy/docker/credentials.yaml` to see the placeholder (`REPLACE_WITH_GITEA_ACCESS_TOKEN`), write the new-list-layout placeholder to a temp file, and stage that content WITHOUT the working-copy token (e.g. `git update-index --cacheinfo` the converted placeholder, or `git stash push -- deploy/docker/credentials.yaml`, edit the placeholder, commit, then re-apply the token locally in the new layout). The committed result must contain only `REPLACE_WITH_GITEA_ACCESS_TOKEN`, not a real token. The user re-applies their real token to the new layout locally afterward (document the new sed/env step in the README).
  - `deploy/docker/config.yaml` → no `public_repos` needed (the demo repo `demo/demo.git` is profiled). Optionally add a commented `public_repos:` example.
  - Update `deploy/docker/README.md` + `docs/deploy-docker.md`: the `sed -i "s/REPLACE_WITH_GITEA_ACCESS_TOKEN/$TOKEN/" credentials.yaml` step becomes setting `GITEA_PASSWORD`/`GITEA_TOKEN` env in `docker-compose.yml` (env overrides the file), OR a sed that fills the new-layout placeholder. Keep the demo's profiled repo (deny-by-default does not affect it).

- [ ] **Step 7: Convert integration test credential fixtures.** Find any test that writes a `credentials.yaml` (the `StartWithAuth` vault writer in `harness.go`) and update it to the new list layout so `profile.New` parses it. `grep -rn "credentials:" test/integration/`.

- [ ] **Step 8: Run full suite + a smoke.** `go vet ./... && golangci-lint run ./... && go build ./... && go test -race ./... && govulncheck ./...`. Smoke: run the proxy with a new-layout `credentials.yaml` + `public_repos`; confirm a profiled repo clones, an unconfigured repo 401s/403s, and a `public_repos` repo clones anonymously.

- [ ] **Step 9: Commit.** `feat(config): wire public_repos allowlist and profile credential store; drop file store`

---

## Task 6: Docs

**Files:**
- Modify: `docs/extensibility.md` (credential-store section + `public_repos` + `port.RepoMatcher`)
- Modify: `example/github-claude-code/README.md` ("Fill in your secrets" → env override), `deploy/docker/README.md`
- Modify: `agent/skills/use-git-proxy/SKILL.md` (operator-facing credential notes: profiles, env, `public_repos`, deny-by-default)
- Resync: `example/github-claude-code/claude-code/use-git-proxy/SKILL.md` (verbatim copy of the source skill — the README mandates it stays in sync)

- [ ] **Step 1: Update `docs/extensibility.md`.** Rewrite the "Credential store" row + section: new `internal/credentials/profile` package, list layout, env-over-file with uppercasing, `description`, per-org wildcards (no `*`/`**`), startup validation (fatal structural vs warning non-functional), `public_repos` in `config.yaml` + `port.RepoMatcher`, deny-by-default tri-state via `internal/access`, and the frozen-surface note (`port.Credentials`/`CredentialStore` unchanged). Mention `internal/credentials/repomatch` as the shared repo-key matcher (distinct from `internal/pathmatch`, which is for in-repo file paths).

- [ ] **Step 2: Update READMEs + skill.** `example/github-claude-code/README.md`: env-based secret (`GITHUB_PASSWORD`/`GITHUB_TOKEN` override the file; `.env`/compose sets them), the `public_repos` knob, and that unconfigured repos now 403. `deploy/docker/README.md` + `docs/deploy-docker.md`: env-based Gitea token. `agent/skills/use-git-proxy/SKILL.md`: an operator-facing note that credentials are profiles (env-over-file, per-org wildcards) and that the proxy denies unconfigured repos (use `public_repos` for anonymous read). Resync the example's `claude-code/use-git-proxy/SKILL.md` copy.

- [ ] **Step 3: Commit.** `docs: profile credentials, public_repos allowlist, and deny-by-default`

---

## Verification (whole branch)

- `go vet ./...`, `golangci-lint run ./...`, `go build ./...`, `go test -race ./...`, `govulncheck ./...` all green on every commit; `internal/port/prsupport_core_isolation_test.go` green (no new `PRSupport`/`IssueSupport` references).
- Manual end-to-end (Task 5 smoke): profiled repo clones/pushes; unconfigured repo → 403 (and upstream not contacted); `public_repos` repo → anonymous clone, anonymous push → 403; env var overrides file literal; `name: company_abc` reads `COMPANY_ABC_TOKEN`; a bare `*` or `**` in `public_repos` or a profile → proxy refuses to start; a secretless profile → proxy starts with a warning naming the uppercased env vars + description; any wildcard → aggregated startup warning.
- No-leak canary: `grep -E 'ghp_|x-access-token|<token>' data/audit/audit.jsonl` → nothing; deny-403 body is the fixed generic string; unauthenticated request → 401 (not 403).
- Standing rule honored: `deploy/docker/credentials.yaml` committed content is the placeholder only (no real Gitea token); `deploy/docker/demo/` untouched.

## Sequencing

Tasks 1→2→3→4→5→6, one PR each (Task 1 and 2 may open in parallel after Task 1 lands; Task 2 depends on Task 1; Task 3 depends on Task 1; Task 4 on Tasks 1+3's `access`; Task 5 on 1–4; Task 6 on 5). Each task is independently mergeable and green on the CI gates.

## Risks / notes

- **Deny-by-default breaks any test relying on anonymous passthrough** — the largest migration surface (Task 3/4 harness updates). The fix is always: give the test repo a credential profile (for read+write) or a `public_repos` entry (read-only). Push-policy tests MUST get a cred store, else pushes 403 before reaching the enforcement engine.
- **`deploy/docker/credentials.yaml` carries the user's real Gitea token** (uncommitted). Task 5 converts only the placeholder template; the user re-applies the token locally. Do not `git add` the working-copy token.
- **`port.Credentials` stays frozen** by design — the deny/anonymous decision is the frontend's via `access.Decide` + the public-repos matcher, not a credential-store flag. If a later need requires the store to signal "anonymous allowed," revisit then.
- **`repomatch` vs `pathmatch`** — deliberately separate: `pathmatch` is gitignore file-path matching (in-repo paths like `secrets/**`); `repomatch` is repo-key matching via stdlib `path.Match` (`*` = one segment). Different domains, different semantics.