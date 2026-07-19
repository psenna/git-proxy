---
name: use-git-proxy
description: Use when the agent needs to clone/fetch/push a git repository, manipulate pull requests and query CI status, or file/read/comment/close/label issues through a git-proxy instance. Covers Bearer auth, the git-protocol leg (clone/fetch/push with policy awareness and read protection), and the agent-facing broker REST API (PRs, CI status, and issues). Use it any time a remote URL points at a git-proxy or a task mentions pushing through / opening PRs or issues via git-proxy.
---

# Use git-proxy

git-proxy is a policy-enforcing gateway between you (the agent) and the upstream
Git repository. You never talk to GitHub/Gitea directly: you talk to the proxy,
it authenticates you with a Bearer token, enforces push/read policy, and forwards
to the upstream with **its own** held credentials. The upstream token is never
given to you (fail-closed, no-leak).

There are **two legs**. Use this skill whenever a remote URL or base URL points at
a git-proxy instance.

| Leg | What it's for | URL |
|---|---|---|
| **Git protocol** | `clone` / `fetch` / `push` (smart-HTTP) | the proxy `listen` address, e.g. `http://127.0.0.1:8080` |
| **Broker REST API** | PRs (create/get/list/merge, comment, review), CI status, and issues (create/get/list, comment, close, reopen, edit, labels) | the `broker.listen` address, e.g. `http://127.0.0.1:8090` |

## 0. Prerequisites — establish these first

Before any command, confirm you have three values. If any is missing, **ask the
operator** — do not guess and do not hard-code a token.

```sh
export GIT_PROXY_URL="http://127.0.0.1:8080"        # git-protocol leg
export GIT_PROXY_BROKER_URL="http://127.0.0.1:8090" # broker REST leg (may be unset if broker disabled)
export GIT_PROXY_TOKEN="agent-token-1"             # YOUR Bearer token (never the upstream's)
# Convenience: the git extra-header the git-protocol leg needs on every call.
export GIT_PROXY_HEADER="http.extraheader=Authorization: Bearer $GIT_PROXY_TOKEN"
```

**Token hygiene:** `GIT_PROXY_TOKEN` is *your* agent credential, scoped to the
proxy. Treat it as a secret — never echo it, never put it in a commit, never log
it. The proxy's upstream token is held by the proxy; you never see it and never
need it.

> If the proxy has **no** `auth.tokens` configured it runs as an open relay (no
> Bearer required) — but that is a misconfiguration for a security gateway. If you
> hit a 401, your token is wrong/missing; if you hit a 403, you are authenticated
> but not on the allowlist for that op.

## 1. Leg one — git protocol (clone / fetch / push)

Point `git` at the proxy by using the proxy URL as the remote and passing your
Bearer via an extra header. The proxy forwards to the upstream with its own
Basic/Bearer creds; you stay authenticated as yourself.

### Clone

```sh
git -c "$GIT_PROXY_HEADER" clone "$GIT_PROXY_URL/<owner>/<repo>.git"
cd <repo>
git -c "$GIT_PROXY_HEADER" remote set-url origin "$GIT_PROXY_URL/<owner>/<repo>.git"
```

Every subsequent `fetch`/`pull`/`push` must also carry the header (the header is
not persisted by `remote set-url`). The `GIT_PROXY_HEADER` env var keeps it short:

```sh
git -c "$GIT_PROXY_HEADER" fetch origin
git -c "$GIT_PROXY_HEADER" push origin feat/my-branch
```

### Read-protected repos — always use a partial clone

If the repo is **read-protected** (`policy.read.deny`, typically `secrets/**`),
a *plain* clone is **rejected up front** with an actionable error rather than
handing you a broken packfile:

```
fatal: read-protected repository requires a partial clone; retry with --filter=blob:none
```

Use a partial clone — this is required, not optional:

```sh
git -c "$GIT_PROXY_HEADER" clone --filter=blob:none "$GIT_PROXY_URL/<owner>/<repo>.git"
```

If a `--filter=blob:none` checkout later aborts with `missing blob object`, that
is the on-demand deny refusing a denied-path blob — the denied blob is never sent.
Recover the non-secret files without fetching the denied one:

```sh
git restore --staged :/ && git checkout HEAD -- . ':!secrets'
```

### Push policy — expect some pushes to be rejected

The proxy enforces policy on `push`. Common denies are **by design** — the
upstream is left unchanged and the deny reason is returned via `report-status`:

- **Force-push to a protected ref** (`history_protect`):
  `! [remote rejected] main -> main (force-push to protected ref "refs/heads/main" is not allowed)`
- **Push to a branch that doesn't match the pattern** (`branch_pattern`, e.g. only
  `main` and `feat/*`): the ref is rejected.
- **Push containing a secret** (`secret_scan`): the matched value is **redacted**
  in the reason — `snippet: ***REDACTED***` — so the reason is safe to repeat.
- **Path-ACL / max-packfile violations**: similarly rejected with a generic reason.

When a push is rejected, read the reason, fix the offending change, and retry. Do
**not** attempt to circumvent policy (e.g. by rebasing to hide the secret) — the
deny is the correct outcome.

## 2. Leg two — broker REST API (PRs + CI + issues)

The broker is a separate HTTP server (separate port from the git leg). It lets you
manipulate PRs, query CI state, and work with issues **without** receiving the
upstream token: you send your agent Bearer, the proxy attaches its own token to the
proxy→upstream leg. Use it for any PR/CI/issue workflow instead of shelling out to
`gh`/`git` against the upstream directly.

> **Issues are opt-in.** The issue tracker is sourced from a separately-configured
> `issue_upstream` (distinct from the SCM upstream that backs PRs/CI). If the
> deployment did not configure one, every issue route returns **501** per-op while
> PR/CI routes keep working — see [Error responses](#error-responses). Auth still
> gates first (a missing/invalid Bearer is 401, not 501, so a 401 never leaks
> "issues are configured").

### Repo path encoding — important

The broker route for a repo is a **single path segment**, so the `/` in
`owner/repo.git` must be **URL-encoded as `%2F`**:

```
<repo>  =  owner/repo.git   →   owner%2Frepo.git
```

Every broker path below uses `owner%2Frepo.git`, not `owner/repo.git`. The
`{ref...}` on the checks route is a terminal wildcard and keeps its slashes
verbatim (no encoding needed for a SHA or branch with slashes).

### Health check (unauthenticated)

```sh
curl -s "$GIT_PROXY_BROKER_URL/healthz"   # {"status":"ok"}
```

### PR operations

```sh
REPO="owner%2Frepo.git"
AUTH="Authorization: Bearer $GIT_PROXY_TOKEN"

# Create a PR. Body: {head, base, title}. → 201 {"number":N,"url":"..."}
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/prs" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"head":"feat/my-branch","base":"main","title":"Add thing"}'

# List PRs (?state=open|closed|all, defaults to open). → 200 [PRState,...]
curl -s "$GIT_PROXY_BROKER_URL/$REPO/prs?state=open" -H "$AUTH"

# Get one PR. → 200 PRState{number,title,state,mergeable,head,base,url}
curl -s "$GIT_PROXY_BROKER_URL/$REPO/prs/7" -H "$AUTH"

# Merge a PR. → 204 on success. Method is optional; if omitted the proxy uses its
# configured default (broker.merge_method). Override with a body or ?method=.
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/prs/7/merge" -H "$AUTH" \
  -d '{"method":"squash"}'            # method: "merge" | "squash" | "rebase"
# or, no body:   curl -s -X POST ".../prs/7/merge?method=squash" -H "$AUTH"
# or, no body, no query: uses the proxy default.

# Comment on a PR. → 204. (Posted to the PR's issue thread.)
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/prs/7/comments" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"body":"lgtm"}'

# Review a PR. → 204. event: APPROVE | REQUEST_CHANGES | COMMENT
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/prs/7/reviews" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"event":"APPROVE","body":"ship it"}'
```

### CI status

```sh
# Query CI for a ref (SHA or branch; slashes preserved). → 200 CheckSummary
curl -s "$GIT_PROXY_BROKER_URL/$REPO/checks/$SHA_OR_BRANCH" -H "$AUTH"
# {"overall":"success","checks":[...],"workflows":[...]}
```

`overall` is one of: `"none"` (no CI configured for the ref) | `"pending"` (a run
is queued/in-progress or completed without a conclusion yet) | `"failure"` (at
least one run failed) | `"success"` (all completed passing) | `"unknown"` (a run
in a state the roll-up can't classify). Precedence is failure > pending > success
> unknown.

### Issue operations

Issue routes are served **only when the deployment configured an `issue_upstream`**.
The repo path is encoded the same way as PRs (`owner%2Frepo.git`).

```sh
REPO="owner%2Frepo.git"
AUTH="Authorization: Bearer $GIT_PROXY_TOKEN"

# Create an issue. Body: {title, body}. → 201 {"number":N,"url":"..."}
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"title":"Bug in checkout","body":"steps to reproduce..."}'

# List issues (?state=open|closed|all, defaults to open). → 200 [IssueState,...]
# Pull requests are filtered out (GitHub models every PR as an issue) — the list
# is issues only.
curl -s "$GIT_PROXY_BROKER_URL/$REPO/issues?state=open" -H "$AUTH"

# Get one issue. → 200 IssueState{number,title,state,body,url,labels}
curl -s "$GIT_PROXY_BROKER_URL/$REPO/issues/42" -H "$AUTH"

# Comment on an issue. → 204.
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues/42/comments" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"body":"Confirmed on main."}'

# Close / reopen an issue. → 204 each (no body).
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues/42/close"  -H "$AUTH"
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues/42/reopen" -H "$AUTH"

# Edit an issue's title and/or body. → 200 IssueState. An EMPTY title/body means
# "leave unchanged" — the field is omitted from the PATCH, so you do NOT blank a
# field by accident. Only send a field you intend to set.
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues/42/edit" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"title":"Better title"}'           # body left unchanged

# Add labels. → 200 ["label",...] (the resulting full label set).
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues/42/labels" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"labels":["bug","p1"]}'

# Remove a single label. → 204. The label name travels in the JSON body (the
# proxy URL-encodes it onto the upstream path), so spaces/emoji are fine.
curl -s -X POST "$GIT_PROXY_BROKER_URL/$REPO/issues/42/labels/remove" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"label":"needs review"}'
```

`IssueState.state` is `"open"` or `"closed"`. `labels` is a flat `["name",...]`.
The issue ops reuse the same sentinel→status map as PRs (see below): a 404 means
the issue number doesn't exist, a 422 means e.g. an unknown label, a 501 means
issues are not configured on this deployment.

### Interpreting `mergeable`

`PRState.mergeable` is a tri-state: `true`/`false`/`null`. GitHub returns `null`
while it computes mergeability; the broker surfaces that as `"unknown"`. **Do not
merge on `null`/unknown** — re-fetch after a moment, or check CI first.

### Error responses

Every error is a JSON body `{"error":"<generic reason>"}` with a status code.
Reasons are **generic class strings** — they never include the upstream response
body, a credential, or an OID. Map them as:

| Status | Meaning | What to do |
|---|---|---|
| 400 | bad request (e.g. malformed JSON body) | fix the request body |
| 401 | missing/invalid Bearer | check `GIT_PROXY_TOKEN` |
| 403 | not allowlisted (agent or op) | ask the operator to allowlist you/op |
| 404 | not found (PR/repo) | verify the repo/PR number |
| 409 | not mergeable (e.g. GitHub 409) | resolve conflicts, re-check `mergeable` |
| 422 | request unprocessable | fix the field values |
| 429 | rate limited (upstream `Retry-After` forwarded when present) | wait, then retry; honor `Retry-After` |
| 501 | op not implemented (upstream adapter doesn't support it) | the op isn't available on this upstream |
| 502 | upstream auth / upstream error | **proxy-side** problem; surface to the operator, don't retry blindly |

Note: `502 "upstream auth"` means the *proxy's* GitHub token is missing/invalid —
that is a proxy misconfiguration, **not** your token. Tell the operator.

### A merge gate may apply (deployment-dependent)

Some deployments enable a **gate-on-green** policy: a merge is refused when the
PR's CI is not green. If your merge returns a non-green reason, query
`/$REPO/checks/<head>` and ensure `overall` is `"success"` before retrying. This is
fail-closed: CI you cannot confirm green does not merge. (If the deployment has no
gate, merges are not CI-gated — this section does not apply.)

## 3. Quick reference

```sh
# Git leg (every fetch/push needs the header)
git -c "$GIT_PROXY_HEADER" clone [--filter=blob:none] "$GIT_PROXY_URL/<owner>/<repo>.git"
git -c "$GIT_PROXY_HEADER" push origin <branch>

# Broker leg (repo slash is %2F encoded; ref slashes are not)
AUTH="Authorization: Bearer $GIT_PROXY_TOKEN"; R="owner%2Frepo.git"
POST   $BROKER/$R/prs                          -d '{"head","base","title"}'      # 201
GET    $BROKER/$R/prs?state=open                                                 # 200
GET    $BROKER/$R/prs/N                                                          # 200
POST   $BROKER/$R/prs/N/merge      [-d '{"method":"squash"}']                   # 204
POST   $BROKER/$R/prs/N/comments   -d '{"body":"..."}'                          # 204
POST   $BROKER/$R/prs/N/reviews    -d '{"event":"APPROVE","body":"..."}'        # 204
GET    $BROKER/$R/checks/<ref>                                                   # 200
# Issues (opt-in: 501 per-op if no issue_upstream is configured)
POST   $BROKER/$R/issues                       -d '{"title","body"}'            # 201
GET    $BROKER/$R/issues?state=open                                              # 200 (PRs filtered out)
GET    $BROKER/$R/issues/N                                                       # 200
POST   $BROKER/$R/issues/N/comments  -d '{"body":"..."}'                        # 204
POST   $BROKER/$R/issues/N/close                                                 # 204
POST   $BROKER/$R/issues/N/reopen                                               # 204
POST   $BROKER/$R/issues/N/edit     [-d '{"title","body"}']  # empty=unchanged  # 200
POST   $BROKER/$R/issues/N/labels    -d '{"labels":[...]}'                      # 200
POST   $BROKER/$R/issues/N/labels/remove -d '{"label":"..."}'                   # 204
GET    $BROKER/healthz                                                           # 200 (no auth)
```

## 4. Installing / obtaining this skill

This skill ships in the **git-proxy repository** at
`agent/skills/use-git-proxy/SKILL.md`. It is not auto-loaded by your agent until
you place it on a skill search path. To make it available:

- **Project-local** (anyone working in a repo that uses this proxy):
  ```sh
  mkdir -p .claude/skills/use-git-proxy
  curl -fsSL <raw URL to>/agent/skills/use-git-proxy/SKILL.md \
    -o .claude/skills/use-git-proxy/SKILL.md
  ```
- **User-global** (available in every working directory):
  ```sh
  mkdir -p ~/.claude/skills/use-git-proxy
  curl -fsSL <raw URL to>/agent/skills/use-git-proxy/SKILL.md \
    -o ~/.claude/skills/use-git-proxy/SKILL.md
  ```

Replace `<raw URL to>` with the raw GitHub URL for this file in your git-proxy
fork/instance (e.g. `https://raw.githubusercontent.com/psenna/git-proxy/main/agent/skills/use-git-proxy/SKILL.md`,
or your GHES/Gitea raw equivalent). After placing it, the skill auto-loads when a
task matches its `description`.

## 5. Security model — what to rely on

- **You never receive the upstream token.** The proxy attaches its own GitHub
  creds on the proxy→upstream leg. Do not attempt to obtain or use the upstream
  token.
- **Your Bearer is consumed for auth only** — it is never forwarded to the
  upstream (the broker's PRSupport/IssueSupport methods take no token). Do not
  send your token anywhere except the `Authorization: Bearer` header to the proxy.
- **Deny reasons are no-leak.** Secret-scan reasons are redacted; broker error
  reasons are generic class strings. You may safely repeat them in logs/PRs.
- **Fail-closed.** Missing token → 401 (never anonymous); non-SCM upstream → the
  broker is disabled at startup; an unknown repo → fail-closed before any upstream
  call. If an op is unavailable, surface it — do not work around it.