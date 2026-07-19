---
layout: default
title: Docker Compose + Gitea
---

# Docker Compose + Gitea

The fastest way to see git-proxy enforce policy is to run it in front of a
**local self-hosted Gitea git server** with Docker Compose. No external account
or cloud repository is required — everything runs on localhost, and you can
watch git-proxy block force-pushes, deny secret-bearing pushes, and withhold
read-protected blobs while recording an attributable audit log.

The copy-paste quickstart lives in
[`deploy/docker/README.md`](https://github.com/psenna/git-proxy/tree/main/deploy/docker/README.md);
this page is the narrative version: the topology, why each piece exists, the
step-by-step enforcement walkthrough, and production hardening.

## Topology

```
                Bearer token                       Basic auth (proxy-held)
agent  ───────────────────────►  git-proxy  ───────────────────────────►  Gitea
       clone / fetch / push          │                                       bare git
       (smart-HTTP, :8080)           │                                       (smart-HTTP,
                                       │                                        :3000 on the
                            policy engine +                                compose network)
                            inspection mirror
                            (git CLI, :8080)
```

- **Gitea** (`gitea/gitea:1`) is the upstream: a real git server that speaks
  smart-HTTP at `http://gitea:3000/<owner>/<repo>.git`. It is the thing being
  protected.
- **git-proxy** sits in front. The agent never talks to Gitea directly. The
  proxy authenticates the agent (Bearer token), enforces policy against the
  push/fetch, and only then forwards to Gitea — attaching the **Gitea access
  token as Basic auth** on the proxy→Gitea leg. The agent never sees that token.

The two containers share a private bridge network (`gitnet`); only the proxy
(`:8080`) and Gitea's web UI (`:3000`, for one-time setup) are published to the
host.

> **This stack is git-protocol-only.** It runs `upstream.kind: plain` with no
> `broker.listen`, so it exercises clone/fetch/push enforcement but not the
> agent-facing broker (PRs, CI, issues). The broker requires an SCM adapter
> (`port.PRSupport`); the PR + CI + **issue** surface lives in
> [`example/github-claude-code/`](https://github.com/psenna/git-proxy/tree/main/example/github-claude-code),
> which sets `upstream.kind: github` and `issue_upstream.kind: github`. Issues are
> opt-in: the issue tracker comes from a separately-configured `issue_upstream`,
> and without it the broker's `/issues` routes return 501 per-op while PR/CI routes
> keep working.

## Prerequisites

- Docker Engine with the `docker compose` plugin.
- `git` and `curl` on the host.

## The files

Everything lives under [`deploy/docker/`](https://github.com/psenna/git-proxy/tree/main/deploy/docker):

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | The two services + `gitnet` network + volumes. |
| `config.yaml` | The proxy config: upstream = Gitea, one Bearer token, the full v1 policy. |
| `credentials.yaml` | Per-repo Basic-auth creds the proxy attaches to Gitea. You fill in the Gitea token. |
| `Dockerfile` (repo root) | Multi-stage build; runtime is Alpine + `git` + `ca-certificates`, non-root. |
| `.dockerignore` (repo root) | Keeps build context lean. |

The runtime image must contain the `git` binary: the inspection mirror is a real
bare clone driven by the git CLI (`internal/gitx` shells out via
`exec.CommandContext`), not a pure Go library. A distroless/scratch image would
break push enforcement.

## 1. Bring the stack up

```sh
cd deploy/docker
mkdir -p data/mirror data/audit          # bind-mounted, writable by the proxy (uid 1000)
docker compose up -d --build
```

Gitea's web UI is on `http://localhost:3000`; git-proxy listens on
`http://127.0.0.1:8080`. Wait for Gitea to be healthy:

```sh
docker compose exec gitea wget -qO- http://localhost:3000/api/v1/version
```

> **Linux permission note:** git-proxy runs as uid 1000. If your host user is
> not uid 1000 and the container cannot write to `data/`, fix ownership once:
> `sudo chown -R 1000:1000 data`. Docker Desktop (macOS/Windows) handles this
> transparently.

## 2. One-time Gitea setup

Gitea ships locked down (`INSTALL_LOCK=true`), so you provision an admin user,
a repo, and a token yourself. The scripted path:

```sh
# admin user "demo" (run as the Gitea runtime uid 1000 — Gitea refuses root)
docker compose exec --user 1000:1000 gitea gitea admin user create \
  --username demo --password demopass --email demo@example.com \
  --admin --must-change-password=false

# repo demo/demo.git, auto-initialized on branch "main"
curl -s -u demo:demopass -X POST http://localhost:3000/api/v1/user/repos \
  -H "Content-Type: application/json" \
  -d '{"name":"demo","auto_init":true,"default_branch":"main"}'

# access token for the proxy -> Gitea leg (the token is the "sha1" field)
curl -s -u demo:demopass -X POST http://localhost:3000/api/v1/users/demo/tokens \
  -H "Content-Type: application/json" \
  -d '{"name":"git-proxy","scopes":["read:repository","write:repository"]}'
```

Put the `sha1` value into `credentials.yaml` and restart the proxy so it
re-reads the credentials. The file uses the profile layout (a list under
`credentials:`); fill the `REPLACE_WITH_GITEA_ACCESS_TOKEN` placeholder, or inject
the token via the `GITEA_PASSWORD` (or `GITEA_TOKEN`) env var in `docker-compose.yml`
(env overrides the file value, so the proxy picks it up without editing the file):

```sh
TOKEN="<paste the sha1 token here>"
sed -i "s/REPLACE_WITH_GITEA_ACCESS_TOKEN/$TOKEN/" credentials.yaml
docker compose restart git-proxy
```

> Prefer the env path? Set `GITEA_PASSWORD` in `docker-compose.yml` (or `.env`)
> and leave `credentials.yaml` untouched — env > file > empty.

> Prefer the web UI? Open `http://localhost:3000`, log in as `demo`/`demopass`,
> create the repo, then create a personal access token under Settings →
> Applications (with repository read/write scopes), and paste it into
> `credentials.yaml`.

## 3. Use git through the proxy

The agent authenticates to the proxy with a Bearer token; the proxy holds the
Gitea token. A small helper avoids typing the header every time:

```sh
export GIT_PROXY_HEADER='http.extraheader=Authorization: Bearer agent-token-1'
PROXY="http://127.0.0.1:8080"
```

Clone (the proxy forwards to Gitea with Basic auth from `credentials.yaml`):

```sh
git -c "$GIT_PROXY_HEADER" clone $PROXY/demo/demo.git
cd demo
git -c "$GIT_PROXY_HEADER" remote set-url origin $PROXY/demo/demo.git
```

> **Read-protected repos:** once any file under `secrets/**` exists in the
> repo (see the read-protection walkthrough below), a **plain** clone like the
> one above is rejected by the proxy with an actionable error pointing you at
> `--filter=blob:none` — the proxy withholds the denied blobs and a plain clone
> cannot tolerate the resulting missing objects. Use
> `git -c "$GIT_PROXY_HEADER" clone --filter=blob:none $PROXY/demo/demo.git`
> for read-protected repos. The plain clone works until a `secrets/**` file is
> pushed.

### A clean push to `feat/*` is forwarded

`branch_pattern` allows `refs/heads/main` and `refs/heads/feat/*`, so a new
feature branch is forwarded to Gitea:

```sh
git checkout -b feat/smoke
echo "hello" > file.txt && git add . && git commit -m "add file"
git -c "$GIT_PROXY_HEADER" push origin feat/smoke
# Gitea now has refs/heads/feat/smoke:
docker compose exec --user 1000:1000 gitea git \
  -C /data/git/repositories/demo/demo.git rev-parse refs/heads/feat/smoke
```

### A force-push to `main` is blocked

`history_protect` blocks non-fast-forward updates to `main`. Create a real
non-fast-forward (amend the tip) and try to force it:

```sh
git checkout main
git commit --amend --allow-empty -m "rewritten history"
git -c "$GIT_PROXY_HEADER" push --force origin main
# ! [remote rejected] main -> main (force-push to protected ref "refs/heads/main" is not allowed)
```

Gitea's `main` is left unchanged — the deny is reported via a structured
`report-status` reason and the upstream is never written.

### A push containing a secret is denied

`secret_scan` rejects pushes whose content matches a known secret shape, with a
**redacted** reason (the matched secret value never reaches the agent, the
audit log, or an alert):

```sh
git checkout -b feat/secret
echo "AKIAIOSFODNN7EXAMPLE" > leak.txt && git add . && git commit -m "oops"
git -c "$GIT_PROXY_HEADER" push origin feat/secret
# ! [remote rejected] feat/secret -> feat/secret (secret found in "leak.txt" at line 1
#                                   (rule: aws-access-key-id); snippet: ***REDACTED***)
```

`feat/secret` never reaches Gitea.

### Read protection withholds `secrets/**` from a partial clone

`policy.read.deny: ["secrets/**"]` withholds blobs whose path matches from any
fetch. First push a benign file under `secrets/` (content that is not itself a
secret), then take a fresh partial clone:

```sh
git checkout feat/smoke
mkdir -p secrets && printf 'placeholder-not-a-real-secret-value\n' > secrets/api.key
git add . && git commit -m "add config"
git -c "$GIT_PROXY_HEADER" push origin feat/smoke

cd .. && rm -rf demo-readonly
git -c "$GIT_PROXY_HEADER" clone --filter=blob:none $PROXY/demo/demo.git demo-readonly
cd demo-readonly
git cat-file -p HEAD:secrets/api.key
# fatal: path 'secrets/api.key' does not exist in 'HEAD'
```

The `secrets/api.key` blob is withheld from the clone (the proxy assembles the
packfile and omits denied-path blobs).

> **If checkout fails:** a `--filter=blob:none` clone of a repo that already
> contains a `secrets/**` file may report `Clone succeeded, but checkout failed`
> and `access to object <oid> denied by read policy`. That is the protection
> working, not a bug: at checkout time git prefetches every blob in `HEAD`
> before writing any file, and the proxy denies the on-demand fetch of the
> `secrets/**` blob — which aborts checkout *before any file is written*, so
> even non-secret files (`README.md`, `docs/…`) are left out of the working
> tree. Their blobs are present in your local object store; the tree simply was
> not populated. Recover the non-secret files without ever fetching the secret:
>
> ```sh
> git restore --staged :/                    # unstage the deletions (fetches nothing)
> git checkout HEAD -- . ':!secrets'         # materialize everything except secrets/
> ```
>
> Or clone with `--no-checkout` up front
> (`git -c "$GIT_PROXY_HEADER" clone --no-checkout --filter=blob:none …`) and
> check out only the paths you need. The denied `secrets/**` blob is never
> delivered on either path. A plain (non-`--filter`) clone of a
read-protected repo is rejected in v1 with an actionable error pointing at
`--filter=blob:none` (the proxy withholds the denied blobs and a plain clone
cannot tolerate the missing objects); use `--filter=blob:none`.

## 4. Inspect the audit log

Every decision is recorded, attributable to `agent-1`, with **no secret or
credential content** (reasons are redacted; only paths/OIDs are recorded):

```sh
tail data/audit/audit.jsonl
```

```json
{"Time":"...","Transport":"http","Agent":"agent-1","Repo":"demo/demo.git",
 "Service":"git-receive-pack","Verdict":"deny",
 "Reasons":["force-push to protected ref \"refs/heads/main\" is not allowed"],
 "Refs":[{"Ref":"refs/heads/main","Old":"...","New":"...","Force":false}],
 "DeniedPaths":null,"DeniedOIDs":null,"DryRun":false}
```

A no-leak canary:

```sh
grep "AKIAIOSFODNN7EXAMPLE" data/audit/audit.jsonl && echo "LEAK!" || echo "no leak (expected)"
```

## 5. Tear it down

```sh
docker compose down -v      # -v removes the Gitea data volume too
sudo rm -rf data            # local runtime state
```

## Production hardening

This example is tuned for a fast local demo. Before anything real:

- **Run the proxy as a non-root user with properly-owned volumes** (the image
  already drops to uid 1000; ensure the mirror/audit volumes are owned by that
  uid — use named volumes with an init chown, or a dedicated host path).
- **Use real, scoped Bearer tokens** for agents; rotate them. The `agent-token-1`
  placeholder is for the demo only.
- **Terminate TLS in front of both the proxy and Gitea** (a reverse proxy or
  Gitea's built-in TLS). The example uses plain HTTP on a private network.
- **Point Gitea at persistent storage** and back it up; the example's
  `gitea-data` volume is ephemeral (`down -v` deletes it).
- **Wire `alerts.webhook`** so violations surface in real time (Slack/Mattermost
  / your IR channel). The proxy's webhook POST is detached from the request
  context, so a denied client disconnecting cannot silence its own alert.
- **Enable dry-run first** (`policy.dry_run: true` with `mode: collect_all`) to
  observe every violation against your real traffic without blocking, then
  switch to enforce once the policy is tuned.
- **Set branch protection on the real upstream** (and on this repo's `main`) so
  a policy bypass can't land without review.

## Publishing this docs site

The page you are reading is a Jekyll site served from the repo's `/docs` folder.
To publish it on GitHub Pages: repo **Settings → Pages → Source: Deploy from a
branch → `main` → `/docs`**. No workflow file is needed — GitHub's native Jekyll
builder renders `_config.yml` (`minima` theme) and the markdown pages. The
`README.md` at the repo root is not served by Pages (only `/docs` is).