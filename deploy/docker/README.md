# Docker Compose: git-proxy + Gitea

A self-contained local stack: **git-proxy** enforcing policy in front of a
**Gitea** git server. `docker compose up` gives you a working policy gateway
against a real git upstream on localhost — no external account needed.

For the full narrative (topology, why each step, production hardening) see
[../../docs/deploy-docker.md](../../docs/deploy-docker.md). This file is the
copy-paste quickstart.

## Prerequisites

- Docker Engine + the `docker compose` plugin.
- `git` and `curl` on the host.

## 1. Bring the stack up

```sh
cd deploy/docker
mkdir -p data/mirror data/audit          # bind-mounted, writable by the proxy (uid 1000)
docker compose up -d --build
```

Gitea publishes its web UI on `http://localhost:3000`; git-proxy listens on
`http://127.0.0.1:8080`.

> **Linux permission note:** the proxy runs as uid 1000. If your host user is
> not uid 1000 and the container can't write to `data/`, fix ownership once:
> `sudo chown -R 1000:1000 data`. Docker Desktop (macOS/Windows) handles this
> transparently.

Wait for Gitea to be healthy:

```sh
docker compose exec gitea wget -qO- http://localhost:3000/api/v1/version
```

## 2. One-time Gitea setup (scripted)

Create an admin user, a repo (`demo/demo.git` with an initial `main` commit),
and an access token the proxy will use as the upstream credential:

```sh
# admin user "demo" (password "demopass"; change in any real use). Run as the
# Gitea runtime uid (1000) — Gitea refuses to run its CLI as root.
docker compose exec --user 1000:1000 gitea gitea admin user create \
  --username demo --password demopass --email demo@example.com \
  --admin --must-change-password=false

# repo demo/demo.git, auto-initialized on branch "main"
curl -s -u demo:demopass -X POST http://localhost:3000/api/v1/user/repos \
  -H "Content-Type: application/json" \
  -d '{"name":"demo","auto_init":true,"default_branch":"main"}'

# access token for the proxy -> Gitea leg (prints JSON; the token is the sha1
# field). Modern Gitea requires explicit scopes; write:repository covers both
# push and fetch.
curl -s -u demo:demopass -X POST http://localhost:3000/api/v1/users/demo/tokens \
  -H "Content-Type: application/json" \
  -d '{"name":"git-proxy","scopes":["read:repository","write:repository"]}'
```

Copy the `sha1` value from the last response and put it into `credentials.yaml`.
The file uses the profile layout (a list under `credentials:`); fill the
`REPLACE_WITH_GITEA_ACCESS_TOKEN` placeholder, or inject it via the `GITEA_PASSWORD`
(or `GITEA_TOKEN`) env var in `docker-compose.yml` (env overrides the file value):

```sh
TOKEN="<paste the sha1 token here>"
sed -i "s/REPLACE_WITH_GITEA_ACCESS_TOKEN/$TOKEN/" credentials.yaml
docker compose restart git-proxy        # re-read credentials.yaml
```

> Prefer the env path? Set `GITEA_PASSWORD` in `docker-compose.yml` (or `.env`)
> instead and leave `credentials.yaml` untouched — env > file > empty, so the
> proxy picks up the token without a sed edit.

> Prefer the web UI instead? Open `http://localhost:3000`, log in as
> `demo`/`demopass`, create the repo and a personal access token under
> Settings → Applications, then paste the token into `credentials.yaml`.

## 3. Use git through the proxy

The agent authenticates to the proxy with a Bearer token; the proxy holds the
Gitea token. Define a helper so you don't type the header every time:

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

**Clean push to `feat/*` is forwarded** (branch_pattern allows `feat/*`):

```sh
git checkout -b feat/smoke
echo "hello" > file.txt && git add . && git commit -m "add file"
git -c "$GIT_PROXY_HEADER" push origin feat/smoke
# Gitea now has refs/heads/feat/smoke:
docker compose exec gitea git -C /data/git/repositories/demo/demo.git rev-parse refs/heads/feat/smoke
```

**Force-push to `main` is blocked** (history_protect) — Gitea's `main` is left
unchanged:

```sh
git checkout main
git commit --allow-empty -m "rewrite"
git -c "$GIT_PROXY_HEADER" push --force origin main   # rejected; structured reason
```

**A push containing a secret is denied** (secret_scan) — `feat/secret` never
reaches Gitea:

```sh
git checkout -b feat/secret
echo "AKIAIOSFODNN7EXAMPLE" > leak.txt && git add . && git commit -m "oops"
git -c "$GIT_PROXY_HEADER" push origin feat/secret    # denied; ref absent upstream
docker compose exec gitea git -C /data/git/repositories/demo/demo.git rev-parse refs/heads/feat/secret 2>&1 | tail -1
```

**Read protection** withholds `secrets/**` blobs from a partial clone (see
[docs/deploy-docker.md](../../docs/deploy-docker.md) for the full flow):

```sh
git -c "$GIT_PROXY_HEADER" clone --filter=blob:none $PROXY/demo/demo.git demo-readonly
```

## 4. Inspect the audit log

Every decision is recorded, attributable to `agent-1`, with **no secret or
credential content**:

```sh
tail data/audit/audit.jsonl
# expect lines like: {"transport":"http","agent":"agent-1","service":"git-receive-pack","verdict":"deny",...}
grep -v "agent-1" data/audit/audit.jsonl   # any unexpected identity?
grep "AKIAIOSFODNN7EXAMPLE" data/audit/audit.jsonl && echo "LEAK!" || echo "no leak (expected)"
```

## 5. Tear it down

```sh
docker compose down -v      # -v removes the Gitea data volume too
sudo rm -rf data            # local runtime state
```