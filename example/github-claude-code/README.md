# Docker Compose: Claude Code (Ollama Cloud) → git-proxy → GitHub

A runnable example where **Claude Code** — backed by **Ollama Cloud** — works
against a **real GitHub** repo through **git-proxy**. The agent clones/fetches/pushes
through the proxy's git-protocol leg and opens PRs / queries CI / files and triages
**issues** through the proxy's **broker** leg, all without ever seeing the GitHub PAT.
The proxy holds the PAT and attaches it on the proxy→GitHub leg.

This is the counterpart to [`deploy/docker/`](../../deploy/docker), which is a
self-contained stack over a local Gitea. That one needs no external account; this one
needs a GitHub account + PAT and an Ollama Cloud key, but exercises the full
agent-facing surface (git protocol **and** broker — PRs, CI, and issues) against real
GitHub.

For the git-proxy narrative see [`../../docs/deploy-docker.md`](../../docs/deploy-docker.md).

## Topology

```
 claude (agent) --8080(git)/8090(broker)--> git-proxy --https--> github.com
   git insteadOf rewrites https://github.com/<x> -> http://git-proxy:8080/<x>
   http.extraHeader attaches "Authorization: Bearer ${AGENT_TOKEN}"
   broker calls go to http://git-proxy:8090 (uses the use-git-proxy skill)
 claude --> https://ollama.com   (Ollama Cloud, Anthropic-compatible /v1/messages)
```

The agent's Bearer (`agent-token-1`) authenticates it to the proxy only — it is never
forwarded to GitHub. The proxy attaches the GitHub PAT itself (HTTP Basic for the git
protocol, Bearer for the broker REST leg).

## Prerequisites

- Docker Engine + the `docker compose` plugin.
- A **GitHub PAT** with repo read/write (push, PR, CI, issues). Classic: the `repo`
  scope (covers issues). Fine-grained: `Contents: write`, `Pull requests: write`,
  `Actions: read`, `Issues: write`.
- An **Ollama Cloud API key** — create one at <https://ollama.com/settings/keys>.
- A GitHub repo you can push to (you'll set `GITHUB_REPO` and the matching key in
  `credentials.yaml`).

> **Not self-contained:** unlike `deploy/docker`, this points at real github.com and a
> hosted model, so it cannot run offline with no credentials.

## 1. Fill in your secrets

```sh
cd example/github-claude-code
cp .env.example .env
$EDITOR .env                # OLLAMA_API_KEY, GITHUB_REPO, (optionally OLLAMA_MODEL)
```

Then edit `credentials.yaml` so the profile's `repos` matches your repo and holds
your PAT in both the `password` (git protocol, Basic) and `token` (broker, Bearer)
fields:

```sh
$EDITOR credentials.yaml
# e.g. for psenna/git-proxy.git:
#   credentials:
#     - name: GITHUB
#       username: x-access-token
#       password: ghp_yourPAT
#       token: ghp_yourPAT
#       repos:
#         - "psenna/git-proxy.git"
```

`x-access-token` + PAT is the canonical GitHub git-HTTPS Basic form (the proxy's git
leg reads only `username`/`password`; the broker reads `token`). One PAT fills both.
You can also inject the PAT via the `GITHUB_PASSWORD` / `GITHUB_TOKEN` env vars
(env > file > empty), e.g. in `docker-compose.yml`, instead of editing this file.
The env-var name is the profile name **uppercased** (`name: GITHUB` → `GITHUB_PASSWORD`
/ `GITHUB_TOKEN`), so a profile named e.g. `company_abc` reads `COMPANY_ABC_TOKEN`.

**Deny-by-default.** A repo with no matching credential profile is **denied**
(403) before the proxy contacts GitHub — it is not anonymous. To expose a repo to
anonymous (uncredentialed) agents for **read-only** clone/fetch, add it to the
top-level `public_repos` allowlist in `config.yaml` (wildcards like `public/*`
allowed; bare `*` / `**` are not). Anonymous pushes to a `public_repos` repo are
still denied (writes always require a credential profile). The example config
does not set `public_repos`; every repo the agent reaches is profiled in
`credentials.yaml`.

## Docker for the agent (rootless Docker-in-Docker via sysbox)

The `claude` agent can run arbitrary container images — node, python, golang,
postgres, minio, anything — by issuing `docker run …` from inside its container.
A rootless Docker-in-Docker daemon (the `docker` compose service) provides this,
isolated from git-proxy's credentials.

### Host prerequisite (hard): install sysbox on a Linux host

The `docker` service uses `runtime: sysbox-runc`. Sysbox (Nestybox **sysbox-ce**,
open source, `github.com/nestybox/sysbox`) must be installed on the host running
`docker compose`:

- **Linux host with systemd**, kernel ≥ 4.18. **Not Docker Desktop** on macOS or
  Windows — its Linux VM cannot add a custom runtime. On macOS/Windows, run this
  example on a Linux VM or server.
- Install via Nestybox's apt/rpm repo or the `.deb`/`.rpm` package from the
  sysbox-ce GitHub releases. The installer registers sysbox with Docker
  (`/etc/docker/daemon.json` → `runtimes`) and restarts Docker.
- Verify:
  ```sh
  docker info | grep -i sysbox    # shows the registered runtime
  docker run --runtime=sysbox-runc --rm alpine echo ok
  ```

If sysbox is not installed, `docker compose up` fails with
`runtime sysbox-runc not found` for the `docker` service.

### What was added

- A **`docker` service** (`docker:27-dind`, `runtime: sysbox-runc`, **no
  `--privileged`**) running the daemon on TCP `2375`, on an isolated **`dinernet`**
  bridge. `git-proxy` is on `proxynet` only — it is NOT on `dinernet`.
- The **`claude` service** joins both `proxynet` and `dinernet`, gets the docker
  CLI client, and sets `DOCKER_HOST=tcp://docker:2375`.
- A shared **`workspace` named volume** mounted at `/workspace` in BOTH `claude`
  and `docker` — the only file-exchange point between the agent and the containers
  it launches.
- A **`CLAUDE.md`** (always loaded by Claude Code) and a **`use-docker`** skill
  that the entrypoint drops into `/workspace`, so the agent knows it has Docker
  and how to use it.

### How the agent uses it

```sh
# Inside the claude container (your repo is already at /workspace):
docker run --rm -v /workspace:/work -w /work node:22-alpine node script.js
docker run --rm -v /workspace:/work -w /work python:3-alpine python script.py
docker run --rm -v /workspace:/work -w /work golang:1-alpine go test ./...
```

**The one rule:** `/workspace` is the only path shared with workload containers.
Files a container must read/write live under `/workspace` (mount it as
`-v /workspace:/work`). Bind-mounting any other path silently mounts an empty
directory — the daemon is in a separate container and cannot see the agent's
filesystem outside the shared volume.

### Security model

The DinD daemon runs as **root inside the sysbox sandbox**, but sysbox's
user-namespace mapping maps that in-container root to an **unprivileged host
user**. The daemon has **no host privileges**, **no access to host devices**, and
**cannot see git-proxy's bind mounts** (including `credentials.yaml`).
Additionally, `git-proxy` is on `proxynet` only — it has no interface on
`dinernet` — so a compromised daemon has no network route to the proxy either.

This is "rootless from the host's perspective" (no privileged container, no host
root), which is the property that protects the credential-isolation model. It is
*not* rootless in the `rootlesskit`/rootless-dockerd sense (the dockerd process
itself is root inside its sandbox); that stronger property is achievable but
unnecessary here.

### Troubleshooting

- **`runtime sysbox-runc not found`** on `docker compose up` → sysbox is not installed
  on the host. Install it (see above) and restart Docker.
- **`docker run -v /some/other/path:/x …` shows empty files** → only `/workspace`
  is shared. Put the files under `/workspace` and mount `-v /workspace:/work`.
- **`Cannot connect to the Docker daemon` from the agent** → the `docker` service
  is still starting. `docker compose up` waits for its healthcheck before
  starting `claude` (`depends_on: service_healthy`); if you `exec` in during a
  window, wait a few seconds and retry.
- **Image-pull / overlay errors inside the daemon** → on some filesystems the
  daemon's default `overlay2` storage driver may need `vfs`. Add
  `--storage-driver=vfs` to the `docker` service `command:` list and retry.

## 2. Bring the stack up

```sh
mkdir -p data/mirror data/audit          # bind-mounted, writable by the proxy (uid 1000)
docker compose up -d --build
```

git-proxy publishes its git leg on `http://127.0.0.1:8080` and its broker on
`http://127.0.0.1:8090`. The `claude` service starts, runs the default prompt once, and
exits.

> **Linux permission note:** the proxy runs as uid 1000. If your host user is not uid
> 1000 and the container can't write to `data/`, fix ownership once:
> `sudo chown -R 1000:1000 data`. Docker Desktop (macOS/Windows) handles this
> transparently.

Confirm the broker came up (this also proves the `kind: github` upstream satisfied the
PRSupport type-assert at startup):

```sh
curl -s http://127.0.0.1:8090/healthz    # {"status":"ok"}
```

This config also sets `issue_upstream.kind: github`, so the broker's **issue routes**
are wired (`POST /{repo}/issues`, list/get/comment/close/reopen/edit/labels) — see the
`use-git-proxy` skill for the full surface. With `issue_upstream` omitted, issue routes
return 501 per-op while PR/CI routes keep working (issues are opt-in).

## 3. Watch the agent

```sh
docker compose logs -f claude
```

With the default prompt the agent clones `${GITHUB_REPO}` through the proxy, creates
`feat/example`, adds `hello.txt`, pushes it, and opens a real PR via the broker (using
the `use-git-proxy` skill, which is baked into the image and dropped into the project's
`.claude/skills/` at startup). Confirm the PR exists on github.com.

To drive a different task:

```sh
docker compose run --rm claude "Summarize the last 5 commits on ${GITHUB_REPO}, then comment on the newest PR via the broker."
```

## 4. Try the git leg yourself (no model needed)

From the host, prove the credentials and routing work independent of Claude Code:

```sh
git -c http.extraheader='Authorization: Bearer agent-token-1' clone \
  http://127.0.0.1:8080/<OWNER>/<REPO>.git demo-checkout
```

## 5. Inspect the audit log

Every decision is recorded, attributable to `claude-code-agent`, with **no secret or
credential content**:

```sh
tail data/audit/audit.jsonl
grep -E 'ghp_|x-access-token' data/audit/audit.jsonl && echo "LEAK!" || echo "no leak (expected)"
```

## 6. Tear it down

```sh
docker compose down -v      # -v removes the workspace and docker-cache volumes too
sudo rm -rf data            # local runtime state
```

## Security model

- **The agent never receives the GitHub PAT.** git-proxy attaches its own creds on the
  proxy→GitHub leg (Basic for git, Bearer for the broker). Do not attempt to obtain or
  use the PAT from inside the agent.
- **The agent Bearer is consumed for auth only** — never forwarded to GitHub.
- **Deny reasons are no-leak.** Secret-scan reasons are redacted; broker error reasons
  are generic class strings. You may safely repeat them.
- **Fail-closed.** Missing/invalid agent Bearer → 401; an upstream that lacks
  PRSupport → the broker refuses to start. The `kind: github` upstream here satisfies
  PRSupport, so the broker runs. **Issues are opt-in**: the issue tracker comes from a
  separate `issue_upstream`; this config sets it to `kind: github` (same PAT), so issue
  routes work. Without `issue_upstream`, issue routes return 501 per-op while PR/CI
  routes keep working — the `PRSupport` startup fail-closed is unaffected.

## Notes

- **Model choice.** `OLLAMA_MODEL` defaults to `gpt-oss:120b`. For agentic git work,
  `qwen3-coder` has stronger tool-calling fidelity (it reliably triggers Claude Code's
  tool layer); override via `.env`.
- **PAT scopes.** See Prerequisites — the PAT must cover push, PR, and CI read.
- **Skill source.** `claude-code/use-git-proxy/SKILL.md` is a verbatim copy of
  [`agent/skills/use-git-proxy/SKILL.md`](../../agent/skills/use-git-proxy/SKILL.md)
  (shipped in PR #38). Keep it in sync with that source.