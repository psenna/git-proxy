# Rootless Docker-in-Docker for the Claude Code example — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a rootless Docker-in-Docker daemon (sysbox runtime) to the `example/github-claude-code` compose stack so the Claude Code agent can run arbitrary images (node, python, golang, postgres, minio) via `docker run`, with the daemon network-isolated from git-proxy's credentials, and make the agent aware of the setup via a `CLAUDE.md` + `use-docker` skill.

**Architecture:** A new `docker` compose service runs `docker:27-dind` under the `sysbox` runtime (no `--privileged`) on an isolated `dinernet` bridge; the `claude` service joins both `proxynet` (git-proxy) and `dinernet` (the daemon) and talks to it over `DOCKER_HOST=tcp://docker:2375`. A shared named volume `workspace` mounted in both `claude` and `docker` is the only file-exchange point. The agent image gains the docker CLI client plus a baked `CLAUDE.md` and `use-docker` skill that the entrypoint drops into `/workspace`.

**Tech Stack:** Docker Compose, `docker:27-dind`, Nestybox sysbox-ce runtime (host), Alpine (`node:22-alpine` base for the agent), bash entrypoint, Markdown skill/CLAUDE.md.

## Global Constraints

- **Example-only.** No Go code, no `internal/`, no `cmd/`, no git-proxy core, no `config.yaml`/`credentials.yaml` schema changes. The `git-proxy` service is untouched.
- **No `--privileged`, no host socket.** The `docker` service uses `runtime: sysbox-runc` and MUST NOT set `privileged: true` and MUST NOT bind-mount `/var/run/docker.sock`.
- **Hard host prerequisite.** sysbox requires a Linux host with systemd (kernel ≥ 4.18). It cannot run on Docker Desktop (macOS/Windows). Documented as a hard prerequisite; not worked around.
- **Network isolation.** `git-proxy` is on `proxynet` ONLY — it MUST NOT be added to `dinernet`. Only `claude` and `docker` join `dinernet`.
- **`/workspace` is the only shared exchange point.** The `workspace` named volume is mounted at `/workspace` in BOTH `claude` and `docker`. No other agent path is bind-mountable into a workload.
- **No commits / on-disk only.** Do NOT `git commit` or `git push` any plan or work. Keep changes uncommitted on disk. (User standing preference — overrides the skill's default commit steps.) The commit steps below are therefore **descriptive only** of the logical change boundary; do not run them.
- **Conventional Commits (if ever committed later):** `feat(example): …`, `docs(example): …`. Commit messages and PR bodies would end with `Co-Authored-By: Claude <noreply@anthropic.com>` / `🤖 Generated with [Claude Code](https://claude.com/claude-code)` — but again, do not commit now.
- **Do not touch** `deploy/docker/credentials.yaml` or `deploy/docker/demo/` (user's Gitea token / clone). This plan does not touch `deploy/` at all.

---

## File Structure

- `example/github-claude-code/claude-code/use-docker/SKILL.md` (new) — on-demand procedural skill: how to run node/python/go, stand up service deps, the `/workspace`-only sharing rule.
- `example/github-claude-code/claude-code/agent-context/CLAUDE.md` (new) — always-loaded awareness template the entrypoint copies into `/workspace/CLAUDE.md`.
- `example/github-claude-code/claude-code/Dockerfile` (modify) — add `docker-cli`; `COPY` the two new artifacts into `/opt`.
- `example/github-claude-code/claude-code/entrypoint.sh` (modify) — drop `CLAUDE.md` and the `use-docker` skill into `/workspace`.
- `example/github-claude-code/docker-compose.yml` (modify) — add `docker` service, `dinernet` network, `workspace` + `docker-cache` volumes; rewire `claude` (both networks, `depends_on` daemon, `DOCKER_HOST`, shared `workspace` volume); drop `claude-work`.
- `example/github-claude-code/README.md` (modify) — new "Docker for the agent" section, security statement, troubleshooting.

---

## Task 1: Agent-awareness content (`use-docker` skill + `CLAUDE.md` template)

**Files:**
- Create: `example/github-claude-code/claude-code/use-docker/SKILL.md`
- Create: `example/github-claude-code/claude-code/agent-context/CLAUDE.md`

**Interfaces:**
- Consumes: nothing (pure content).
- Produces: two files under the `claude-code/` build context that Task 2 `COPY`s into the image and Task 3's entrypoint installs into `/workspace`.

- [ ] **Step 1: Create the `use-docker` skill**

Write `example/github-claude-code/claude-code/use-docker/SKILL.md` with exactly this content:

````markdown
---
name: use-docker
description: Use when the agent needs to run code or stand up service dependencies (postgres, minio, redis, etc.) inside containers. The git-proxy example stack gives you a rootless Docker-in-Docker daemon at DOCKER_HOST=tcp://docker:2375; this skill gives the canonical run pattern, per-language one-liners, the /workspace sharing rule, and the security boundary. Use it any time a task says to run, build, test, or execute code in node/python/go (or any other image), or to launch a database/cache/service for development.
---

# Use Docker (rootless DinD)

You are running inside the `claude` container of the git-proxy example stack. A
**rootless Docker-in-Docker daemon** is available at `DOCKER_HOST=tcp://docker:2375`
(set in your environment). Use it to run code in any language and to stand up
service dependencies — without installing anything on the agent itself.

## The one rule that matters most: `/workspace` is the only shared path

The Docker daemon lives in a **separate container** (`docker`). It cannot see your
filesystem except for the shared `/workspace` volume. So:

- **Files you want a container to read or write MUST live under `/workspace`.**
- Mount the shared volume into every workload: `-v /workspace:/work`, and set the
  workdir: `-w /work`.
- **Never bind-mount any other path** (e.g. `-v /opt:/x`, `-v /tmp:/x`,
  `-v /home/claude:/x`). The daemon will silently mount an **empty** directory and
  your command will fail or see no files. There is no error — it just looks empty.

Your working directory IS `/workspace` (the repo is cloned here), so repo files
are already shareable.

## Canonical run pattern

```sh
docker run --rm -v /workspace:/work -w /work <image> <command>
```

`--rm` removes the container after it exits (keep workloads ephemeral unless you
need a named volume for state). `-v /workspace:/work -w /work` makes your files
appear at `/work` inside the container and sets the working directory there.

## Per-language one-liners

```sh
# Node (your agent image is node:22, but use a fresh container for isolation)
docker run --rm -v /workspace:/work -w /work node:22-alpine node script.js
docker run --rm -v /workspace:/work -w /work node:22-alpine npm install

# Python
docker run --rm -v /workspace:/work -w /work python:3-alpine python script.py
docker run --rm -v /workspace:/work -w /work python:3-alpine sh -c 'pip install -r requirements.txt && python script.py'

# Go
docker run --rm -v /workspace:/work -w /work golang:1-alpine go test ./...
docker run --rm -v /workspace:/work -w /work golang:1-alpine go build -o /work/app .
```

Note: a workload's installed dependencies (e.g. `node_modules/`, a Python venv,
`/root/go/pkg`) persist only if they are written under `/workspace` (the shared
volume) OR a named volume you create. State written elsewhere inside the
container is lost when `--rm` removes it. For Go, set `GOMODCACHE`/`GOCACHE`
under `/work` if you want build caches to persist.

## Standing up a service dependency (postgres, minio, redis, …)

Run the service detached on the daemon's internal bridge, then connect from
another workload container by name.

```sh
# Start postgres (detached; keeps running). Give it a named volume for data.
docker run -d --name pg \
  -e POSTGRES_PASSWORD=secret \
  -v pgdata:/var/lib/postgresql/data \
  postgres:16

# Connect from a throwaway container on the same daemon network (linked by name):
docker run --rm --link pg postgres:16 \
  psql -h pg -U postgres -c '\l'
```

Workload containers you launch are on the daemon's default bridge network; they
reach each other by container name (`pg`, `minio`, …). They are NOT on the
compose `dinernet` and cannot reach `git-proxy` — that is intentional.

## Two execution surfaces — don't cross them

- **Git operations** (clone/fetch/push, PRs, CI, issues): go through **git-proxy**
  (see the `use-git-proxy` skill). Never `git clone` against github.com directly,
  and never try to reach the upstream token.
- **Running code & service deps**: use **Docker** (this skill).

Do not use Docker to bypass git-proxy (e.g. cloning github.com inside a
container). The Docker daemon is isolated from git-proxy on purpose.

## Security boundary (what you cannot do)

- You will **never** receive the upstream GitHub PAT. It is held by git-proxy and
  is not on `dinernet`. Do not attempt to obtain it.
- The Docker daemon is **rootless from the host's perspective**: it has no host
  privileges and cannot see git-proxy's bind mounts. It can run containers and
  pull images — that is its whole scope.
- If `docker` commands fail with "Cannot connect to the Docker daemon", the
  `docker` service may still be starting; wait a few seconds and retry (the
  compose `depends_on: service_healthy` normally prevents this).
````

- [ ] **Step 2: Create the `CLAUDE.md` awareness template**

Write `example/github-claude-code/claude-code/agent-context/CLAUDE.md` with exactly this content:

````markdown
# Environment

You are Claude Code running inside the `claude` container of the git-proxy
example stack. You have TWO execution surfaces:

- **Git operations** (clone/fetch/push, PRs, CI, issues): go through git-proxy.
  See the `use-git-proxy` skill. Never talk to github.com directly.
- **Running code & service deps** (node, python, go, postgres, minio, …): use
  Docker, available via `DOCKER_HOST=tcp://docker:2375`. See the `use-docker`
  skill.

## Docker rules (read before you `docker run`)

- `/workspace` is the ONLY shared exchange point with workload containers. Files
  you want a container to read/write must live under `/workspace`; mount it as
  `-v /workspace:/work` and `-w /work`.
- Do NOT bind-mount any other path (e.g. `/opt`, `/tmp`, `/home/claude`) — the
  Docker daemon is in a separate container and cannot see your filesystem outside
  the shared `/workspace` volume. It will silently mount an empty path.
- Your working directory IS `/workspace`, so repo files are already shareable.
- The Docker daemon is rootless/isolated: it cannot reach git-proxy or its
  credentials. You will never receive the upstream GitHub PAT — do not attempt to
  obtain it.
````

- [ ] **Step 3: Verify the content is well-formed and matches the spec**

Run:
```bash
test -f example/github-claude-code/claude-code/use-docker/SKILL.md && \
test -f example/github-claude-code/claude-code/agent-context/CLAUDE.md && \
head -4 example/github-claude-code/claude-code/use-docker/SKILL.md
```
Expected: prints the YAML frontmatter block (`---`, `name: use-docker`, `description: …`, `---`) and exits 0. Confirm both files exist and the skill frontmatter `name:` is `use-docker`.

- [ ] **Step 4: (Logical change boundary — do NOT commit)**

This task adds the two awareness artifacts that later tasks bake into the image and install into `/workspace`. No commit per the user's standing preference.

---

## Task 2: Agent image — docker CLI + bake the awareness artifacts

**Files:**
- Modify: `example/github-claude-code/claude-code/Dockerfile`
- Modify: `example/github-claude-code/claude-code/entrypoint.sh`

**Interfaces:**
- Consumes: the two files from Task 1 (as `COPY` sources in the `./claude-code` build context).
- Produces: an agent image that contains the docker CLI client at `/usr/bin/docker` and the baked artifacts at `/opt/skills/use-docker/SKILL.md` and `/opt/agent-context/CLAUDE.md`; an entrypoint that installs them into `/workspace` at startup.

- [ ] **Step 1: Read the current Dockerfile and entrypoint**

Run:
```bash
cat example/github-claude-code/claude-code/Dockerfile
cat example/github-claude-code/claude-code/entrypoint.sh
```
Confirm the current `apk add` line is `git ca-certificates bash curl`, there is one `COPY use-git-proxy/SKILL.md …` line, and the entrypoint has a block that copies the `use-git-proxy` skill into `/workspace/.claude/skills/`.

- [ ] **Step 2: Modify the Dockerfile — add `docker-cli` and the two `COPY` lines**

In `example/github-claude-code/claude-code/Dockerfile`, change the `apk add` line and add two `COPY` lines so the file reads:

```dockerfile
# syntax=docker/dockerfile:1
#
# The agent image: Claude Code (the official npm CLI) on Node, with git so it can
# clone/fetch/push. Backed by Ollama Cloud at runtime (configured via env in
# docker-compose.yml, not baked in — the API key is a secret).
#
# The use-git-proxy skill is baked into the image so the entrypoint can drop it
# into the project's .claude/skills/ at startup (reliable auto-load for the broker
# leg). The use-docker skill + CLAUDE.md are baked the same way so the agent is
# aware of its rootless DinD environment (see docker-compose.yml `docker` service).

FROM node:22-alpine

# git: clone/fetch/push. ca-certificates: HTTPS to github.com and ollama.com.
# bash: entrypoint. curl: the broker leg (the skill drives the broker with curl).
# docker-cli: the client only (no daemon) — talks to the rootless DinD daemon in
# the separate `docker` service via DOCKER_HOST=tcp://docker:2375.
RUN apk add --no-cache git ca-certificates bash curl docker-cli && rm -rf /var/cache/apk/* && \
    npm install -g @anthropic-ai/claude-code

# Non-root runtime, matching git-proxy's uid 1000.
RUN adduser -D -u 1000 -G users claude

# Bake the skills + the always-loaded CLAUDE.md; the entrypoint copies them into
# /workspace/.claude/skills/ and /workspace/CLAUDE.md at startup.
COPY use-git-proxy/SKILL.md /opt/skills/use-git-proxy/SKILL.md
COPY use-docker/SKILL.md /opt/skills/use-docker/SKILL.md
COPY agent-context/CLAUDE.md /opt/agent-context/CLAUDE.md

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER claude
WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 3: Modify the entrypoint — install the awareness artifacts into `/workspace`**

In `example/github-claude-code/claude-code/entrypoint.sh`, find the existing block that copies the `use-git-proxy` skill:

```sh
# Make the use-git-proxy skill available to this project workspace. Claude Code
# auto-loads skills from .claude/skills/ in the project (cwd) directory.
mkdir -p /workspace/.claude/skills/use-git-proxy
cp /opt/skills/use-git-proxy/SKILL.md /workspace/.claude/skills/use-git-proxy/SKILL.md
```

Add immediately after it:

```sh
# Make the agent aware of its rootless DinD environment. CLAUDE.md is always
# loaded by Claude Code (project root); the use-docker skill is on-demand.
cp /opt/agent-context/CLAUDE.md /workspace/CLAUDE.md
mkdir -p /workspace/.claude/skills/use-docker
cp /opt/skills/use-docker/SKILL.md /workspace/.claude/skills/use-docker/SKILL.md
```

- [ ] **Step 4: Build the agent image to prove the Dockerfile + COPY sources resolve**

Run:
```bash
docker build -t git-proxy-claude-test -f example/github-claude-code/claude-code/Dockerfile example/github-claude-code/claude-code
```
Expected: the build succeeds (exit 0). A failure here means a `COPY` source path is wrong (Task 1 files must exist at `./claude-code/use-docker/SKILL.md` and `./claude-code/agent-context/CLAUDE.md`) or `docker-cli` is not a valid apk package name (it is, on Alpine 3.20+).

- [ ] **Step 5: Verify the docker CLI and baked artifacts are present in the image**

Run:
```bash
docker run --rm --entrypoint sh git-proxy-claude-test -c 'docker --version && test -f /opt/skills/use-docker/SKILL.md && test -f /opt/agent-context/CLAUDE.md && echo OK'
```
Expected: prints a `Docker version …` line and `OK` (exit 0). This proves the docker client is installed and both awareness artifacts are baked.

- [ ] **Step 6: (Logical change boundary — do NOT commit)**

The agent image now carries the docker client and the awareness artifacts. No commit per the user's standing preference.

---

## Task 3: Compose — `docker` service, `dinernet`, shared `workspace` volume, rewire `claude`

**Files:**
- Modify: `example/github-claude-code/docker-compose.yml`

**Interfaces:**
- Consumes: the `claude` image from Task 2 (its build context `./claude-code`).
- Produces: a compose file with a `docker` service (rootless DinD on `dinernet`), a `dinernet` network, shared `workspace` + `docker-cache` volumes, and a `claude` service that joins both networks, depends on the daemon, sets `DOCKER_HOST`, and shares `workspace`.

- [ ] **Step 1: Read the current compose file**

Run:
```bash
cat example/github-claude-code/docker-compose.yml
```
Confirm: `claude` has `depends_on: [git-proxy]`, `volumes: [claude-work:/workspace]`, `networks: [proxynet]`; `git-proxy` is on `proxynet`; bottom-level `networks: { proxynet }` and `volumes: { claude-work: {} }`.

- [ ] **Step 2: Add the `docker` service**

In `example/github-claude-code/docker-compose.yml`, add a new `docker` service block (place it after the `git-proxy` service and before the `claude` service, or anywhere among the services — ordering is cosmetic in compose):

```yaml
  # Rootless Docker-in-Docker daemon. The agent (claude) uses it to run arbitrary
  # images (node, python, golang, postgres, minio, …) via DOCKER_HOST. Runs under
  # the sysbox runtime with NO --privileged: sysbox user-namespace mapping makes
  # the inner dockerd unprivileged on the host, so it cannot access host devices
  # or git-proxy's bind mounts (incl. credentials.yaml). It is on dinernet ONLY —
  # git-proxy is not on dinernet, so a compromised daemon has no route to the proxy.
  # Host prerequisite: sysbox must be installed on a Linux host (see README).
  docker:
    image: docker:27-dind
    runtime: sysbox-runc
    container_name: github-claude-dind
    # The docker:dind entrypoint (dockerd-entrypoint.sh) execs `dockerd "$@"`, so
    # `command:` is the dockerd args. Listen on TCP for cross-container access on
    # dinernet AND on the unix socket for the in-container healthcheck.
    command: ["--host=tcp://0.0.0.0:2375", "--host=unix:///var/run/docker.sock"]
    volumes:
      - docker-cache:/var/lib/docker   # image/layer cache survives restarts
      - workspace:/workspace           # shared with claude (the exchange point)
    networks:
      - dinernet
    healthcheck:
      test: ["CMD", "docker", "info"]
      interval: 5s
      timeout: 3s
      retries: 30
      start_period: 10s
```

- [ ] **Step 3: Rewire the `claude` service — both networks, depends_on daemon, DOCKER_HOST, shared workspace**

In the `claude` service block, make these changes:

(a) Replace:
```yaml
    depends_on:
      - git-proxy
```
with:
```yaml
    depends_on:
      git-proxy:
        condition: service_started
      docker:
        condition: service_healthy
```

(b) In the `environment:` block, add (after the existing `GIT_PROXY_HEADER` line):
```yaml
      # Docker client -> the rootless DinD daemon on the isolated dinernet.
      DOCKER_HOST: "tcp://docker:2375"
      DOCKER_TLS_VERIFY: ""
```

(c) Replace:
```yaml
    volumes:
      - claude-work:/workspace
    networks:
      - proxynet
```
with:
```yaml
    volumes:
      - workspace:/workspace
    networks:
      - proxynet
      - dinernet
```

Leave the `claude` service's `build`, `container_name`, `command`, and the rest of its `environment:` unchanged.

- [ ] **Step 4: Replace the bottom-level `networks:` and `volumes:`**

Replace:
```yaml
networks:
  proxynet:
    driver: bridge

volumes:
  claude-work: {}
```
with:
```yaml
networks:
  proxynet:
    driver: bridge
  dinernet:
    driver: bridge

volumes:
  workspace: {}
  docker-cache: {}
```

- [ ] **Step 5: Confirm `git-proxy` is NOT on `dinernet`**

Run:
```bash
grep -A2 '^  git-proxy:' example/github-claude-code/docker-compose.yml | grep networks -A1
```
Expected: shows `proxynet` only under `git-proxy`'s `networks:`. `git-proxy` MUST NOT list `dinernet`. (If it does, you accidentally edited the wrong service — undo it.)

- [ ] **Step 6: Validate the compose file parses and references resolve**

Run:
```bash
docker compose -f example/github-claude-code/docker-compose.yml config >/tmp/cfg.out && echo "PARSE OK" && grep -E 'dinernet|workspace|docker-cache|DOCKER_HOST|runtime' /tmp/cfg.out
```
Expected: `PARSE OK`, and the grep shows `dinernet`, `workspace`, `docker-cache`, `DOCKER_HOST`, and `runtime: sysbox-runc` (compose normalizes the `runtime` key into the rendered config). A parse error means a YAML indentation mistake — fix and re-run. (Note: `docker compose config` does NOT verify sysbox is installed on the host; that is covered by the final E2E task on a sysbox host.)

- [ ] **Step 7: (Logical change boundary — do NOT commit)**

The compose stack now has the rootless DinD daemon wired in. No commit per the user's standing preference.

---

## Task 4: README — sysbox prerequisite, usage, security statement, troubleshooting

**Files:**
- Modify: `example/github-claude-code/README.md`

**Interfaces:**
- Consumes: the final compose/Dockerfile/entrypoint state from Tasks 2–3.
- Produces: a README section that tells an operator the host prerequisite, what was added, how the agent uses Docker, the security model, and how to troubleshoot.

- [ ] **Step 1: Read the current README to find the insertion point**

Run:
```bash
grep -n '^## ' example/github-claude-code/README.md
```
Pick an insertion point: add the new section after the existing "Deny-by-default" / credentials section (the one that documents `credentials.yaml`) and before any final "Run it" / "Cleanup" section. If unsure, append the new section near the end before any "Troubleshooting" that already exists (merge with it).

- [ ] **Step 2: Add the "Docker for the agent" section**

Insert this section into `example/github-claude-code/README.md`:

````markdown
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
````

- [ ] **Step 3: Verify the README section is present and well-formed**

Run:
```bash
grep -c 'runtime: sysbox-runc\|/workspace is the only\|unprivileged host user\|runtime sysbox-runc not found' example/github-claude-code/README.md
```
Expected: prints `4` (one match per phrase). Confirms the prerequisite, the sharing rule, the security statement, and the troubleshooting entry are all present.

- [ ] **Step 4: (Logical change boundary — do NOT commit)**

The README now documents the DinD addition. No commit per the user's standing preference.

---

## Task 5: End-to-end manual verification on a Linux + sysbox host

**Files:**
- None (verification only — no file changes).

**Interfaces:**
- Consumes: the full stack from Tasks 1–4.
- Produces: confirmed-working rootless DinD for the agent, with the sharing boundary and network isolation proven.

> This task is **manual** and requires a Linux host with sysbox installed and verified (`docker info | grep -i sysbox`). It cannot run on Docker Desktop or in CI. It is the capstone that proves the stack works end-to-end.

- [ ] **Step 1: Confirm the host has sysbox**

Run:
```sh
docker info | grep -i sysbox
```
Expected: a line showing the `sysbox` runtime is registered. If absent, stop and install sysbox (see the README section from Task 4) before continuing.

- [ ] **Step 2: Build and start the stack**

Run from the repo root:
```sh
cd example/github-claude-code
docker compose build
docker compose up -d
```
Expected: the `docker` service reaches `healthy` (check with `docker compose ps`); `claude` starts after it. No `runtime sysbox-runc not found` error.

- [ ] **Step 3: Prove the agent can reach the daemon and run each language**

Run:
```sh
docker compose exec claude sh -c 'docker version --format "{{.Server.Version}}"'
docker compose exec claude sh -c 'echo "console.log(42)" > /workspace/t.js && docker run --rm -v /workspace:/work -w /work node:22-alpine node t.js'
docker compose exec claude sh -c 'docker run --rm python:3-alpine python -c "print(2+2)"'
docker compose exec claude sh -c 'docker run --rm golang:1-alpine go version'
```
Expected: a docker server version, then `42`, then `4`, then a `go version go1.…` line. (First runs pull images — allow time / outbound internet.)

- [ ] **Step 4: Prove the `/workspace` sharing boundary (positive + negative)**

Run:
```sh
# Positive: /workspace shares bidirectionally.
docker compose exec claude sh -c 'echo hi > /workspace/shared.txt && docker run --rm -v /workspace:/work -w /work alpine cat /work/shared.txt'
# Negative: a non-/workspace path does NOT share (silently empty).
docker compose exec claude sh -c 'echo bye > /tmp/agentonly.txt && docker run --rm -v /tmp:/x alpine cat /x/agentonly.txt || echo "NOT FOUND (expected)"'
```
Expected: positive prints `hi`; negative prints `NOT FOUND (expected)` (or `cat` exits non-zero with no output) — proving only `/workspace` is shared.

- [ ] **Step 5: Prove a service dependency works**

Run:
```sh
docker compose exec claude sh -c 'docker run -d --name pg -e POSTGRES_PASSWORD=secret postgres:16 && sleep 5 && docker run --rm --link pg postgres:16 psql -h pg -U postgres -c "\l" ; docker rm -f pg'
```
Expected: a list of databases (proves the agent can stand up and connect to a service dep). The trailing `docker rm -f pg` cleans up.

- [ ] **Step 6: Prove network isolation — the daemon cannot reach git-proxy**

Run:
```sh
docker compose exec docker sh -c 'wget -qO- --timeout=3 http://git-proxy:8080/ 2>&1 || echo "NO ROUTE (expected)"'
```
Expected: `NO ROUTE (expected)` (the `docker` service is on `dinernet` only; `git-proxy` is on `proxynet` only — no route between them).

- [ ] **Step 7: Prove the no-leak sanity check — the daemon cannot see git-proxy's credential files**

Run:
```sh
docker compose exec docker sh -c 'ls /config.yaml /credentials.yaml 2>&1 || echo "NOT VISIBLE (expected)"'
```
Expected: `NOT VISIBLE (expected)` — the daemon container has no bind-mount of the proxy's config/credentials (only `git-proxy` does).

- [ ] **Step 8: Prove agent awareness — `CLAUDE.md` and the `use-docker` skill are installed**

Run:
```sh
docker compose exec claude sh -c 'test -f /workspace/CLAUDE.md && test -f /workspace/.claude/skills/use-docker/SKILL.md && head -1 /workspace/CLAUDE.md'
```
Expected: prints `# Environment` (the first line of the installed `CLAUDE.md`) and exits 0 — proving the entrypoint installed both awareness artifacts.

- [ ] **Step 9: Tear down**

Run:
```sh
docker compose down -v
```
Expected: removes containers, networks, and the `workspace`/`docker-cache` volumes.

- [ ] **Step 10: (No commit — verification only)**

All verification steps pass. No file changes, no commit.

---

## Self-Review

**1. Spec coverage:**
- Why DinD + sysbox (socket/`--privileged` rejected) → covered in README Task 4 security model + Global Constraints.
- Architecture (docker service, two-network split, git-proxy off dinernet, shared workspace volume) → Task 3 (+ Task 5 Step 6 proves isolation).
- DinD volume problem + `/workspace`-only sharing boundary → Task 1 skill, Task 4 README, Task 5 Step 4 (positive+negative).
- Agent awareness (CLAUDE.md + use-docker skill, entrypoint install) → Tasks 1–2, Task 5 Step 8.
- Precise security model (root inside sandbox, unprivileged on host) → Task 4 README security statement.
- Files touched list → File Structure + Tasks 1–4.
- Manual verification checklist → Task 5 (all 5 spec checks: build/up, node/python/go, postgres dep, sharing boundary, network isolation, no-leak sanity, plus awareness install).
- Out of scope (TLS, rootlesskit, pre-pull, Docker Desktop) → Global Constraints + README troubleshooting.
No gaps.

**2. Placeholder scan:** No TBD/TODO. Every code/content step contains the full file content or exact diff. No "similar to Task N."

**3. Type/name consistency:** The shared volume is `workspace` (not `claude-work`) consistently across Tasks 2–5. The skill name is `use-docker` consistently (frontmatter, `/opt/skills/use-docker/SKILL.md`, `/workspace/.claude/skills/use-docker/SKILL.md`, README). `DOCKER_HOST=tcp://docker:2375` is consistent across compose, skill, CLAUDE.md, README, and verification. The `docker:27-dind` image tag is consistent. The `command:` is dockerd args (not `["dockerd", …]`) consistently, with the entrypoint behavior explained in both compose comment and README.

One refinement made during review: the `docker` service `command:` includes BOTH `--host=tcp://0.0.0.0:2375` and `--host=unix:///var/run/docker.sock` so the `docker info` healthcheck (which uses the unix socket by default) works — captured in the compose comment and verified by Task 5 Step 2/3.