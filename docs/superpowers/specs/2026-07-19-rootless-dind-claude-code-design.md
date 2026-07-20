# Rootless Docker-in-Docker for the Claude Code example

**Date:** 2026-07-19
**Scope:** `example/github-claude-code/` only. No Go code, no git-proxy core, no
`config` schema changes. The `git-proxy` service is untouched.

## Goal

Let the Claude Code agent in the `example/github-claude-code` compose stack run
**arbitrary container images** — node, python, golang, and service dependencies
like postgres and minio — by issuing `docker run …` from inside the agent
container, **without** exposing the host Docker socket and **without** a
privileged root daemon that could reach git-proxy's credentials.

## Why DinD (and why rootless via sysbox)

The agent needs to run code in multiple languages and stand up service
dependencies as part of development work. That requires the ability to launch
arbitrary images, not just a pre-baked set of runtimes — so baking the runtimes
into the agent image (the simpler, most-secure option) is insufficient here.

Docker-in-Docker is the mechanism. The security constraint is the hard part:

- **Bind-mounting the host `/var/run/docker.sock`** is rejected: it gives the
  agent root-equivalent control of the *host* Docker daemon, which can spawn
  privileged containers and read git-proxy's bind mounts — directly defeating
  the proxy's no-leak model.
- **`docker:dind-rootless` with `--privileged`** is rejected: although the
  dockerd process is rootless, the container hosting it is `--privileged`, so
  anything that compromises the daemon inherits the privileged container's host
  access — including the ability to read `credentials.yaml` off the host. In a
  stack whose reason for existing is credential isolation, that is a real
  downgrade to the threat model.
- **Sysbox** (Nestybox sysbox-ce) is the chosen runtime. It runs the DinD
  container **without `--privileged`** by mapping in-container root to an
  unprivileged host user via Linux user namespaces. The inner dockerd has no
  host privileges, no host-device access, and cannot see git-proxy's bind mounts.

**Host prerequisite (hard):** sysbox requires a **Linux host with systemd**
(kernel ≥ 4.18). It cannot run on Docker Desktop (macOS/Windows), whose Linux VM
does not allow adding a custom runtime. This is documented as a hard
prerequisite in the README; `docker compose up` fails with `runtime sysbox not
found` if sysbox is absent.

## Architecture

A new `docker` service runs the daemon; the `claude` service is its only client.
Two isolated bridge networks keep the daemon away from the credentials.

```
                         ┌─────────── dinernet (bridge) ───────────┐
                         │                                          │
   claude (agent) ───────┤── tcp://docker:2375 ──►  docker (dind)   │
     │  uid 1000         │  (DOCKER_HOST)           runtime: sysbox-runc │
     │  node + docker-cli│                          no --privileged │
     └──── proxynet ─────┘                          image cache vol  │
            │
            ├──► git-proxy (uid 1000)  ──► github.com   [credentials.yaml lives here]
            └──► ollama.com (outbound)

   git-proxy is on proxynet ONLY — it has NO interface on dinernet.
```

- **`docker` service** (new): `image: docker:27-dind`, `runtime: sysbox-runc`, **no
  `privileged: true`**, on `dinernet` only. Dockerd listens on TCP `2375` (plain,
  no TLS — acceptable because only `claude` is on `dinernet`). A named volume
  `docker-cache` at `/var/lib/docker` caches pulled images across restarts.
- **`claude` service** (modified): joins **both** `proxynet` (git-proxy + ollama)
  and `dinernet` (the daemon). Gets the docker CLI client and
  `DOCKER_HOST=tcp://docker:2375`. `depends_on: docker: { condition:
  service_healthy }` so the agent does not race the daemon. Its `/workspace`
  becomes a **shared named volume** also mounted into the `docker` service.
- **`git-proxy`** unchanged and **not** on `dinernet` — so a compromised daemon
  has no network route to the proxy or its `credentials.yaml` bind mount.
  Defense-in-depth on top of sysbox's user-namespace isolation.

### The DinD volume problem and the shared `workspace` volume

In DinD the `docker` CLI runs in the `claude` container, but the daemon that
interprets `-v` bind mounts runs in the separate `docker` container. So `docker
run -v /workspace:/work …` is resolved by the daemon **relative to its own
filesystem**, not the agent's. The fix: mount the **same named volume `workspace`
at `/workspace` in both `claude` and `docker`**. Then the agent's files under
`/workspace` (its working directory — the repo is cloned there) are visible to
any workload container via `-v /workspace:/work`, bidirectionally.

**Sharing boundary (inherent to DinD, not changed by sysbox):**

| Path the agent bind-mounts | Shares with workload? | Why |
|---|---|---|
| `/workspace` (and anything under it) | yes | both containers mount the `workspace` named volume there |
| Any other path in the `claude` container | no | the daemon cannot see the agent's filesystem outside the shared volume; it silently mounts an empty path |

The rule, codified for the agent: **`/workspace` is the only shared exchange
point.** Anything a workload must read or write lives under `/workspace`.

## Agent awareness

The agent must proactively know it has Docker, the `/workspace` sharing rule, and
the security boundary — not wait to discover it. Two artifacts, both baked into
the image and installed by the entrypoint at startup (mirroring the existing
`use-git-proxy` skill-baking pattern).

### `CLAUDE.md` in `/workspace` (always-loaded awareness)

Claude Code auto-reads `CLAUDE.md` from the project root on every turn, so this
is the highest-signal lever. The entrypoint copies a baked template from
`/opt/agent-context/CLAUDE.md` to `/workspace/CLAUDE.md` at startup. It stays
short — just the facts the agent needs in context every turn:

```markdown
# Environment

You are Claude Code running inside the `claude` container of the git-proxy
example stack. You have TWO execution surfaces:

- **Git operations** (clone/fetch/push, PRs, CI, issues): go through git-proxy.
  See the `use-git-proxy` skill. Never talk to github.com directly.
- **Running code & service deps** (node, python, go, postgres, minio, …): use
  Docker, available via `DOCKER_HOST=tcp://docker:2375`. See the `use-docker`
  skill.

## Docker rules (read before you `docker run`)
- `/workspace` is the ONLY shared exchange point with workload containers.
  Files you want a container to read/write must live under `/workspace`; mount
  it as `-v /workspace:/work` and `-w /work`.
- Do NOT bind-mount any other path (e.g. `/opt`, `/tmp`, `/home/claude`) — the
  Docker daemon is in a separate container and cannot see your filesystem
  outside the shared `/workspace` volume. It will silently mount an empty path.
- Your working directory IS `/workspace`, so repo files are already shareable.
- The Docker daemon is rootless/isolated: it cannot reach git-proxy or its
  credentials. You will never receive the upstream GitHub PAT — do not attempt
  to obtain it.
```

### `use-docker` skill (on-demand procedures)

A new skill baked at `/opt/skills/use-docker/SKILL.md`, dropped into
`/workspace/.claude/skills/use-docker/SKILL.md` by the entrypoint (same mechanism
as `use-git-proxy`). Auto-loads when a task mentions running code or standing up
a service. It carries the procedural detail too long for `CLAUDE.md`:

- Canonical run pattern: `docker run --rm -v /workspace:/work -w /work <image> <cmd>`.
- Per-language one-liners: `node:22-alpine`, `python:3-alpine`, `golang:1-alpine`
  (run, build, test).
- Running a service dep: `docker run -d --name pg … postgres:16`, then connect
  from another workload container on the daemon's bridge network; deps are
  ephemeral unless given a named volume.
- The `/workspace`-only sharing rule repeated, with the "silently empty path"
  failure mode.
- A "prefer git-proxy for git; use Docker only for code/deps" reminder so the two
  surfaces do not get crossed.

### Entrypoint + Dockerfile changes

`entrypoint.sh`, after the existing skill-drop:
```sh
# Make the agent aware of its Docker environment (always-loaded context).
cp /opt/agent-context/CLAUDE.md /workspace/CLAUDE.md
# Bake the use-docker skill alongside use-git-proxy.
mkdir -p /workspace/.claude/skills/use-docker
cp /opt/skills/use-docker/SKILL.md /workspace/.claude/skills/use-docker/SKILL.md
```

`claude-code/Dockerfile` gains:
```dockerfile
COPY use-docker/SKILL.md /opt/skills/use-docker/SKILL.md
COPY agent-context/CLAUDE.md /opt/agent-context/CLAUDE.md
```
and `apk add docker-cli` (client only — no daemon in the agent image).

**Why two artifacts:** `CLAUDE.md` guarantees proactive awareness (always in
context — the agent knows it has Docker on turn one, without a skill trigger);
the skill carries the longer how-to without bloating every-turn context. This
matches how a real Claude Code project separates always-on context from
on-demand procedures.

## Security model (precise)

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
unnecessary here, and would add complexity for no threat-model gain.

## Files

- `example/github-claude-code/docker-compose.yml` — add `docker` service;
  `dinernet` network; `workspace` + `docker-cache` volumes; `claude` joins
  `dinernet`, `depends_on` the daemon, sets `DOCKER_HOST`; drop `claude-work`.
- `example/github-claude-code/claude-code/Dockerfile` — `apk add docker-cli`;
  `COPY` the `use-docker` skill and the `CLAUDE.md` template.
- `example/github-claude-code/claude-code/entrypoint.sh` — drop `CLAUDE.md` and
  the `use-docker` skill into `/workspace`.
- `example/github-claude-code/claude-code/use-docker/SKILL.md` (new) — procedures.
- `example/github-claude-code/claude-code/agent-context/CLAUDE.md` (new) —
  awareness template.
- `example/github-claude-code/README.md` — new "Docker for the agent (rootless
  DinD via sysbox)" section, the security statement, and troubleshooting.

**Unchanged:** `git-proxy` service, `config.yaml`, `credentials.yaml`,
`.env.example` (the daemon is internal; `DOCKER_HOST` is set in compose, not
`.env`), all Go code.

## Verification (manual; this is an example, not a testable unit)

On a Linux host with sysbox installed and verified (`docker info | grep -i
sysbox`):

1. `docker compose build && docker compose up` — the `docker` service becomes
   healthy; `claude` starts after it.
2. `docker compose exec claude sh` then:
   - `docker version` — client reaches the daemon (server section present).
   - `echo 'console.log("hi")' > /workspace/t.js && docker run --rm -v
     /workspace:/work -w /work node:22-alpine node t.js` → prints `hi` (proves
     `/workspace` sharing).
   - `docker run --rm python:3-alpine python -c 'print(1+1)'` → `2`.
   - `docker run --rm golang:1-alpine go version` → prints a Go version.
   - `docker run -d --name pg -e POSTGRES_PASSWORD=secret postgres:16` then
     `docker run --rm --link pg postgres:16 psql -h pg -U postgres -c '\l'` →
     lists databases (proves service deps work).
3. **Sharing boundary:** `docker run --rm -v /opt:/x alpine ls /x` → empty (the
   daemon cannot see the agent's `/opt`; only `/workspace` is shared).
4. **Network isolation:** from the daemon, `git-proxy` is unreachable — e.g.
   `docker compose exec docker sh -c 'wget -qO- http://git-proxy:8080/ || true'`
   fails to resolve (no route), confirming git-proxy is off `dinernet`.
5. **No-leak sanity:** `credentials.yaml` is not visible to the daemon —
   `docker compose exec docker ls /config.yaml /credentials.yaml` → not found.

## Out of scope

- TLS on the `dinernet` TCP connection (YAGNI — only `claude` can reach `dinernet`).
- Rootless-dockerd (`rootlesskit`) mode inside the sysbox container (no
  threat-model gain over sysbox's user-namespace isolation).
- Pre-pulling node/python/golang into the daemon cache (the daemon pulls on
  demand; outbound internet is already required by the stack).
- Supporting Docker Desktop (sysbox cannot run there). Documented as a hard
  prerequisite, not worked around.