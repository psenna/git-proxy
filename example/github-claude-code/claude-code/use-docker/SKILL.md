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
  `-v /home/node:/x`). The daemon will silently mount an **empty** directory and
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