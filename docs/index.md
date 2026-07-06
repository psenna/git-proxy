---
layout: home
title: git-proxy
---

# git-proxy

A policy-enforcing gateway between AI coding agents and upstream Git
repositories. It terminates the agent's git traffic (over HTTPS or SSH),
authenticates the agent with scoped credentials, and inspects and gates every
`clone`, `fetch`, `push`, and branch-flow action before it reaches the real
repository.

Two equal goals:

1. **Security gateway** — protect the repository from destructive or leaky agent
   behavior: force-push, history rewrites, pushes to protected branches, and
   secret exfiltration via `fetch`.
2. **Least-privilege access** — scope what each agent can read and write at file
   granularity, so an agent gets just enough git access to do its job and nothing
   more.

> **Status:** v1 shipped. git-proxy enforces push rules (history-protect,
> branch-pattern, commit-message, path-acl, secret-scan), read protection
> (object withholding + on-demand blob denial), attributable audit, dry-run
> mode, violation alerts, and both HTTP and SSH transports.

## Try it locally

The fastest way to see git-proxy enforce policy is the
[Docker Compose + Gitea](./deploy-docker/) example — `docker compose up` gives
you a working policy gateway in front of a real git server on localhost, no
external account required:

```sh
cd deploy/docker
mkdir -p data/mirror data/audit
docker compose up -d --build
# then the one-time Gitea setup + clone/push through the proxy — see
# deploy/docker/README.md
```

## Build from source

```sh
go build -o git-proxy ./cmd/git-proxy
./git-proxy -config config.yaml
```

Point an agent's git at the proxy (the agent uses a Bearer token; the proxy holds
the upstream credentials):

```sh
git -c http.extraheader="Authorization: Bearer agent-token-1" \
    -c "url.https://127.0.0.1:8080/.insteadOf=https://git.example.com/" \
    clone https://git.example.com/upstream.git
# Read-protected repo? Partial-clone so the proxy can withhold denied blobs:
#   git clone --filter=blob:none https://git.example.com/upstream.git
```

## Documentation

- [Architecture](./architecture/) — the v1 shipped design: layer diagram, push
  and fetch decision flows, the seams and registries, the pure fail-closed
  engine, dry-run, audit/alert, and the milestone table.
- [Extensibility](./extensibility/) — how to add rules, SCM adapters, frontends,
  auth, secret scanners, credential stores, and sinks.
- [Docker Compose + Gitea](./deploy-docker/) — run a full policy gateway against
  a local self-hosted git server.

Source and issues: [github.com/psenna/git-proxy](https://github.com/psenna/git-proxy).