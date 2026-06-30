# git-proxy

A policy-enforcing gateway that sits between AI coding agents and upstream Git
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

> **Status:** bootstrapping v1. No runnable code yet — see the
> [issues](https://github.com/psenna/git-proxy/issues) and
> [`requirements.md`](./requirements.md).

## Documentation

- [`requirements.md`](./requirements.md) — goals, features, and v1 scope.
- [`PRINCIPLES.md`](./PRINCIPLES.md) — engineering principles every change must
  follow.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — issue and PR workflow for the agents
  and humans implementing git-proxy.

## Why

AI coding agents are powerful but can rewrite history, force-push, leak secrets
via `fetch`, or push straight to `main`. git-proxy gives teams a deterministic,
auditable policy layer so an agent can be granted just enough git access to do
its job — and no more. The agent never sees the upstream credentials and never
sees files it isn't allowed to read.