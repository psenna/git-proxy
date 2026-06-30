# git-proxy

A policy-enforcing gateway that sits between AI coding agents and upstream Git
repositories. It terminates the agent's git traffic (over HTTPS or SSH),
authenticates the agent with scoped credentials, and forwards operations to the
real repository — inspecting and gating every `clone`, `fetch`, `push`, and
branch-flow action along the way.

All interactions between the agent and the SCM go through the proxy. The proxy
speaks the native git protocols (smart HTTP and SSH) and is transparent to the
agent: a one-line `insteadOf` redirect is all that's needed on the client side.
The agent never sees the upstream credentials — the proxy holds them — and never
sees files it isn't allowed to read.

## Goals

Two goals, equal weight:

1. **Security gateway** — protect the repository from destructive or leaky agent
   behavior: force-push, history rewrites, pushes to protected branches, and
   secret exfiltration via `fetch`.
2. **Least-privilege access** — scope what each agent can read and write at file
   granularity, so an agent gets just enough git access to do its job and nothing
   more.

## Scope

Provider-agnostic by design. v1 talks to any plain git server over HTTP/SSH. The
enforcement layer is a pluggable policy engine, so SCM-specific capabilities
(pull requests, reviews, branch-protection APIs) can be layered in later without
reworking the core. All enforcement happens **at the proxy** — the proxy is the
single choke point, independent of whatever the upstream host does or doesn't
support.

## Features

### Auth & identity

- Agent authenticates with scoped per-agent tokens.
- Proxy holds upstream credentials in a vault; the agent never receives them.
- Per-agent policy profiles (different agents → different rules).

### Transport

- HTTPS smart-HTTP and SSH on agent↔proxy; proxy→upstream over HTTP or SSH.
- Transparent to the agent via `git config url.<proxy>.insteadOf <upstream>`.

### Read protection (v1 core)

- Filter `fetch`/`clone` by path: denied paths never reach the agent's context.
- gitignore-style syntax: `deny .env*`, `deny secrets/**`, `read-only docs/`.
- Per-agent redaction vs. outright denial modes.

### Rules on push

- Protect git history: block force-push, rebase, amend, and ref deletion.
- Branch-name patterns (`feat/*`, `fix/*`); block direct push to protected
  branches (`main`, `release/*`).
- Commit-message rules (conventional-commits, required issue ref, sign-off).
- File read/write ACL with gitignore-style syntax (same engine as read rules).
- Secret/blob heuristics: block high-entropy or sensitive file types in a push.

### Rules on PR / branch flow (enforced at the proxy)

With enforcement at the proxy and a plain-git upstream, there is no real PR
object to attach rules to. PR rules are therefore enforced as **branch-flow
rules at push time**: protect the flow by blocking direct pushes to protected
branches and by enforcing branch/commit patterns. When a GitHub/GitLab SCM
adapter is added later, these same rules graduate to act on actual PR objects.

- Branch-flow protection: no direct push to protected branches → must go through
  a feature branch (PR implied by the flow, not via an upstream API).
- Rule-based gates on the push: required paths untouched, scope limits, blocked
  file combinations.

### Audit & ops

- Full audit log of every op, tagged with agent identity and verdict.
- Dry-run / observe mode vs. enforce mode.
- Alerts on violations.
- Policy-as-code config (YAML), versioned, reloadable.
- Pluggable SCM layer so GitHub/GitLab PR & branch-protection APIs can be added
  later.

## Out of v1 scope (future)

- **Scoped & TTL credentials**: task-bound tokens scoped to a single task/branch
  and auto-revoked when the task ends; ephemeral auto-created feature branches
  with a TTL, deleted on merge or expiry.