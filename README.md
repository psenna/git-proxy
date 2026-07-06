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

> **Status:** v1 shipped. git-proxy enforces push rules (history-protect,
> branch-pattern, commit-message, path-acl, secret-scan), read protection
> (object withholding + on-demand blob denial), attributable audit, dry-run
> mode, violation alerts, and both HTTP and SSH transports. See
> [`docs/architecture.md`](./docs/architecture.md) for the shipped design and
> the [issues](https://github.com/psenna/git-proxy/issues) for the roadmap.

## Quickstart

Build the binary:

```sh
go build -o git-proxy ./cmd/git-proxy
# or: go build ./...
```

Write a minimal `config.yaml` (grounded in `internal/config`; every field below
is real — see `docs/architecture.md` for the decision flows):

```yaml
listen: "127.0.0.1:8080"
upstream:
  kind: plain                       # plain = smart-HTTP git (default); "github" = GitHub skeleton
  url: "https://git.example.com/upstream.git"
auth:
  tokens:
    "agent-token-1": "agent-1"       # bearer token -> agent id (audit attribute)
policy:
  mode: first_deny                  # or collect_all (report every violation, not just the first)
  mirror:
    dir: "/tmp/git-proxy-mirror"    # required when any rule is on (inspection-mirror cache root)
  rules:
    history_protect:
      enabled: true
      params: { refs: ["refs/heads/main"] }      # block force-push / rewrite of main
    branch_pattern:
      enabled: true
      params: { allow: ["refs/heads/main", "refs/heads/feat/*"] }  # only these refs may be pushed
    secret_scan:
      enabled: true                 # redacted reasons; the matched secret never reaches the agent/audit/alert
  read:
    deny: ["secrets/**"]            # withhold secrets/ blobs from fetch (use --filter=blob:none to clone)
  # dry_run: true                   # forward a clean policy-deny instead of blocking; audit records deny + dry_run
audit:
  file: "/tmp/git-proxy/audit.jsonl"  # append-only JSONL; omit to disable
# alerts:
#   webhook: "https://hooks.example.com/git-proxy"   # omit to disable; malformed URL fails fast at startup
# ssh:
#   listen: "127.0.0.1:2222"
#   host_key: "/path/to/ssh_host_ed25519_key"          # omit -> ephemeral key (dev/test only)
#   authorized_keys:
#     agent-1: "ssh-ed25519 AAAA...comment"
```

Run it:

```sh
./git-proxy -config config.yaml
```

Point an agent's git at the proxy (the agent uses the bearer token; the proxy
holds the upstream credentials):

```sh
git -c http.extraheader="Authorization: Bearer agent-token-1" \
    -c "url.https://127.0.0.1:8080/.insteadOf=https://git.example.com/" \
    clone https://git.example.com/upstream.git
# For a read-protected repo, partial-clone so the proxy can withhold denied blobs:
#   git clone --filter=blob:none https://git.example.com/upstream.git
```

A clean fast-forward push to `feat/*` is forwarded; a `--force` push to `main`
is blocked with a structured `report-status` reason and the upstream is left
unchanged; a push containing a secret is denied; and a `--filter=blob:none`
clone of a repo with `secrets/**` read-denied withholds the secret blobs. Every
decision is recorded in the audit file; every deny fires an alert. The agent
never sees the upstream credentials.

## Deployment

A multi-stage `Dockerfile` builds a minimal runtime image (Alpine + `git` +
`ca-certificates`, non-root) — the inspection mirror needs the `git` binary on
`PATH`, so a distroless image won't work:

```sh
docker build -t git-proxy .
docker run --rm -p 8080:8080 -v "$PWD/config.yaml:/config.yaml:ro" git-proxy
```

The fastest way to see enforcement against a real upstream is the
**Docker Compose + Gitea** example — `docker compose up` runs git-proxy in
front of a local self-hosted git server, no external account required:

```sh
cd deploy/docker
mkdir -p data/mirror data/audit
docker compose up -d --build
```

See [`docs/deploy-docker.md`](./docs/deploy-docker.md) for the full walkthrough
(topology, one-time Gitea setup, the enforcement flow, audit inspection, and
production hardening). A documentation site (this README + the `docs/` pages)
is published to GitHub Pages from the `/docs` folder — see the deploy guide's
"Publishing this docs site" section.

## Documentation

- [`requirements.md`](./requirements.md) — goals, features, and v1 scope.
- [`docs/architecture.md`](./docs/architecture.md) — the v1 shipped design
  (layer diagram, decision flows, seams, scope, milestone table).
- [`docs/extensibility.md`](./docs/extensibility.md) — how to add rules, SCM
  adapters, frontends, auth, secret scanners, credential stores, and sinks.
- [`docs/deploy-docker.md`](./docs/deploy-docker.md) — run git-proxy in front of
  a local Gitea git server with Docker Compose (fastest way to try it).
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