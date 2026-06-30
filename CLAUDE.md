# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Read first, every session

Before starting any task, read these files — they define what this project is
and how it must be built:

- [`requirements.md`](./requirements.md) — goals, features, and v1 scope.
- [`PRINCIPLES.md`](./PRINCIPLES.md) — engineering principles. Binding.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — issue/PR workflow and Definition of Done.
- [`README.md`](./README.md) — project overview.

## What this project is

git-proxy is a policy-enforcing gateway between AI coding agents and upstream Git
repositories. It is written in Go. See `requirements.md` for the full picture.

## How to work here

- **One issue per PR.** Pick an issue from the tracker, implement it, open a PR
  that closes it. Do not bundle unrelated work.
- **TDD.** Red → Green → Commit. Pure logic (policy engine, rules) gets
  table-driven unit tests; protocol/end-to-end paths get integration tests with
  a real `git` client.
- **Extensibility by interface.** Integration seams live in `internal/port`.
  Add integrations by implementing an interface and registering — never edit the
  core orchestrator.
- **Fail closed.** Security decisions default to deny. The agent never receives
  upstream credentials.
- **CI is mandatory.** `go vet`, `golangci-lint`, `go build`, `go test`, and
  `govulncheck` must pass before merge. `main` is protected.
- **Conventional Commits.** One logical change per commit. Keep every commit
  green.

## Project layout (as it grows)

- `cmd/git-proxy/` — the binary.
- `internal/port/` — shared interfaces (the extensibility seams).
- `internal/*` — implementations (config, auth, policy, gitproto, gitx,
  upstream, transport, audit, secret, orchestrator).
- `test/integration/` — end-to-end tests driving a real `git` client.

## Status

Bootstrapping v1. Follow the issues in order; Issue #1 establishes the CI
pipeline that gates every later PR.