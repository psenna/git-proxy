# Contributing

This guide is for the agents and humans implementing git-proxy. Read
[`PRINCIPLES.md`](./PRINCIPLES.md) first — it is binding.

## Issue and PR workflow

- **One issue per PR.** Each issue in the tracker maps to one PR that closes it.
- Work from a branch named after the issue: `ci/1-quality-pipeline`,
  `feat/2-passthrough-skeleton`, etc.
- Open a PR against `main`. The CI pipeline (set up in Issue #1) must be green
  before merge.
- `main` is protected: direct pushes are rejected; PRs require review approval
  and passing CI.
- Reference the issue in the PR body (`Closes #N`).

## Definition of Done for every issue

1. All acceptance criteria in the issue are satisfied.
2. New code is covered by unit tests (pure logic) and/or integration tests
   (protocol/end-to-end paths).
3. `go vet ./...`, `golangci-lint run`, `go build ./...`, and `go test ./...` all
   pass locally.
4. The change follows the principles: small parts, interface-based extension,
  fail-closed where security-relevant.
5. The PR is reviewed and CI is green before merge.
6. The PR closes its issue.

## TDD cycle (per task within an issue)

1. Write the failing test.
2. Run it; confirm it fails for the right reason.
3. Implement the minimum to pass.
4. Run the tests; confirm green.
5. Commit (Red → Green → Commit).

## Commit messages

Conventional Commits:

- `feat: add history-protect rule`
- `test: cover force-push rejection`
- `chore: configure golangci-lint`
- `docs: expand README`
- `refactor: extract pkt-line codec`

## Layout

See the per-issue file lists. In short: `cmd/git-proxy` for the binary,
`internal/port` for interfaces, `internal/*` for implementations,
`test/integration` for end-to-end tests with a real `git` client.

## Adding an integration

| To add | Do |
|---|---|
| A policy rule | new file in `internal/policy/rules`, implement `Rule`, `init()` register, unit tests, reference by name in config. |
| An SCM provider | new package under `internal/upstream`, implement `Upstream` (+ optional `PRSupport`), `init()` register. |
| A frontend | new package under `internal/transport`, implement `Transport`, register. |
| An auth method | implement `Authenticator`, register. |
| A secret scanner | implement `SecretScanner`, register. |
| A credential store | implement `CredentialStore`, register. |