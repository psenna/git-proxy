# Engineering Principles

These principles govern every change to git-proxy. Reviewers reject PRs that
violate them; implementing agents must internalize them before starting an issue.

## 1. Small, testable parts

- Every capability is a package with a narrow exported API and its own tests.
- A change should be reviewable in one sitting. If a task is too big to test in
  isolation, split it.
- Prefer focused files with one clear responsibility over large files that do
  many things.

## 2. Extensibility by interface

- All integration seams live in `internal/port` as interfaces: `Transport`,
  `Authenticator`, `Upstream`, `Rule`, `SecretScanner`, `AuditSink`,
  `CredentialStore`.
- New integrations (a rule, an SCM provider, a frontend, an auth method) are
  added by implementing an interface and registering it — never by editing the
  core orchestrator.
- Registries are name → factory; config selects implementations by name.

## 3. Test-driven development

- Write the failing test first, watch it fail, implement the minimum to pass,
  then commit. Red, green, commit — frequently.
- The policy engine and rules are pure functions: fast, deterministic, no I/O,
  table-driven. No git binary needed to unit-test them.
- Protocol layers are tested against recorded pkt-line fixtures (golden
  packets).

## 4. Real git on the integration-test path

- Integration tests drive a real `git` client through the proxy against a real
  upstream in `t.TempDir`. No protocol mocks on the end-to-end path.
- The integration harness is born at the passthrough milestone (Issue #2) and
  every later milestone extends it.

## 5. Fail closed

- Security decisions default to **deny**. An unknown rule, a missing config, or
  an evaluation error blocks the operation and is logged — never silently
  allowed.
- The agent never receives upstream credentials. The proxy holds them.

## 6. DRY, YAGNI

- Don't add capability ahead of a requirement. Don't generalize prematurely.
- Don't reimplement what go-git or the `git` binary already do correctly — wrap
  them behind an interface instead.

## 7. Frequent commits, one concern each

- One logical change per commit. Conventional Commit messages
  (`feat:`, `test:`, `chore:`, `docs:`, `refactor:`).
- Every commit keeps the build and tests green.

## 8. Honest status

- Don't claim a feature works without a passing test that proves it.
- If a step was skipped or a test is missing, say so in the PR — don't hedge.