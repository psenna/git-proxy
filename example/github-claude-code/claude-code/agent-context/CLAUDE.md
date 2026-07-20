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
- Do NOT bind-mount any other path (e.g. `/opt`, `/tmp`, `/home/node`) — the
  Docker daemon is in a separate container and cannot see your filesystem outside
  the shared `/workspace` volume. It will silently mount an empty path.
- Your working directory IS `/workspace`, so repo files are already shareable.
- The Docker daemon is rootless/isolated: it cannot reach git-proxy or its
  credentials. You will never receive the upstream GitHub PAT — do not attempt to
  obtain it.