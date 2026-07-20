# syntax=docker/dockerfile:1
#
# The agent image: Claude Code (the official npm CLI) on Node, with git so it can
# clone/fetch/push. Backed by Ollama Cloud at runtime (configured via env in
# docker-compose.yml, not baked in — the API key is a secret).
#
# The use-git-proxy skill is baked into the image so the entrypoint can drop it
# into the project's .claude/skills/ at startup (reliable auto-load for the broker
# leg). The use-docker skill + CLAUDE.md are baked the same way so the agent is
# aware of its rootless DinD environment (see docker-compose.yml `docker` service).

FROM node:22-alpine

# git: clone/fetch/push. ca-certificates: HTTPS to github.com and ollama.com.
# bash: entrypoint. curl: the broker leg (the skill drives the broker with curl).
# docker-cli: the client only (no daemon) — talks to the rootless DinD daemon in
# the separate `docker` service via DOCKER_HOST=tcp://docker:2375.
RUN apk add --no-cache git ca-certificates bash curl docker-cli && rm -rf /var/cache/apk/* && \
    npm install -g @anthropic-ai/claude-code

# Non-root runtime: node:22-alpine already ships a `node` user with uid 1000
# (HOME=/home/node), matching git-proxy's uid 1000 so the shared workspace
# volume is read/writable by both. We reuse it instead of creating one —
# `adduser -D -u 1000` would collide with that built-in user. (USER node is set
# at the end so the COPY/chmod steps still run as root.)

# Bake the skills + the always-loaded CLAUDE.md; the entrypoint copies them into
# /workspace/.claude/skills/ and /workspace/CLAUDE.md at startup.
COPY use-git-proxy/SKILL.md /opt/skills/use-git-proxy/SKILL.md
COPY use-docker/SKILL.md /opt/skills/use-docker/SKILL.md
COPY agent-context/CLAUDE.md /opt/agent-context/CLAUDE.md

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER node
WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]