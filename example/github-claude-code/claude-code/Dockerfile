# syntax=docker/dockerfile:1
#
# The agent image: Claude Code (the official npm CLI) on Node, with git so it can
# clone/fetch/push. Backed by Ollama Cloud at runtime (configured via env in
# docker-compose.yml, not baked in — the API key is a secret).
#
# The use-git-proxy skill is baked into the image so the entrypoint can drop it
# into the project's .claude/skills/ at startup (reliable auto-load for the broker
# leg).

FROM node:22-alpine

# git: clone/fetch/push. ca-certificates: HTTPS to github.com and ollama.com.
# bash: entrypoint. curl: the broker leg (the skill drives the broker with curl).
RUN apk add --no-cache git ca-certificates bash curl && rm -rf /var/cache/apk/* && \
    npm install -g @anthropic-ai/claude-code

# Non-root runtime, matching git-proxy's uid 1000.
RUN adduser -D -u 1000 -G users claude

# Bake the skill; the entrypoint copies it into /workspace/.claude/skills/.
COPY use-git-proxy/SKILL.md /opt/skills/use-git-proxy/SKILL.md

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER claude
WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]