#!/usr/bin/env bash
# Claude Code agent entrypoint for the git-proxy + GitHub example.
#
# 1. Route every github.com clone/fetch/push through git-proxy and attach the
#    agent Bearer. Claude Code shells out to `git`, so `insteadOf` + `extraHeader`
#    catch every git operation transparently — no need to teach the model a wrapper.
# 2. Drop the use-git-proxy skill into the project skill path so it auto-loads for
#    the broker (PR + CI) leg.
# 3. Run Claude Code headless (`-p`) with the prompt from compose `command`/$@.
set -eu

: "${AGENT_TOKEN:?AGENT_TOKEN must be set (see .env)}"
: "${GITHUB_REPO:?GITHUB_REPO must be set (see .env)}"

# Rewrite https://github.com/<anything> -> http://git-proxy:8080/<anything> so all
# git traffic flows through the proxy.
git config --global url."http://git-proxy:8080/".insteadOf "https://github.com/"
# Attach the agent Bearer to every request to the proxy host. (The proxy is plain
# HTTP on the compose network, so no TLS/sslVerify concerns.)
git config --global http."http://git-proxy:8080/".extraHeader "Authorization: Bearer ${AGENT_TOKEN}"

# Make the use-git-proxy skill available to this project workspace. Claude Code
# auto-loads skills from .claude/skills/ in the project (cwd) directory.
mkdir -p /workspace/.claude/skills/use-git-proxy
cp /opt/skills/use-git-proxy/SKILL.md /workspace/.claude/skills/use-git-proxy/SKILL.md

# The compose `command` (or `docker compose run --rm claude "<prompt>"`) becomes $@.
exec claude -p "$@"