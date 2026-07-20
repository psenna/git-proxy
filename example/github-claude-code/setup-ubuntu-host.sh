#!/usr/bin/env bash
#
# setup-ubuntu-host.sh — configure an Ubuntu Linux host to run the
# example/github-claude-code stack (which uses a rootless Docker-in-Docker
# daemon under the sysbox-ce runtime: `runtime: sysbox-runc` in docker-compose.yml).
#
# What this does:
#   1. Installs Docker Engine + the compose plugin NATIVELY via apt (sysbox does
#      not work with snap Docker — it refuses, and the daemon can't see the runtime).
#   2. Installs jq (required by the sysbox installer).
#   3. Installs sysbox-ce from the official Nestybox .deb. The installer registers
#      the `sysbox-runc` runtime with Docker (/etc/docker/daemon.json) and SIGHUPs
#      dockerd. It does NOT make sysbox the default runtime (we don't want that —
#      only the `docker` dind service uses it; git-proxy and claude use default runc).
#   4. Verifies: sysbox service is active, `docker info` lists `sysbox-runc`, and a
#      `docker run --runtime=sysbox-runc` smoke test works.
#
# Prerequisites (hard, per sysbox-ce docs):
#   - Ubuntu (or Debian) on amd64 or arm64, with systemd as the process manager
#     (the default on Ubuntu server/desktop).
#   - Kernel >= 4.18 (any modern Ubuntu is fine). shiftfs is included in Ubuntu
#     kernels; for kernel >= 6.3 it is not even needed (ID-mapped mounts are used).
#   - Run with sudo (root).
#
# Re-running is safe: it skips Docker if already installed natively, skips sysbox
# if `sysbox-runc` is already registered, and only downloads/installs what's missing.
#
# Usage:
#   sudo bash example/github-claude-code/setup-ubuntu-host.sh
#
# Reference: https://github.com/nestybox/sysbox/blob/master/docs/user-guide/install-package.md

set -euo pipefail

# ---- tunables ---------------------------------------------------------------
SYSBOX_VER="0.7.0"   # sysbox-ce release; bump here when a newer version is out.
# ----------------------------------------------------------------------------

log()  { printf '\n\033[1;34m[setup]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[setup] error:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- root + OS + systemd checks --------------------------------------------
[[ $EUID -eq 0 ]] || die "must be run as root (try: sudo bash $0)."

if [[ ! -r /etc/os-release ]]; then
  die "no /etc/os-release — this doesn't look like a supported Linux distro."
fi
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ok "OS: ${PRETTY_NAME:-$ID} (supported by sysbox-ce)" ;;
  *) die "OS is '${ID:-unknown}' — sysbox-ce packages are for Ubuntu/Debian. See the sysbox distro-compat docs for other distros." ;;
esac

[[ -d /run/systemd/system ]] || die "systemd is not the process manager; sysbox requires systemd."

ARCH="$(dpkg --print-architecture 2>/dev/null || die 'cannot detect architecture')"
case "$ARCH" in
  amd64|arm64) ok "arch: $ARCH (sysbox-ce has a .deb for it)" ;;
  *) die "arch '$ARCH' has no sysbox-ce .deb (only amd64/arm64)." ;;
esac

KVER="$(uname -r | cut -d. -f1-2)"
KMAJ="${KVER%%.*}"; KMIN="${KVER#*.}"; KMIN="${KMIN%%.*}"
if [[ $KMAJ -lt 4 || ( $KMAJ -eq 4 && $KMIN -lt 18 ) ]]; then
  die "kernel $(uname -r) is older than 4.18; sysbox requires >= 4.18."
fi
ok "kernel: $(uname -r) (>= 4.18)"

# ---- 1. Docker Engine + compose plugin (native apt, NOT snap) ---------------
install_docker() {
  log "Installing Docker Engine + compose plugin (native apt)…"
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  CODENAME="${VERSION_CODENAME:-}"
  [[ -n "$CODENAME" ]] || die "could not determine distro codename from /etc/os-release."
  echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io \
                    docker-buildx-plugin docker-compose-plugin
}

# Refuse snap Docker outright — sysbox cannot work with it.
if command -v docker >/dev/null 2>&1; then
  DOCKER_PATH="$(command -v docker)"
  if [[ "$DOCKER_PATH" == /snap/bin/* ]]; then
    die "Docker is installed as a snap ($DOCKER_PATH). sysbox does not support snap Docker. Remove it first: 'sudo snap remove docker', then re-run this script."
  fi
fi

if docker version >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  ok "Docker Engine + compose plugin already installed ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo present))."
else
  install_docker
  ok "Docker Engine + compose plugin installed."
fi

# Ensure the docker group exists and the calling user is in it (so they can run
# docker without sudo after this script). $SUDO_USER is the user who ran sudo.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  getent group docker >/dev/null 2>&1 || groupadd -f docker
  if ! id -nG "$SUDO_USER" | grep -qw docker; then
    usermod -aG docker "$SUDO_USER"
    ok "added '$SUDO_USER' to the docker group (log out/in or 'newgrp docker' to use docker without sudo)."
  fi
fi

# ---- 2. jq (sysbox installer dependency) -----------------------------------
if command -v jq >/dev/null 2>&1; then
  ok "jq already installed."
else
  log "Installing jq…"
  apt-get update -y >/dev/null
  apt-get install -y jq
  ok "jq installed."
fi

# ---- 3. sysbox-ce -----------------------------------------------------------
# Idempotent: skip if docker already knows the sysbox-runc runtime.
if docker info 2>/dev/null | grep -qw sysbox-runc; then
  ok "sysbox-ce already installed (docker sees the 'sysbox-runc' runtime)."
else
  log "Installing sysbox-ce v${SYSBOX_VER}…"
  # Uninstall any prior sysbox first (recommended by the upstream install doc).
  if dpkg -s sysbox-ce >/dev/null 2>&1; then
    apt-get purge -y sysbox-ce
  fi

  DEB="sysbox-ce_${SYSBOX_VER}-0.linux_${ARCH}.deb"
  URL="https://downloads.nestybox.com/sysbox/releases/v${SYSBOX_VER}/${DEB}"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  log "Downloading $URL"
  if ! curl -fsSL "$URL" -o "$TMP/$DEB"; then
    cat >&2 <<EOF

  Could not download the .deb from downloads.nestybox.com
  (there is a known intermittent SSL issue with that host — see
  https://github.com/nestybox/sysbox/issues/855).

  Download it manually from the sysbox-ce GitHub releases and install it:
    https://github.com/nestybox/sysbox/releases/tag/v${SYSBOX_VER}
    sudo apt-get install -y jq
    sudo apt-get install -y ./${DEB}
  then re-run this script to verify.
EOF
    die "sysbox-ce .deb download failed."
  fi
  ok "downloaded $DEB"

  log "Installing $DEB (this may restart Docker — save any running containers first)…"
  apt-get install -y "$TMP/$DEB"
  ok "sysbox-ce installed."

  # The installer SIGHUPs dockerd to pick up the runtime; if that didn't take,
  # an explicit restart forces it.
  if ! docker info 2>/dev/null | grep -qw sysbox-runc; then
    log "Docker doesn't see 'sysbox-runc' yet — restarting dockerd…"
    systemctl restart docker
    sleep 2
  fi
fi

# Ensure the sysbox systemd service is active.
if ! systemctl is-active --quiet sysbox; then
  log "Starting the sysbox service…"
  systemctl enable --now sysbox
fi

# ---- 4. verify --------------------------------------------------------------
log "Verifying…"
systemctl is-active --quiet sysbox && ok "sysbox service: active" \
  || die "sysbox service is not active (try: systemctl status sysbox -n20)."

if docker info 2>/dev/null | grep -qw sysbox-runc; then
  ok "docker recognizes the 'sysbox-runc' runtime."
else
  die "docker does not list 'sysbox-runc' in its runtimes (try: docker info | grep -i runtime)."
fi

log "Smoke test: docker run --runtime=sysbox-runc --rm alpine echo ok"
if docker run --runtime=sysbox-runc --rm alpine echo ok | grep -qx ok; then
  ok "sysbox-runc runtime works."
else
  die "sysbox-runc smoke test failed."
fi

# ---- next steps -------------------------------------------------------------
cat <<EOF

\033[1;32m[setup] host is ready.\033[0m

Next, from the repo root on this host:
  cd example/github-claude-code
  cp .env.example .env       # then edit .env: AGENT_TOKEN, GITHUB_REPO, OLLAMA_API_KEY
  docker compose build
  docker compose up -d
  docker compose ps          # the 'docker' service must be healthy; claude starts after it

Then run the E2E checks (see the README "Docker for the agent" section and the
verification runbook), e.g.:
  docker compose exec claude sh -c 'docker run --rm -v /workspace:/work -w /work node:22-alpine node -e "console.log(42)"'

EOF