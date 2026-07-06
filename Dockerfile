# syntax=docker/dockerfile:1
#
# Multi-stage build for git-proxy.
#
# The runtime image MUST contain the `git` binary: the inspection mirror is a
# real bare clone driven by the git CLI (internal/gitx shells out via
# exec.CommandContext — see internal/gitx/mirror.go:111,125), not a pure Go
# library. A distroless/scratch runtime would break push enforcement (no
# mirror -> no ancestry walk -> every push fail-closes). Alpine + git +
# ca-certificates is the minimal runtime that satisfies that.

# ---- build stage ----
FROM golang:1.26-alpine AS build
# GOTOOLCHAIN=local: build with the image's Go 1.26 toolchain and never download
# another (the module declares go 1.25.0; 1.26 builds it natively). Matches the
# CI pin and keeps the build hermetic.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0
WORKDIR /src
# Cache deps first: copy only module files so `go mod download` is cached across
# source-only changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags='-s -w' -o /out/git-proxy ./cmd/git-proxy

# ---- runtime stage ----
FROM alpine:3.20
# git: inspection mirror + packfile assembly. ca-certificates: HTTPS upstreams.
# No other runtime deps.
RUN apk add --no-cache git ca-certificates && rm -rf /var/cache/apk/*
# Non-root runtime: a security gateway should not run as root. uid/gid 1000
# (the bind-mounted data dirs in the compose example are created host-side and
# owned by uid 1000 on a typical single-user Linux box / handled by Docker
# Desktop's VFS on macOS; see deploy/docker/README.md if your host uid differs).
RUN adduser -D -u 1000 -G users gitproxy
COPY --from=build /out/git-proxy /usr/local/bin/git-proxy
USER gitproxy
EXPOSE 8080
ENTRYPOINT ["git-proxy"]
# Default config path matches the compose example bind-mount.
CMD ["-config", "/config.yaml"]