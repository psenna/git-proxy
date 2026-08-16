---
layout: default
title: Helm Chart
---

# Helm Chart

This page covers installing git-proxy on a Kubernetes cluster using the Helm
chart at
[`deploy/helm/git-proxy/`](https://github.com/psenna/git-proxy/tree/main/deploy/helm/git-proxy).
It runs the same policy-enforcing gateway described elsewhere on this site,
managed as a Deployment with a ConfigMap for non-secret config and Secrets for
everything sensitive.

For exhaustive detail (the full values reference, the Secret
fragment-assembly mechanism, ingress tuning, persistence, multi-replica
constraints, secret rotation) see the chart's own README:
**[deploy/helm/git-proxy/README.md](https://github.com/psenna/git-proxy/tree/main/deploy/helm/git-proxy)**.
This page is the short version.

## Prerequisites

- A Kubernetes cluster (any conformant distribution).
- Helm 3.8+ (needed for OCI registry support).

## Install from OCI

Chart releases are published to GHCR as an OCI artifact. Pick a published
version from the [release notes](https://github.com/psenna/git-proxy/releases)
or the [GHCR packages page](https://github.com/psenna/git-proxy/pkgs/container/charts%2Fgit-proxy)
— there is no `:latest` chart version:

```sh
helm install git-proxy oci://ghcr.io/psenna/charts/git-proxy --version <chart-version>
```

## Create the required Secrets

git-proxy's sensitive config (bearer tokens, upstream credentials, the SSH
host key) has no environment-variable override, so it can only reach the
proxy through a Kubernetes Secret — never through `values.yaml` or the
ConfigMap. At minimum, create the auth Secret:

```sh
cat > auth.yaml <<'EOF'
auth:
  tokens:
    "<bearer-token>": agent-1
EOF

kubectl create secret generic git-proxy-auth --from-file=auth.yaml=./auth.yaml
```

then reference it with `config.auth.existingSecret=git-proxy-auth`. Without
it, the proxy runs as an **open relay**. Depending on your setup you may also
need:

- An upstream-credentials Secret (`config.upstream.credentials.existingSecret`)
  if the upstream requires auth.
- An SSH host-key Secret (`config.ssh.hostKey.existingSecret`) if you enable
  the SSH frontend — see the chart README's "SSH host key" section for the
  `ssh-keygen` walkthrough.

The chart never creates or manages Secret content itself; see the chart
README's "Secrets & the fragment-assembly mechanism" section for the full
mechanism and field-by-field table.

## The three frontends, briefly

- **git-HTTP** — always on, no health endpoint of its own.
- **Broker** (agent-facing REST API for PRs/CI/issues) — opt-in via
  `config.broker.enabled`, requires `config.upstream.kind: github`.
- **SSH** — opt-in via `config.ssh.enabled`, requires `config.ssh.authorizedKeys`.

See the chart README's "The three frontends" section for the full table and
the broker's GitHub-only requirement.

## Smoke-test the install

```sh
helm test <release>
```

This runs a `helm test` hook pod that checks the git-HTTP frontend answers
(401/404) and, if the broker is enabled, that `/healthz` returns
`{"status":"ok"}`.

## Full documentation

The chart README covers everything this page doesn't: the Secret
fragment-assembly mechanism in full, ingress tuning for large git pushes,
`persistence.mirror` vs `persistence.audit`, why multiple replicas are
blocked by default, Secret rotation, and the full values reference.

**[deploy/helm/git-proxy/README.md](https://github.com/psenna/git-proxy/tree/main/deploy/helm/git-proxy)**
