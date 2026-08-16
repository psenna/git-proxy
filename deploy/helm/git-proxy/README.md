# git-proxy

A Helm chart for [git-proxy](https://github.com/psenna/git-proxy), a
policy-enforcing gateway between AI coding agents and upstream Git
repositories.

## Quick start

git-proxy's Bearer-token → agent-name map (`auth.tokens`) lives inside
`config.yaml` with no environment-variable override, so it can never be set
via `values.yaml` — it has to come from a Secret. Create the auth fragment
first:

```sh
cat > auth.yaml <<'EOF'
auth:
  tokens:
    "<bearer-token>": agent-1
EOF

kubectl create secret generic git-proxy-auth --from-file=auth.yaml=./auth.yaml
```

Then install, pointing `config.upstream.url` at a real upstream git server:

```sh
helm install git-proxy deploy/helm/git-proxy \
  --set config.upstream.url=https://github.com \
  --set config.auth.existingSecret=git-proxy-auth
```

Without `config.auth.existingSecret`, the proxy starts as an **open relay** —
see the warning below and in the post-install `NOTES.txt`.

## Secrets & the fragment-assembly mechanism

**Why:** several parts of git-proxy's `config.yaml` are sensitive (bearer
tokens, upstream credentials, an SSH host private key) and none of them have
an environment-variable override in the binary — the only way to supply them
is inside the config file itself. A ConfigMap is not an acceptable place for
that, so this chart never puts secret material in the rendered ConfigMap
(`templates/configmap.yaml`); it only ever composes secret content from
Kubernetes Secrets, at pod-start time, inside the pod.

**How:** every install runs an `assemble-config` init container (the same
image as the app) that concatenates the ConfigMap's base config plus zero or
more Secret-sourced fragments into a single file at
`/run/git-proxy/config.yaml`, on a `Memory`-backed `emptyDir`. The main
container always starts with `-config /run/git-proxy/config.yaml` — whether
or not any fragment is configured, so there's exactly one code path.

Fragment table (see `templates/deployment.yaml` for the exact mounts):

| Values field | Secret key (default) | Mounted at | Assembled into config.yaml? |
| --- | --- | --- | --- |
| `config.auth.existingSecret` | `auth.yaml` (`config.auth.key`) | `/etc/git-proxy/auth/auth.yaml` | Yes — concatenated as a top-level `auth:` fragment. |
| `config.upstream.credentials.existingSecret` | `credentials.yaml` (`config.upstream.credentials.key`) | `/etc/git-proxy/credentials/credentials.yaml` | No — referenced by path via `credentials_file` in the base config, not concatenated. A whole separate file, not a YAML fragment. |
| `config.issueUpstream.credentials.existingSecret` | `credentials.yaml` (`config.issueUpstream.credentials.key`) | `/etc/git-proxy/issue-credentials/credentials.yaml` | No — same as above, own `credentials_file`. If unset but `config.upstream.credentials.existingSecret` is set, `issue_upstream.credentials_file` falls back to the SCM credentials path (the single-PAT GitHub case). |
| `config.ssh.hostKey.existingSecret` | `host_key` (`config.ssh.hostKey.key`) | `/etc/git-proxy/ssh/host_key` | No — a raw PEM private key file, referenced by path, not YAML. |
| `extraConfigFragments[].existingSecret` / `.key` | your choice | `/etc/git-proxy/fragments/<index>/fragment.yaml` | Yes — concatenated in list order, after `auth:`. |

`extraConfigFragments` is the generic escape hatch for any other sensitive
top-level `config.yaml` key (e.g. `alerts.webhook` if it embeds a token). Each
fragment must supply a **top-level key the base ConfigMap does not already
render** — `listen`, `upstream`, `issue_upstream`, `repos`, `public_repos`,
`policy`, `ssh`, `audit`, `alerts`, and `broker` are all rendered by the
ConfigMap, so a fragment duplicating one of those (or `auth`, which the auth
fragment owns) produces a YAML parse error when concatenated. The chart never
creates or manages Secret content itself — only ever references
pre-existing Secrets by name.

## The three frontends

| Frontend | Enabled by | Health check | Notes |
| --- | --- | --- | --- |
| git-HTTP | always on | none of its own — `/` returns 401/404, not a dedicated health route | Readiness/liveness default to a TCP check on `http-git` for this reason. |
| Broker (REST API: PRs, CI status, issues) | `config.broker.enabled` | `GET /healthz` → `{"status":"ok"}` | **Requires `config.upstream.kind: github`** — any other kind is a guaranteed startup crash-loop, and the chart enforces this at render time (`templates/_validations.tpl`). |
| SSH | `config.ssh.enabled` | none | Needs `config.ssh.authorizedKeys` (non-empty). Strongly recommended: a real host-key Secret — an ephemeral key changes every restart. |

## SSH host key

Generate a stable ed25519 host key and store it in a Secret:

```sh
ssh-keygen -t ed25519 -N '' -f host_key
kubectl create secret generic git-proxy-ssh-hostkey --from-file=host_key=./host_key
```

```yaml
config:
  ssh:
    enabled: true
    hostKey:
      existingSecret: git-proxy-ssh-hostkey
    authorizedKeys:
      agent-1: "ssh-ed25519 AAAA... agent-1@example"
```

Without `config.ssh.hostKey.existingSecret`, you must explicitly opt in with
`config.ssh.hostKey.allowEphemeral: true` — otherwise the chart's validation
guard refuses to render. **Ephemeral is dev/test only**: a brand-new host key
is generated every pod restart, so every client sees a host-key-changed
warning (or outright rejection) after each restart.

## Using the broker

`config.broker.enabled: true` requires `config.upstream.kind: "github"`. If
you enable the broker with any other upstream kind, the chart refuses to
render with:

> `git-proxy: config.broker.enabled=true requires config.upstream.kind="github" (got "..."). The broker type-asserts port.PRSupport off the upstream adapter and fails closed at startup: "broker: upstream *plain.Upstream does not implement port.PRSupport; the broker requires an SCM adapter (set upstream.kind: github)".`

This is a real startup-time behavior of the binary, not just a chart
opinion — the broker needs an SCM adapter that implements `port.PRSupport`,
and only the GitHub adapter does.

## Ingress

git-over-HTTP pushes and clones can be large and long-running, so the
git-HTTP ingress needs generous body-size, buffering, and timeout settings.
For an nginx ingress controller:

```yaml
ingress:
  git:
    enabled: true
    className: nginx
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "0"
      nginx.ingress.kubernetes.io/proxy-buffering: "off"
      nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    hosts:
      - host: git.example.com
        paths:
          - path: /
            pathType: Prefix
```

- `proxy-body-size: "0"` removes nginx's default request-size cap (large
  pushes).
- `proxy-buffering: "off"` and `proxy-request-buffering: "off"` stream the
  request/response instead of buffering it whole in nginx, which both large
  clones and pushes need.
- `proxy-read-timeout: "600"` gives slow clients (large repos, slow links)
  room to finish.

`ingress.git` and `ingress.broker` are independent blocks — separate
hostnames, separate annotations, separate TLS — since git-HTTP and the broker
are different listeners on different ports. There is **no Ingress for SSH**:
SSH is raw TCP, not HTTP, so it can't go through a standard Ingress resource.
Front it with a `sshService.type: LoadBalancer` or `NodePort` Service instead,
or your ingress controller's TCP-passthrough / stream configuration if it has
one (e.g. nginx-ingress's `tcp-services` ConfigMap).

## Persistence

- `persistence.mirror` — the git inspection-mirror cache. A rebuildable
  performance cache: safe to leave as the default `emptyDir` (lost on
  restart, rebuilt on demand) unless you want to avoid the cold-start cost of
  re-mirroring after every pod restart, in which case set
  `persistence.mirror.enabled: true`.
- `persistence.audit` — the compliance-relevant audit log. **Recommended: a
  real PVC in production** (`persistence.audit.enabled: true`). Left as the
  default `emptyDir`, the audit trail is lost on every pod restart
  (reschedule, node drain, rollout, OOM-kill, ...).

The binary does not rotate its audit log file. For long-lived deployments,
either ship logs off-pod with an external log shipper (sidecar or
node-level DaemonSet tailing the PVC) or periodically truncate/rotate the
file externally.

## Multi-replica

`replicaCount > 1` is blocked by default — the chart's validation guard
(`templates/_validations.tpl`) refuses to render unless you set
`unsafeAllowMultipleReplicas: true`. This is a real correctness constraint,
not just a conservative default: git-proxy keeps the inspection-mirror cache
and the append-only audit file as **per-pod local state** with a
single-writer assumption, and there is no RWX-shared-storage or
leader-election design.

With multiple replicas:

- **Audit log is split** — each pod appends to its own local audit file, so
  the compliance trail is scattered across pods with no aggregation. This is
  the real correctness problem: an incomplete audit trail on any one pod's
  volume is not a complete record of what happened.
- **Mirror cache is independently duplicated** — each pod cold-mirrors
  independently, wasting disk and slowing per-pod cold start. Wasteful, but
  not itself a correctness bug the way the audit split is.

Only set `unsafeAllowMultipleReplicas: true` if you've independently solved
both problems (e.g. centralized audit shipping and you accept the mirror
cache duplication).

## Secret rotation

The Deployment's `checksum/config` pod annotation only hashes the rendered
ConfigMap (`templates/configmap.yaml`) — it has no way to observe a Secret's
*content* (the chart never reads Secret data, only references Secret names).
So editing an existing Secret's content in place (rotating a bearer token,
rotating upstream credentials, rotating the SSH host key) does **not**
trigger a rollout. After rotating any Secret's content, restart manually:

```sh
kubectl rollout restart deployment/<release>-git-proxy
```

## Known limitations

- The broker cannot be functionally tested against a plain or Gitea upstream
  — it needs real GitHub credentials (`config.upstream.kind: github` plus a
  working PAT/App credential) to do anything beyond fail closed.
- No `kind`-cluster CI job in this initial version of the chart's CI. A
  documented fast-follow, not a functional gap in the chart itself.
- The chart never creates or manages Secret content, ever — by design. You
  are always responsible for creating `auth.yaml`, credentials files, and the
  SSH host key yourself.

## Values reference

Not exhaustive — see `values.yaml`'s own comments for the full set and their
defaults. The most consequential values:

| Value | Purpose |
| --- | --- |
| `config.upstream.url` | The upstream git server. Required; the binary refuses to start without it. |
| `config.auth.existingSecret` | Secret holding the `auth:` (bearer-token → agent) fragment. Empty = open relay. |
| `config.broker.enabled` | Turns on the agent-facing REST API. Requires `config.upstream.kind: github`. |
| `config.ssh.enabled` | Turns on the SSH frontend. Requires `config.ssh.authorizedKeys`. |
| `config.policy.rules` | Push-policy rule map (name → `{enabled, agents, repos, params}`). |
| `persistence.mirror.enabled` | Backs the inspection-mirror cache with a PVC instead of emptyDir. |
| `persistence.audit.enabled` | Backs the audit log with a PVC instead of emptyDir. Recommended in production. |
| `ingress.git.enabled` / `ingress.broker.enabled` | Independent Ingress resources for the two HTTP frontends. |
| `replicaCount` / `unsafeAllowMultipleReplicas` | Single-replica by default; see "Multi-replica" above before changing. |
| `image.tag` | Falls back to `Chart.yaml`'s `appVersion` when unset. No `:latest` tag is ever published. |
