{{- define "git-proxy.validate" -}}

{{- $_ := include "git-proxy.imageRef" . -}}

{{- if not .Values.config.upstream.url -}}
{{- fail "git-proxy: config.upstream.url is required — the binary refuses to start without it (internal/config/config.go: \"config: upstream.url is required\"). Set config.upstream.url to the upstream git server, e.g. https://github.com or http://gitea.git.svc:3000." -}}
{{- end -}}

{{- if and (not .Values.config.auth.existingSecret) (not .Values.config.auth.unsafeAllowNoAuth) -}}
{{- fail "git-proxy: config.auth.existingSecret is unset, so the HTTP frontend would run with no agent authentication (an open relay -- any client that can reach it reads/writes through the proxy using the proxy's own upstream credentials). The binary now fails closed at startup: \"config: auth.tokens is empty\" (security review finding H9). Create a Secret holding a verbatim auth.tokens YAML fragment (bearer-token -> agent-name) and set config.auth.existingSecret, or set config.auth.unsafeAllowNoAuth=true to explicitly acknowledge running with no incoming auth (not recommended for production)." -}}
{{- end -}}

{{- if and (gt (int .Values.replicaCount) 1) (not .Values.unsafeAllowMultipleReplicas) -}}
{{- fail (printf "git-proxy: replicaCount=%d is not supported. git-proxy keeps per-pod local state -- the bare inspection-mirror cache (policy.mirror.dir) and the append-only audit file -- with a single-writer assumption and no RWX/leader-election design. Run one replica, or set unsafeAllowMultipleReplicas=true if you have independently guaranteed each replica has its own storage and you accept a split audit log." (int .Values.replicaCount)) -}}
{{- end -}}

{{- if and .Values.config.issueUpstream.enabled (not .Values.config.issueUpstream.kind) -}}
{{- fail "git-proxy: config.issueUpstream.enabled=true requires config.issueUpstream.kind (e.g. \"github\"). An empty kind means \"issues disabled\" to the binary, so an enabled-but-kindless issue upstream is a misconfiguration." -}}
{{- end -}}

{{- if and .Values.config.issueUpstream.enabled (not .Values.config.issueUpstream.url) -}}
{{- fail "git-proxy: config.issueUpstream.enabled=true requires config.issueUpstream.url -- the binary fails closed at startup with \"config: issue_upstream.url is required when issue_upstream.kind is set\"." -}}
{{- end -}}

{{- if and .Values.config.ssh.enabled (not .Values.config.ssh.authorizedKeys) -}}
{{- fail "git-proxy: config.ssh.enabled=true requires a non-empty config.ssh.authorizedKeys map (agent-name -> public key line). The binary fails closed: \"config: ssh.authorized_keys is required when ssh.listen is set (an enabled SSH frontend with no authorized keys denies everyone)\"." -}}
{{- end -}}

{{- if and .Values.config.ssh.enabled (not .Values.config.ssh.hostKey.existingSecret) (not .Values.config.ssh.hostKey.allowEphemeral) -}}
{{- fail "git-proxy: config.ssh.enabled=true requires config.ssh.hostKey.existingSecret (a Secret holding an unencrypted PEM SSH host private key). Without it the frontend generates an EPHEMERAL ed25519 host key at startup, so every client sees a host-key mismatch after each pod restart. Create the Secret (ssh-keygen -t ed25519 -N '' -f host_key; kubectl create secret generic <name> --from-file=host_key=./host_key), or set config.ssh.hostKey.allowEphemeral=true for dev/test only." -}}
{{- end -}}

{{- if and .Values.config.broker.enabled (not (eq .Values.config.upstream.kind "github")) -}}
{{- fail (printf "git-proxy: config.broker.enabled=true requires config.upstream.kind=\"github\" (got %q). The broker type-asserts port.PRSupport off the upstream adapter and fails closed at startup: \"broker: upstream *plain.Upstream does not implement port.PRSupport; the broker requires an SCM adapter (set upstream.kind: github)\"." .Values.config.upstream.kind) -}}
{{- end -}}

{{- if and .Values.config.broker.enabled (eq (int .Values.ports.broker) (int .Values.ports.git)) -}}
{{- fail (printf "git-proxy: ports.broker (%d) must differ from ports.git (%d). The broker is a separate listener on a separate port, never a sub-path of the git frontend; the binary fails closed with \"config: broker.listen must differ from listen\"." (int .Values.ports.broker) (int .Values.ports.git)) -}}
{{- end -}}

{{- if .Values.config.ssh.enabled -}}
{{-   if eq (int .Values.ports.ssh) (int .Values.ports.git) -}}
{{-     fail (printf "git-proxy: ports.ssh (%d) collides with ports.git (%d). All three frontends run in one process; the second net.Listen fails with \"address already in use\" and the pod crash-loops." (int .Values.ports.ssh) (int .Values.ports.git)) -}}
{{-   end -}}
{{-   if and .Values.config.broker.enabled (eq (int .Values.ports.ssh) (int .Values.ports.broker)) -}}
{{-     fail (printf "git-proxy: ports.ssh (%d) collides with ports.broker (%d). All three frontends run in one process; the second net.Listen fails with \"address already in use\" and the pod crash-loops." (int .Values.ports.ssh) (int .Values.ports.broker)) -}}
{{-   end -}}
{{- end -}}

{{- range $i, $p := .Values.config.publicRepos -}}
{{-   $s := toString $p -}}
{{-   if eq $s "" -}}
{{-     fail (printf "git-proxy: config.publicRepos[%d] is empty. repomatch rejects empty patterns at startup (\"empty pattern\") and the proxy crash-loops." $i) -}}
{{-   end -}}
{{-   if eq $s "*" -}}
{{-     fail (printf "git-proxy: config.publicRepos[%d] is a bare \"*\" catch-all, which repomatch rejects at startup (\"bare * catch-all not allowed\"). A bare * would expose every upstream repo to anonymous readers. Use a scoped pattern such as \"public/*\"." $i) -}}
{{-   end -}}
{{-   if contains "**" $s -}}
{{-     fail (printf "git-proxy: config.publicRepos[%d]=%q contains \"**\", which repomatch rejects anywhere in a pattern at startup (\"** not allowed (use single-segment *)\"). Use single-segment wildcards, e.g. \"public/*\"." $i $s) -}}
{{-   end -}}
{{- end -}}

{{- with .Values.config.alerts.webhook -}}
{{-   if not (or (hasPrefix "http://" .) (hasPrefix "https://" .)) -}}
{{-     fail (printf "git-proxy: config.alerts.webhook=%q must start with http:// or https://. The binary fails fast at startup: \"config: alerts.webhook: unsupported scheme (http/https only)\". If the webhook URL embeds a token, do not put it here -- supply it through extraConfigFragments instead (see the chart README)." .) -}}
{{-   end -}}
{{- end -}}

{{- if and .Values.probes.useBrokerHealthz (not .Values.config.broker.enabled) -}}
{{- fail "git-proxy: probes.useBrokerHealthz=true requires config.broker.enabled=true. /healthz only exists on the broker listener; without the broker there is no HTTP health endpoint anywhere in the process (the git frontend answers / with 401/404 by design), so the readiness probe would point at a port that is never bound." -}}
{{- end -}}

{{- range $i, $f := .Values.extraConfigFragments -}}
{{-   if not $f.existingSecret -}}
{{-     fail (printf "git-proxy: extraConfigFragments[%d].existingSecret is required (the chart never creates Secrets; it only references pre-existing ones)." $i) -}}
{{-   end -}}
{{-   if not $f.key -}}
{{-     fail (printf "git-proxy: extraConfigFragments[%d].key is required -- name the Secret key holding the verbatim YAML fragment (e.g. \"alerts.yaml\")." $i) -}}
{{-   end -}}
{{- end -}}

{{- range $n := list "mirror" "audit" -}}
{{-   $p := index $.Values.persistence $n -}}
{{-   if and $p.enabled (not $p.existingClaim) (not $p.size) -}}
{{-     fail (printf "git-proxy: persistence.%s.enabled=true with no persistence.%s.existingClaim requires persistence.%s.size (the chart-managed PersistentVolumeClaim needs a storage request)." $n $n $n) -}}
{{-   end -}}
{{- end -}}

{{- end -}}
