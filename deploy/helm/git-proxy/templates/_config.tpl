{{- define "git-proxy.configBase" -}}
# Rendered by the git-proxy Helm chart ({{ include "git-proxy.chart" . }}). Do not edit in-cluster.
# NOTE: the top-level `auth:` key is DELIBERATELY absent here. Bearer tokens are
# supplied by a Secret fragment that the assemble-config init container appends
# to this file at {{ include "git-proxy.paths.assembledConfig" . }}.
listen: "0.0.0.0:{{ int .Values.ports.git }}"
upstream:
  {{- with .Values.config.upstream.kind }}
  kind: {{ . | quote }}
  {{- end }}
  url: {{ .Values.config.upstream.url | quote }}
  {{- if .Values.config.upstream.credentials.existingSecret }}
  credentials_file: {{ include "git-proxy.paths.credentialsFile" . | quote }}
  {{- end }}
{{- if .Values.config.issueUpstream.enabled }}
issue_upstream:
  kind: {{ .Values.config.issueUpstream.kind | quote }}
  url: {{ .Values.config.issueUpstream.url | quote }}
  {{- $icf := include "git-proxy.issueCredentialsPath" . }}
  {{- if $icf }}
  credentials_file: {{ $icf | quote }}
  {{- end }}
{{- end }}
{{- with .Values.config.repos }}
repos:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .Values.config.publicRepos }}
public_repos:
{{ toYaml . | indent 2 }}
{{- end }}
{{- $pol := .Values.config.policy }}
{{- $rules := dict }}
{{- range $name, $rule := $pol.rules }}
{{-   if $rule.enabled }}
{{-     $r := dict "enabled" true }}
{{-     with $rule.agents }}{{ $_ := set $r "agents" . }}{{ end }}
{{-     with $rule.repos  }}{{ $_ := set $r "repos"  . }}{{ end }}
{{-     with $rule.params }}{{ $_ := set $r "params" . }}{{ end }}
{{-     $_ := set $rules $name $r }}
{{-   end }}
{{- end }}
{{- $needMirror := include "git-proxy.policyNeedsMirror" . }}
{{- $maxPack := int64 $pol.push.maxPackfileBytes }}
{{- $emitPolicy := or $pol.mode $pol.dryRun (gt (len $rules) 0) $needMirror $pol.read.deny (gt $maxPack 0) }}
{{- if $emitPolicy }}
policy:
  {{- with $pol.mode }}
  mode: {{ . | quote }}
  {{- end }}
  {{- if $pol.dryRun }}
  dry_run: true
  {{- end }}
  {{- if $needMirror }}
  mirror:
    dir: {{ include "git-proxy.paths.mirrorDir" . | quote }}
  {{- end }}
  {{- if gt (len $rules) 0 }}
  rules:
{{ toYaml $rules | indent 4 }}
  {{- end }}
  {{- if gt $maxPack 0 }}
  push:
    max_packfile_bytes: {{ $maxPack }}
  {{- end }}
  {{- with $pol.read.deny }}
  read:
    deny:
{{ toYaml . | indent 6 }}
  {{- end }}
{{- end }}
{{- if .Values.config.ssh.enabled }}
ssh:
  listen: "0.0.0.0:{{ int .Values.ports.ssh }}"
  {{- if .Values.config.ssh.hostKey.existingSecret }}
  host_key: {{ include "git-proxy.paths.sshHostKey" . | quote }}
  {{- end }}
  authorized_keys:
{{ toYaml .Values.config.ssh.authorizedKeys | indent 4 }}
{{- end }}
{{- if .Values.config.audit.enabled }}
audit:
  file: {{ include "git-proxy.paths.auditFile" . | quote }}
{{- end }}
{{- with .Values.config.alerts.webhook }}
alerts:
  webhook: {{ . | quote }}
{{- end }}
{{- if .Values.config.broker.enabled }}
broker:
  listen: "0.0.0.0:{{ int .Values.ports.broker }}"
  {{- with .Values.config.broker.allowedAgents }}
  allowed_agents:
{{ toYaml . | indent 4 }}
  {{- end }}
  {{- with .Values.config.broker.allowedOps }}
  allowed_ops:
{{ toYaml . | indent 4 }}
  {{- end }}
  {{- with .Values.config.broker.mergeMethod }}
  merge_method: {{ . | quote }}
  {{- end }}
{{- end }}
{{- end -}}
