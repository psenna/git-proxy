{{- define "git-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "git-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "git-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "git-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "git-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "git-proxy.labels" -}}
helm.sh/chart: {{ include "git-proxy.chart" . }}
{{ include "git-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: git-proxy
{{- end }}

{{- define "git-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "git-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "git-proxy.imageRef" -}}
{{- $repo := .Values.image.repository | default "" -}}
{{- if not $repo -}}
{{- fail "git-proxy: image.repository is required (there is no default image; set image.repository, e.g. ghcr.io/psenna/git-proxy)" -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion | default "" -}}
{{- if not $tag -}}
{{- fail "git-proxy: no image tag could be resolved: image.tag is empty and Chart.yaml has no appVersion. git-proxy publishes no :latest tag, so an explicit tag is required (set image.tag, e.g. v0.0.8)." -}}
{{- end -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}

{{- define "git-proxy.paths.baseDir"             -}}/etc/git-proxy/base{{- end -}}
{{- define "git-proxy.paths.baseConfig"          -}}/etc/git-proxy/base/config-base.yaml{{- end -}}
{{- define "git-proxy.paths.authDir"             -}}/etc/git-proxy/auth{{- end -}}
{{- define "git-proxy.paths.authFragment"        -}}/etc/git-proxy/auth/auth.yaml{{- end -}}
{{- define "git-proxy.paths.fragmentsRoot"       -}}/etc/git-proxy/fragments{{- end -}}
{{- define "git-proxy.paths.assembledDir"        -}}/run/git-proxy{{- end -}}
{{- define "git-proxy.paths.assembledConfig"     -}}/run/git-proxy/config.yaml{{- end -}}
{{- define "git-proxy.paths.credentialsDir"      -}}/etc/git-proxy/credentials{{- end -}}
{{- define "git-proxy.paths.credentialsFile"     -}}/etc/git-proxy/credentials/credentials.yaml{{- end -}}
{{- define "git-proxy.paths.issueCredentialsDir" -}}/etc/git-proxy/issue-credentials{{- end -}}
{{- define "git-proxy.paths.issueCredentialsFile" -}}/etc/git-proxy/issue-credentials/credentials.yaml{{- end -}}
{{- define "git-proxy.paths.sshDir"              -}}/etc/git-proxy/ssh{{- end -}}
{{- define "git-proxy.paths.sshHostKey"          -}}/etc/git-proxy/ssh/host_key{{- end -}}
{{- define "git-proxy.paths.mirrorDir"           -}}/var/lib/git-proxy/mirror{{- end -}}
{{- define "git-proxy.paths.auditDir"            -}}/var/log/git-proxy{{- end -}}
{{- define "git-proxy.paths.auditFile"           -}}/var/log/git-proxy/audit.jsonl{{- end -}}

{{- define "git-proxy.paths.fragment" -}}
{{- printf "/etc/git-proxy/fragments/%d/fragment.yaml" (int .index) -}}
{{- end -}}

{{- define "git-proxy.auth.secretName" -}}{{ .Values.config.auth.existingSecret }}{{- end -}}
{{- define "git-proxy.auth.secretKey"  -}}{{ .Values.config.auth.key | default "auth.yaml" }}{{- end -}}

{{- define "git-proxy.credentials.secretName" -}}{{ .Values.config.upstream.credentials.existingSecret }}{{- end -}}
{{- define "git-proxy.credentials.secretKey"  -}}{{ .Values.config.upstream.credentials.key | default "credentials.yaml" }}{{- end -}}

{{- define "git-proxy.issueCredentials.secretName" -}}{{ .Values.config.issueUpstream.credentials.existingSecret }}{{- end -}}
{{- define "git-proxy.issueCredentials.secretKey"  -}}{{ .Values.config.issueUpstream.credentials.key | default "credentials.yaml" }}{{- end -}}

{{- define "git-proxy.sshHostKey.secretName" -}}{{ .Values.config.ssh.hostKey.existingSecret }}{{- end -}}
{{- define "git-proxy.sshHostKey.secretKey"  -}}{{ .Values.config.ssh.hostKey.key | default "host_key" }}{{- end -}}

{{/*
issue_upstream.credentials_file resolution: own Secret -> own path; else SCM
Secret -> SCM path (the documented single-PAT GitHub case); else omit the key.
*/}}
{{- define "git-proxy.issueCredentialsPath" -}}
{{- if .Values.config.issueUpstream.credentials.existingSecret -}}
{{- include "git-proxy.paths.issueCredentialsFile" . -}}
{{- else if .Values.config.upstream.credentials.existingSecret -}}
{{- include "git-proxy.paths.credentialsFile" . -}}
{{- end -}}
{{- end -}}

{{/* True (non-empty) when the binary would require policy.mirror.dir. */}}
{{- define "git-proxy.policyNeedsMirror" -}}
{{- $needs := false -}}
{{- range $name, $rule := .Values.config.policy.rules -}}
{{-   if $rule.enabled -}}{{- $needs = true -}}{{- end -}}
{{- end -}}
{{- if .Values.config.policy.read.deny -}}{{- $needs = true -}}{{- end -}}
{{- if $needs -}}true{{- end -}}
{{- end -}}

{{/* Space-separated, ordered list of files the assemble-config init container concatenates. */}}
{{- define "git-proxy.assembleFileList" -}}
{{- $files := list (include "git-proxy.paths.baseConfig" .) -}}
{{- if .Values.config.auth.existingSecret -}}
{{- $files = append $files (include "git-proxy.paths.authFragment" .) -}}
{{- end -}}
{{- range $i, $f := .Values.extraConfigFragments -}}
{{- $files = append $files (printf "/etc/git-proxy/fragments/%d/fragment.yaml" $i) -}}
{{- end -}}
{{- join " " $files -}}
{{- end -}}

{{- define "git-proxy.mirrorClaimName" -}}
{{- if .Values.persistence.mirror.existingClaim -}}{{ .Values.persistence.mirror.existingClaim }}
{{- else -}}{{ printf "%s-mirror" (include "git-proxy.fullname" .) }}{{- end -}}
{{- end -}}

{{- define "git-proxy.auditClaimName" -}}
{{- if .Values.persistence.audit.existingClaim -}}{{ .Values.persistence.audit.existingClaim }}
{{- else -}}{{ printf "%s-audit" (include "git-proxy.fullname" .) }}{{- end -}}
{{- end -}}
