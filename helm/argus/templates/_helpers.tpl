{{/* Shared name + label helpers. */}}

{{- define "argus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "argus.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "argus.labels" -}}
app.kubernetes.io/name: {{ include "argus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "argus.image" -}}
{{- $repo := .Values.image.repository -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}

{{/* Resolve the Postgres host: in-cluster or external. */}}
{{- define "argus.postgresHost" -}}
{{- if .Values.postgres.enabled -}}
{{ include "argus.fullname" . }}-postgres
{{- else -}}
{{ .Values.postgres.external.host }}
{{- end -}}
{{- end -}}

{{- define "argus.redisUrl" -}}
{{- if .Values.redis.enabled -}}
redis://{{ include "argus.fullname" . }}-redis:6379
{{- else -}}
{{ .Values.redis.external.url }}
{{- end -}}
{{- end -}}
