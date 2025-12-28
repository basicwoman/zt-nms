{{/*
Expand the name of the chart.
*/}}
{{- define "zt-nms.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zt-nms.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "zt-nms.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zt-nms.labels" -}}
helm.sh/chart: {{ include "zt-nms.chart" . }}
{{ include "zt-nms.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zt-nms.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zt-nms.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "zt-nms.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "zt-nms.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL helpers
*/}}
{{- define "zt-nms.postgresql.host" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" (include "zt-nms.fullname" .) }}
{{- else }}
{{- .Values.externalPostgresql.host }}
{{- end }}
{{- end }}

{{- define "zt-nms.postgresql.port" -}}
{{- if .Values.postgresql.enabled }}
{{- "5432" }}
{{- else }}
{{- .Values.externalPostgresql.port | toString }}
{{- end }}
{{- end }}

{{- define "zt-nms.postgresql.database" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalPostgresql.database }}
{{- end }}
{{- end }}

{{- define "zt-nms.postgresql.username" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.username }}
{{- else }}
{{- .Values.externalPostgresql.username }}
{{- end }}
{{- end }}

{{- define "zt-nms.postgresql.secretName" -}}
{{- if .Values.postgresql.enabled }}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.existingSecret }}
{{- else }}
{{- printf "%s-postgresql" (include "zt-nms.fullname" .) }}
{{- end }}
{{- else }}
{{- .Values.externalPostgresql.existingSecret }}
{{- end }}
{{- end }}

{{- define "zt-nms.postgresql.secretKey" -}}
{{- if .Values.postgresql.enabled }}
{{- .Values.postgresql.auth.secretKeys.userPasswordKey | default "password" }}
{{- else }}
{{- .Values.externalPostgresql.existingSecretPasswordKey | default "password" }}
{{- end }}
{{- end }}

{{/*
Redis helpers
*/}}
{{- define "zt-nms.redis.host" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master" (include "zt-nms.fullname" .) }}
{{- else }}
{{- .Values.externalRedis.host }}
{{- end }}
{{- end }}

{{- define "zt-nms.redis.port" -}}
{{- if .Values.redis.enabled }}
{{- "6379" }}
{{- else }}
{{- .Values.externalRedis.port | toString }}
{{- end }}
{{- end }}

{{- define "zt-nms.redis.secretName" -}}
{{- if .Values.redis.enabled }}
{{- if .Values.redis.auth.existingSecret }}
{{- .Values.redis.auth.existingSecret }}
{{- else }}
{{- printf "%s-redis" (include "zt-nms.fullname" .) }}
{{- end }}
{{- else }}
{{- .Values.externalRedis.existingSecret }}
{{- end }}
{{- end }}

{{- define "zt-nms.redis.secretKey" -}}
{{- if .Values.redis.enabled }}
{{- .Values.redis.auth.existingSecretPasswordKey | default "redis-password" }}
{{- else }}
{{- .Values.externalRedis.existingSecretPasswordKey | default "password" }}
{{- end }}
{{- end }}

{{/*
NATS helpers
*/}}
{{- define "zt-nms.nats.url" -}}
{{- if .Values.nats.enabled }}
{{- printf "nats://%s-nats:4222" (include "zt-nms.fullname" .) }}
{{- else }}
{{- .Values.externalNats.url }}
{{- end }}
{{- end }}

{{/*
etcd helpers
*/}}
{{- define "zt-nms.etcd.endpoints" -}}
{{- if .Values.etcd.enabled }}
{{- printf "http://%s-etcd:2379" (include "zt-nms.fullname" .) }}
{{- else }}
{{- join "," .Values.externalEtcd.endpoints }}
{{- end }}
{{- end }}

{{/*
TLS secret name
*/}}
{{- define "zt-nms.tls.secretName" -}}
{{- if .Values.tls.existingSecrets.server }}
{{- .Values.tls.existingSecrets.server }}
{{- else }}
{{- printf "%s-tls" (include "zt-nms.fullname" .) }}
{{- end }}
{{- end }}
