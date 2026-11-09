{{/* Base name for all resources in this release. */}}
{{- define "glitchtip.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every object. */}}
{{- define "glitchtip.labels" -}}
app.kubernetes.io/name: glitchtip
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* Selector labels for one component. Call with (dict "root" . "component" "web"). */}}
{{- define "glitchtip.selectorLabels" -}}
app.kubernetes.io/name: glitchtip
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Resolved DATABASE_URL. Bundled Postgres builds it from credentials;
otherwise the external URL is required.
*/}}
{{- define "glitchtip.databaseUrl" -}}
{{- if .Values.postgres.enabled -}}
{{- $pw := required "postgres.password is required when postgres.enabled=true" .Values.postgres.password -}}
postgres://{{ .Values.postgres.user }}:{{ $pw }}@{{ include "glitchtip.fullname" . }}-postgres:5432/{{ .Values.postgres.database }}
{{- else -}}
{{- required "externalDatabaseUrl is required when postgres.enabled=false" .Values.externalDatabaseUrl -}}
{{- end -}}
{{- end -}}

{{/* Redis connection URL for the bundled instance. */}}
{{- define "glitchtip.redisUrl" -}}
redis://{{ include "glitchtip.fullname" . }}-redis:6379/0
{{- end -}}

{{/* Shared env for web + worker + migrate. */}}
{{- define "glitchtip.env" -}}
- name: SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "glitchtip.fullname" . }}
      key: SECRET_KEY
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "glitchtip.fullname" . }}
      key: DATABASE_URL
- name: REDIS_URL
  value: {{ include "glitchtip.redisUrl" . | quote }}
- name: PORT
  value: {{ .Values.web.port | quote }}
- name: GLITCHTIP_DOMAIN
  value: {{ .Values.externalUrl | default (printf "https://%s" .Values.domain) | quote }}
- name: DEFAULT_FROM_EMAIL
  value: {{ .Values.defaultFromEmail | quote }}
- name: ENABLE_OPEN_USER_REGISTRATION
  value: {{ .Values.openRegistration | quote }}
- name: CELERY_WORKER_AUTOSCALE
  value: "1,3"
{{- end -}}
