{{- define "statushub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "statushub.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "statushub.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "statushub.labels" -}}
app.kubernetes.io/name: {{ include "statushub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "statushub.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/*
Environment shared by every workload.

Secrets arrive as references into an existing Kubernetes Secret rather than
templated into the release: a value in a Helm release is a value in the
cluster's release history, readable by anybody with `helm get values`.
*/}}
{{/*
Whether this release runs the workloads that must exist in exactly one region.
*/}}
{{- define "statushub.isPrimary" -}}
{{- eq (default "primary" .Values.region.role) "primary" -}}
{{- end -}}

{{- define "statushub.env" -}}
- name: STATUSHUB_REGION
  value: {{ default "default" .Values.region.name | quote }}
- name: STATUSHUB_REGION_ROLE
  value: {{ default "primary" .Values.region.role | quote }}
{{- with .Values.region.writeBudget }}
- name: STATUSHUB_DB_WRITE_BUDGET
  value: {{ . | quote }}
{{- end }}
- name: STATUSHUB_ENVIRONMENT
  value: {{ .Values.config.environment | quote }}
- name: STATUSHUB_BASE_URL
  value: {{ required "config.baseURL is required: it appears in every receiver URL, and a wrong value produces URLs nobody can use" .Values.config.baseURL | quote }}
- name: STATUSHUB_SHARDS
  value: {{ .Values.config.shards | quote }}
- name: STATUSHUB_LOG_FORMAT
  value: {{ .Values.config.logFormat | quote }}
- name: STATUSHUB_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: STATUSHUB_TRUST_PROXY_HEADERS
  value: {{ .Values.config.trustProxyHeaders | quote }}
- name: STATUSHUB_SHUTDOWN_GRACE
  value: {{ printf "%ds" (int .Values.shutdownGraceSeconds) | quote }}
{{- if .Values.config.blockedCIDRs }}
- name: STATUSHUB_BLOCKED_CIDRS
  value: {{ join "," .Values.config.blockedCIDRs | quote }}
{{- end }}
- name: STATUSHUB_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.existingSecret }}
      key: {{ .Values.secrets.keys.databaseURL }}
- name: STATUSHUB_TENANT_SALT_MASTER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.existingSecret }}
      key: {{ .Values.secrets.keys.tenantSaltMaster }}
{{- end -}}

{{- define "statushub.podSecurity" -}}
securityContext:
{{ toYaml .Values.podSecurityContext | indent 2 }}
{{- end -}}

{{- define "statushub.containerSecurity" -}}
securityContext:
{{ toYaml .Values.containerSecurityContext | indent 2 }}
{{- end -}}
