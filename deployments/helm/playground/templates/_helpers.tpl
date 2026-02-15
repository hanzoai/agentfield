{{- define "playground.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "playground.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "playground.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "playground.labels" -}}
app.kubernetes.io/name: {{ include "playground.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "playground.selectorLabels" -}}
app.kubernetes.io/name: {{ include "playground.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "playground.controlPlane.fullname" -}}
{{- printf "%s-control-plane" (include "playground.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "playground.postgres.fullname" -}}
{{- printf "%s-postgres" (include "playground.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "playground.demoAgent.fullname" -}}
{{- printf "%s-demo-agent" (include "playground.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "playground.controlPlane.grpcPort" -}}
{{- $grpcPort := int (default 0 .Values.controlPlane.service.grpcPort) -}}
{{- if eq $grpcPort 0 -}}
{{- add (int .Values.controlPlane.service.port) 100 -}}
{{- else -}}
{{- $grpcPort -}}
{{- end -}}
{{- end -}}

{{- define "playground.controlPlane.postgresUrl" -}}
{{- $url := default "" .Values.controlPlane.storage.postgresUrl -}}
{{- if $url -}}
{{- $url -}}
{{- else if and .Values.postgres.enabled (not .Values.postgres.auth.existingSecret) -}}
{{- printf "postgres://%s:%s@%s:5432/%s?sslmode=disable" .Values.postgres.auth.username .Values.postgres.auth.password (include "playground.postgres.fullname" .) .Values.postgres.auth.database -}}
{{- else -}}
{{- "" -}}
{{- end -}}
{{- end -}}

{{- define "playground.apiAuth.secretName" -}}
{{- if .Values.apiAuth.existingSecret -}}
{{- .Values.apiAuth.existingSecret -}}
{{- else -}}
{{- printf "%s-api-auth" (include "playground.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "playground.postgres.secretName" -}}
{{- if .Values.postgres.auth.existingSecret -}}
{{- .Values.postgres.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-postgres-auth" (include "playground.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
