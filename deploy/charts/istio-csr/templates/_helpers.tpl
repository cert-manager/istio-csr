{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "cert-manager-istio-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cert-manager-istio-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "cert-manager-istio-agent.labels" -}}
app.kubernetes.io/name: {{ include "cert-manager-istio-agent.name" . }}
helm.sh/chart: {{ include "cert-manager-istio-agent.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Required claims serialized to CLI argument
*/}}
{{- define "requiredClaims" -}}
{{- if .Values.oidc.requiredClaims -}}
{{- $local := (list) -}}
{{- range $k, $v := .Values.oidc.requiredClaims -}}
{{- $local = (printf "%s=%s" $k $v | append $local) -}}
{{- end -}}
{{ join "," $local }}
{{- end -}}
{{- end -}}
