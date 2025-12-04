{{- /* Template for Redis password */ -}}
{{- with secret "database/creds/garde-redis" -}}
{{ .Data.password }}
{{- end -}}

