{{- /* 
  Vault Agent Template for garde secrets
  
  Reads secrets from Vault and writes them to /run/secrets/
  Each secret is written to a separate file.
  
  Configure your secrets in Vault at: secret/garde/*
*/ -}}

{{- with secret "secret/garde/config" -}}
{{ .Data.data.redis_host }}
{{- end -}}

