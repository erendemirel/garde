{{ $domain := env "SERVICE_CERT_DOMAIN" -}}
{{ if not $domain }}{{ $domain = env "COOKIE_DOMAIN" }}{{ end -}}
{{ if not $domain }}{{ $domain = "localhost" }}{{ end -}}
{{ $ip := env "NODE_WG_IP" -}}
{{ $ipSans := "127.0.0.1" -}}
{{ if $ip }}{{ $ipSans = printf "%s,%s" $ipSans $ip }}{{ end -}}
{{ with pkiCert "pki_int/issue/garde-service" (printf "common_name=garde.%s" $domain) (printf "alt_names=garde-api,localhost,garde.%s" $domain) (printf "ip_sans=%s" $ipSans) "ttl=720h" -}}
{{ .Key }}
{{- end }}
