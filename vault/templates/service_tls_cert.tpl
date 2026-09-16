# Service-listener leaf from Vault PKI. Vault Agent renews before expiry.
#
# Env (set on the vault-agent container):
#   SERVICE_CERT_DOMAIN  — registrable domain (COOKIE_DOMAIN / DOMAIN_NAME)
#   NODE_WG_IP           — this node's mesh address (optional; 127.0.0.1 always included)
#
# Rendered next to this template by agent-config.hcl destinations.
{{- /* common_name and SANs must match DOMAIN_NAME checks in MTLSMiddleware */ -}}
{{ $domain := env "SERVICE_CERT_DOMAIN" -}}
{{ if not $domain }}{{ $domain = env "COOKIE_DOMAIN" }}{{ end -}}
{{ if not $domain }}{{ $domain = "localhost" }}{{ end -}}
{{ $ip := env "NODE_WG_IP" -}}
{{ $ipSans := "127.0.0.1" -}}
{{ if $ip }}{{ $ipSans = printf "%s,%s" $ipSans $ip }}{{ end -}}
{{ with pkiCert "pki_int/issue/garde-service" (printf "common_name=garde.%s" $domain) (printf "alt_names=garde-api,localhost,garde.%s" $domain) (printf "ip_sans=%s" $ipSans) "ttl=720h" -}}
{{ .Cert }}
{{- end }}
