#!/bin/sh
set -e
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=devtoken
vault secrets tune -max-lease-ttl=87600h pki 2>/dev/null || true
vault secrets tune -max-lease-ttl=43800h pki_int 2>/dev/null || true
if ! vault read pki/cert/ca >/dev/null 2>&1; then
  vault write -field=certificate pki/root/generate/internal common_name="garde service root" ttl=87600h key_bits=4096 >/dev/null
  echo root_CA_generated
else
  echo root_CA_present
fi
if ! vault read pki_int/cert/ca >/dev/null 2>&1; then
  csr=$(vault write -field=csr pki_int/intermediate/generate/internal common_name="garde service intermediate" ttl=43800h key_bits=4096)
  cert=$(vault write -field=certificate pki/root/sign-intermediate csr="$csr" format=pem_bundle ttl=43800h)
  vault write pki_int/intermediate/set-signed certificate="$cert" >/dev/null
  echo intermediate_CA_generated
else
  echo intermediate_CA_present
fi
DOMAIN=$(vault kv get -field=value secret/garde/domain_name 2>/dev/null || echo localhost)
vault write pki_int/roles/garde-service allowed_domains="$DOMAIN,garde-api,localhost" allow_subdomains=true allow_bare_domains=true allow_localhost=true allow_ip_sans=true server_flag=true client_flag=false key_bits=4096 max_ttl=7680h ttl=7680h >/dev/null
vault write pki_int/roles/garde-client allowed_domains="$DOMAIN" allow_bare_domains=true allow_subdomains=false server_flag=false client_flag=true key_bits=4096 max_ttl=7680h ttl=7680h >/dev/null
echo PKI_ready_domain=$DOMAIN
