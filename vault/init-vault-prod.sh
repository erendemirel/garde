#!/bin/sh
# One-time production Vault setup for the single-VPS Compose stack:
#   - Enable KV v2 + AppRole
#   - Create garde policy/role
#   - Write role-id / secret-id for Vault Agent
#   - Seed secrets from /prod.secrets
#
# Prerequisites:
#   - Vault is running in server mode (not -dev), initialized, and unsealed
#   - VAULT_TOKEN is a root token (or equivalent) from `vault operator init`
#
# See docs/INSTALLATION.md "Deploying to a VPS".

set -e

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-}"

if [ -z "$VAULT_TOKEN" ]; then
  echo "VAULT_TOKEN is required."
  echo "Use the root_token from vault-credentials.json (output of vault operator init)."
  echo "Example .env line: VAULT_TOKEN=hvs.xxxxx"
  exit 1
fi

echo "Vault address: $VAULT_ADDR"
echo "Waiting for Vault to be unsealed..."
i=0
until vault status >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "Vault is not unsealed (or not reachable)."
    echo "Run: docker compose -f docker-compose.prod.yml --profile ops run --rm vault-unseal"
    exit 1
  fi
  echo "  still sealed/unreachable, retrying..."
  sleep 2
done
echo "Vault is unsealed."

# Enable KV v2
vault secrets enable -path=secret kv-v2 2>/dev/null || true

# Enable AppRole and create garde policy + role
vault auth enable approle 2>/dev/null || true

vault policy write garde - <<'EOF'
path "secret/data/garde/*" {
  capabilities = ["read"]
}
path "database/creds/garde-redis" {
  capabilities = ["read"]
}
# Service-listener mTLS material from Vault PKI (see deploy/scripts/vault-pki.sh).
path "pki_int/issue/garde-service" {
  capabilities = ["create", "update"]
}
path "pki_int/issue/garde-client" {
  capabilities = ["create", "update"]
}
path "pki_int/cert/ca" {
  capabilities = ["read"]
}
path "pki_int/ca/pem" {
  capabilities = ["read"]
}
EOF

vault write auth/approle/role/garde \
  token_policies="garde" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0

# Write role-id and secret-id to /vault (host-mounted ./vault) for the agent.
# These are long-lived machine credentials (secret_id_ttl=0); keep them host-private.
vault read -field=role_id auth/approle/role/garde/role-id > /vault/role-id
vault write -f -field=secret_id auth/approle/role/garde/secret-id > /vault/secret-id
chmod 600 /vault/role-id /vault/secret-id
echo "Wrote AppRole credentials to /vault/role-id and /vault/secret-id (mode 600)"

# Seed secrets from file (same format as dev.secrets: KEY=value)
if [ -f /prod.secrets ]; then
  echo "Seeding secrets from /prod.secrets..."
  # Trim with sed — do not use xargs; it strips quotes and corrupts JSON secrets.
  # Split on the first '=' only — base64 values (MFA_ENCRYPTION_KEY) contain '='.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key=${line%%=*}
    value=${line#*=}
    if [ "$key" = "$line" ]; then
      value=
    fi
    key=$(printf '%s' "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    # Allow empty values so optional keys (e.g. TRUSTED_PROXIES=) still exist for Vault Agent templates
    if [ -n "$key" ]; then
      lower_key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
      echo "  Setting secret: $lower_key"
      vault kv put "secret/garde/$lower_key" value="$value"
    fi
  done < /prod.secrets
  echo "Secrets seeded."
else
  echo "No /prod.secrets found; skipping seed. Add secrets manually or mount a file at /prod.secrets."
fi

# --- Vault PKI for the service listener (Agent auto-renews leaves) ------------
echo "Enabling Vault PKI for service-listener mTLS..."
ROOT_PATH=pki
INT_PATH=pki_int
SERVER_ROLE=garde-service
CLIENT_ROLE=garde-client
LEAF_TTL="${VAULT_PKI_LEAF_TTL:-7680h}"

vault secrets enable -path="$ROOT_PATH" pki 2>/dev/null || true
vault secrets tune -max-lease-ttl=87600h "$ROOT_PATH" 2>/dev/null || true
vault secrets enable -path="$INT_PATH" pki 2>/dev/null || true
vault secrets tune -max-lease-ttl=43800h "$INT_PATH" 2>/dev/null || true

if ! vault read -format=json "$ROOT_PATH/cert/ca" >/dev/null 2>&1; then
  vault write -field=certificate "$ROOT_PATH/root/generate/internal" \
    common_name="garde service root" ttl=87600h key_bits=4096 >/dev/null
fi
vault write "$ROOT_PATH/config/urls" \
  issuing_certificates="$VAULT_ADDR/v1/$ROOT_PATH" \
  crl_distribution_points="$VAULT_ADDR/v1/$ROOT_PATH/crl" >/dev/null 2>&1 || true

if ! vault read -format=json "$INT_PATH/cert/ca" >/dev/null 2>&1; then
  csr=$(vault write -field=csr "$INT_PATH/intermediate/generate/internal" \
    common_name="garde service intermediate" ttl=43800h key_bits=4096)
  cert=$(vault write -field=certificate "$ROOT_PATH/root/sign-intermediate" \
    csr="$csr" format=pem_bundle ttl=43800h)
  vault write "$INT_PATH/intermediate/set-signed" certificate="$cert" >/dev/null
fi
vault write "$INT_PATH/config/urls" \
  issuing_certificates="$VAULT_ADDR/v1/$INT_PATH" \
  crl_distribution_points="$VAULT_ADDR/v1/$INT_PATH/crl" >/dev/null 2>&1 || true

DOMAIN="$(vault kv get -field=value secret/garde/domain_name 2>/dev/null || true)"
DOMAIN="${DOMAIN:-localhost}"
vault write "$INT_PATH/roles/$SERVER_ROLE" \
  allowed_domains="$DOMAIN,garde-api,localhost" \
  allow_subdomains=true \
  allow_bare_domains=true \
  allow_localhost=true \
  allow_ip_sans=true \
  server_flag=true \
  client_flag=false \
  key_bits=4096 \
  max_ttl="$LEAF_TTL" \
  ttl="$LEAF_TTL" >/dev/null

vault write "$INT_PATH/roles/$CLIENT_ROLE" \
  allowed_domains="$DOMAIN" \
  allow_bare_domains=true \
  allow_subdomains=false \
  server_flag=false \
  client_flag=true \
  key_bits=4096 \
  max_ttl="$LEAF_TTL" \
  ttl="$LEAF_TTL" >/dev/null

# Prefer Agent-rendered PEMs when the service listener is enabled.
if [ "$(vault kv get -field=value secret/garde/service_listener 2>/dev/null || true)" = "true" ]; then
  vault kv put secret/garde/service_tls_cert_path value="/run/secrets/service_tls_cert.pem" >/dev/null
  vault kv put secret/garde/service_tls_key_path value="/run/secrets/service_tls_key.pem" >/dev/null
  vault kv put secret/garde/service_tls_ca_path value="/run/secrets/service_tls_ca.pem" >/dev/null
  echo "service_tls_*_path set to /run/secrets/service_tls_{cert,key,ca}.pem"
fi

echo "Vault PKI ready (roles $SERVER_ROLE / $CLIENT_ROLE for domain $DOMAIN)."

echo "Vault AppRole init complete. Vault Agent can authenticate with role-id/secret-id."
echo "You can leave VAULT_TOKEN in .env for future reseeds, or remove it and use AppRole only."
echo "Set secret/garde/mfa_encryption_key and issue /validate keys with POST /admin/api-keys."
