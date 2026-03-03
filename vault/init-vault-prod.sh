#!/bin/sh

set -e

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-}"

if [ -z "$VAULT_TOKEN" ]; then
  echo "VAULT_TOKEN is required (e.g. root token for dev-mode Vault)"
  exit 1
fi

echo "Vault address: $VAULT_ADDR"
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
  echo "  Vault not ready yet, retrying..."
  sleep 1
done
echo "Vault is ready!"

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
EOF

vault write auth/approle/role/garde \
  token_policies="garde" \
  token_ttl=1h \
  token_max_ttl=4h

# Write role-id and secret-id to /vault (mounted from host so agent can use them)
vault read -field=role_id auth/approle/role/garde/role-id > /vault/role-id
vault write -f -field=secret_id auth/approle/role/garde/secret-id > /vault/secret-id
echo "Wrote role-id and secret-id to /vault/role-id and /vault/secret-id"

# Seed secrets from file (same format as dev.secrets: KEY=value)
if [ -f /prod.secrets ]; then
  echo "Seeding secrets from /prod.secrets..."
  while IFS='=' read -r key value || [ -n "$key" ]; do
    case "$key" in ''|\#*) continue ;; esac
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)
    if [ -n "$key" ] && [ -n "$value" ]; then
      lower_key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
      echo "  Setting secret: $lower_key"
      vault kv put "secret/garde/$lower_key" value="$value"
    fi
  done < /prod.secrets
  echo "Secrets seeded."
else
  echo "No /prod.secrets found; skipping seed. Add secrets manually or mount a file at /prod.secrets."
fi

echo "Vault init complete. Vault Agent can authenticate with AppRole and read secrets."
