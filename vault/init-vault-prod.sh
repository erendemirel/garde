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
EOF

vault write auth/approle/role/garde \
  token_policies="garde" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0

# Write role-id and secret-id to /vault (host-mounted ./vault) for the agent
vault read -field=role_id auth/approle/role/garde/role-id > /vault/role-id
vault write -f -field=secret_id auth/approle/role/garde/secret-id > /vault/secret-id
chmod 600 /vault/role-id /vault/secret-id 2>/dev/null || true
echo "Wrote AppRole credentials to /vault/role-id and /vault/secret-id"

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

echo "Vault AppRole init complete. Vault Agent can authenticate with role-id/secret-id."
echo "You can leave VAULT_TOKEN in .env for future reseeds, or remove it and use AppRole only."
