#!/bin/sh
# Vault initialization script for dev environment
# Reads secrets from dev.secrets file and seeds them into Vault

set -e

export VAULT_ADDR="${VAULT_ADDR:-http://dev-vault:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-devtoken}"

echo "Vault address: $VAULT_ADDR"
echo "Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
  echo "  Vault not ready yet, retrying..."
  sleep 1
done
echo "Vault is ready!"

# Auto-create the Vault Agent token file on a shared volume so fresh clones
# do not need a host-side vault/dev-token file (which is gitignored).
TOKEN_DIR="${VAULT_AGENT_TOKEN_DIR:-/vault/agent-token}"
mkdir -p "$TOKEN_DIR"
printf '%s\n' "${VAULT_TOKEN:-devtoken}" > "$TOKEN_DIR/dev-token"
# Vault Agent drops to the non-root `vault` user and must be able to read this.
if id vault >/dev/null 2>&1; then
  chown vault:vault "$TOKEN_DIR/dev-token"
  chmod 600 "$TOKEN_DIR/dev-token"
else
  chmod 644 "$TOKEN_DIR/dev-token"
fi
echo "Wrote Vault Agent token to $TOKEN_DIR/dev-token"

# Enable KV secrets engine if not already enabled
vault secrets enable -path=secret kv-v2 2>/dev/null || true

echo "Seeding secrets from dev.secrets..."

# Read dev.secrets and write each noncomment, nonempty line to Vault
# We'll store all secrets under secret/garde/

# Parse the dev.secrets file and create individual secret files for Vault Agent
while IFS='=' read -r key value || [ -n "$key" ]; do
  # Skip empty lines and comments
  case "$key" in
    ''|\#*) continue ;;
  esac
  
  # Remove any leading/trailing whitespace
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)

  # Allow empty values so optional keys (e.g. TRUSTED_PROXIES=) still exist for Vault Agent templates
  if [ -n "$key" ]; then
    lower_key=$(echo "$key" | tr '[:upper:]' '[:lower:]')
    echo "  Setting secret: $lower_key"
    vault kv put "secret/garde/$lower_key" value="$value"
  fi
done < /dev.secrets

echo "All secrets seeded successfully!"
echo "Vault is ready for Vault Agent to fetch secrets."

