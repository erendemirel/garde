#!/bin/sh
# Unseal production Vault using keys from a line-oriented file.
#
# Create the keys file after first-time init (see docs/INSTALLATION.md):
#   jq -r '.unseal_keys_b64[]' vault-credentials.json > vault-unseal-keys
#   chmod 600 vault-unseal-keys
# Or manually put at least 3 unseal keys (one per line) into vault-unseal-keys.
#
# Usage (from repo root):
#   docker compose -f docker-compose.prod.yml --profile ops run --rm vault-unseal

set -e

export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
KEYS_FILE="${VAULT_UNSEAL_KEYS_FILE:-/vault-unseal-keys}"
THRESHOLD="${VAULT_UNSEAL_THRESHOLD:-3}"

if [ ! -f "$KEYS_FILE" ]; then
  echo "Missing unseal keys file: $KEYS_FILE"
  echo "After 'vault operator init -format=json > vault-credentials.json', create it with:"
  echo "  jq -r '.unseal_keys_b64[]' vault-credentials.json > vault-unseal-keys"
  echo "  chmod 600 vault-unseal-keys"
  echo "Never commit vault-credentials.json or vault-unseal-keys."
  exit 1
fi

echo "Vault address: $VAULT_ADDR"
echo "Waiting for Vault process to respond..."
i=0
# vault status: 0=unsealed, 2=sealed, other=unreachable/error
while true; do
  vault status >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
    break
  fi
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "Vault did not become reachable"
    exit 1
  fi
  sleep 1
done

if vault status >/dev/null 2>&1; then
  echo "Vault is already unsealed."
  exit 0
fi

count=0
while IFS= read -r key || [ -n "$key" ]; do
  # Skip blanks and comments
  case "$key" in ''|\#*) continue ;; esac
  count=$((count + 1))
  echo "Unsealing with key $count..."
  vault operator unseal "$key" >/dev/null
  if vault status >/dev/null 2>&1; then
    echo "Vault is unsealed."
    exit 0
  fi
  if [ "$count" -ge "$THRESHOLD" ]; then
    break
  fi
done < "$KEYS_FILE"

if vault status >/dev/null 2>&1; then
  echo "Vault is unsealed."
  exit 0
fi

echo "Vault is still sealed after applying $count key(s). Check vault-unseal-keys and threshold ($THRESHOLD)."
vault status || true
exit 1
