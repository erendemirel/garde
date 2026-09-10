#!/usr/bin/env bash
# Unseal a Vault member (Shamir only). Operator-only: never run this from CI.
#
#   ./deploy/scripts/unseal.sh node1
#   ./deploy/scripts/unseal.sh --all
#
# With VAULT_KMS_KEY_ID (awskms auto-unseal), members unseal themselves after
# reboot. This script is then only useful if a member is still sealed (KMS/IMDS
# failure) — it cannot substitute for fixing IAM/KMS. For Shamir → awskms
# migration, use deploy/scripts/vault-seal-migrate.sh instead.
#
# Unseal keys are read interactively or from VAULT_UNSEAL_KEYS_FILE. They must
# never be stored in GitHub secrets or on the servers.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory

[ -z "${CI:-}" ] || die "refusing to run in CI - unseal keys must not pass through a pipeline"

if [ -n "${VAULT_KMS_KEY_ID:-}" ]; then
  warn "inventory has VAULT_KMS_KEY_ID=$VAULT_KMS_KEY_ID (awskms)."
  warn "Prefer fixing KMS/IMDS if a member stays sealed after reboot."
  warn "Continuing with Shamir unseal keys only if this cluster has not migrated yet."
fi

TARGETS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --all) TARGETS="$NODES"; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) TARGETS="$TARGETS $1"; shift ;;
  esac
done
[ -n "${TARGETS// /}" ] || die "usage: unseal.sh <node>... | --all"

THRESHOLD="${VAULT_UNSEAL_THRESHOLD:-3}"

read_keys() {
  if [ -n "${VAULT_UNSEAL_KEYS_FILE:-}" ]; then
    [ -f "$VAULT_UNSEAL_KEYS_FILE" ] || die "keys file not found: $VAULT_UNSEAL_KEYS_FILE"
    grep -v '^\s*\(#\|$\)' "$VAULT_UNSEAL_KEYS_FILE"
  else
    local i=1 key
    while [ "$i" -le "$THRESHOLD" ]; do
      read -r -s -p "Unseal key $i/$THRESHOLD: " key; printf '\n' >&2
      printf '%s\n' "$key"
      i=$((i + 1))
    done
  fi
}

KEYS="$(read_keys)"
[ -n "$KEYS" ] || die "no unseal keys provided"

for node in $TARGETS; do
  require_node "$node"
  step "$node ($(node_vault_id "$node"))"

  if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
    ok "already unsealed"
    continue
  fi

  applied=0
  while IFS= read -r key; do
    [ -z "$key" ] && continue
    applied=$((applied + 1))
    on_node "$node" "docker exec -e VAULT_ADDR=http://127.0.0.1:8200 garde-vault vault operator unseal '$key' >/dev/null" \
      || warn "key $applied was rejected"
    if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
      ok "unsealed after $applied key(s)"
      break
    fi
    [ "$applied" -ge "$THRESHOLD" ] && break
  done <<<"$KEYS"

  if ! on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
    die "$node is still sealed after $applied key(s)"
  fi
done

step "Cluster state"
"$DEPLOY_DIR/scripts/healthcheck.sh" --all || true
