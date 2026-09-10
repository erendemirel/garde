#!/usr/bin/env bash
# Migrate an existing Shamir-sealed Raft cluster to AWS KMS auto-unseal.
# Operator-only: never run from CI.
#
# Prerequisites (do these first):
#   1. terraform apply in terraform/aws/ (KMS key + instance profile + IMDS hop 2)
#   2. VAULT_KMS_KEY_ID and AWS_REGION in deploy/inventory.env
#   3. Offline Shamir unseal keys available (VAULT_UNSEAL_KEYS_FILE or prompts)
#
# Then:
#   ./deploy/scripts/sync-config.sh --all
#   ./deploy/scripts/vault-seal-migrate.sh
#
# Per HashiCorp seal migration: each member is restarted with seal "awskms" in
# config, then `vault operator unseal -migrate` with the old Shamir keys.
# After success, store recovery material from vault-credentials.json offline;
# day-to-day reboots auto-unseal via KMS.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
need_cmd jq

[ -z "${CI:-}" ] || die "refusing to run in CI - unseal keys must not pass through a pipeline"

: "${VAULT_KMS_KEY_ID:?VAULT_KMS_KEY_ID missing from inventory — apply terraform/aws and merge inventory_fragment}"
: "${AWS_REGION:?AWS_REGION missing from inventory}"

THRESHOLD="${VAULT_UNSEAL_THRESHOLD:-3}"
CREDS_FILE="$REPO_ROOT/vault-credentials.json"

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

read_keys() {
  if [ -n "${VAULT_UNSEAL_KEYS_FILE:-}" ]; then
    [ -f "$VAULT_UNSEAL_KEYS_FILE" ] || die "keys file not found: $VAULT_UNSEAL_KEYS_FILE"
    grep -v '^\s*\(#\|$\)' "$VAULT_UNSEAL_KEYS_FILE"
  else
    local i=1 key
    while [ "$i" -le "$THRESHOLD" ]; do
      read -r -s -p "Shamir unseal key $i/$THRESHOLD: " key; printf '\n' >&2
      printf '%s\n' "$key"
      i=$((i + 1))
    done
  fi
}

step "Checking seal stanza is present on all nodes"
for node in $NODES; do
  require_node "$node"
  on_node "$node" "grep -q 'seal \"awskms\"' '$REMOTE_ROOT/config/vault/raft.hcl'" \
    || die "$node raft.hcl has no seal awskms — run: ./deploy/scripts/sync-config.sh --all"
  on_node "$node" "grep -q '$VAULT_KMS_KEY_ID' '$REMOTE_ROOT/config/vault/raft.hcl'" \
    || die "$node raft.hcl kms_key_id does not match VAULT_KMS_KEY_ID=$VAULT_KMS_KEY_ID"
done
ok "awskms seal configured for $VAULT_KMS_KEY_ID"

step "Preflight: instance profile + IMDS from Vault container network (hop limit >= 2)"
for node in $NODES; do
  on_node "$node" "
    set -e
    TOKEN=\$(curl -sf --connect-timeout 2 -X PUT \
      -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
      http://169.254.169.254/latest/api/token)
    ROLE=\$(curl -sf --connect-timeout 2 -H \"X-aws-ec2-metadata-token: \$TOKEN\" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/)
    [ -n \"\$ROLE\" ] || { echo 'no instance profile role on IMDS'; exit 1; }
    echo \"imds_role=\$ROLE\"
    # Share Vault's network namespace so hop limit is tested the same way awskms sees it.
    # (Vault image wget/busybox cannot reliably PUT for IMDSv2.)
    docker run --rm --network container:garde-vault curlimages/curl:8.5.0 -sf --connect-timeout 3 \
      -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
      http://169.254.169.254/latest/api/token >/dev/null \
      || { echo 'Vault network cannot reach IMDS — set http_put_response_hop_limit=2'; exit 1; }
  " || die "$node IMDS/instance-profile preflight failed (profile + hop limit 2 required before migrate)"
  ok "$node IMDS reachable from host and Vault network namespace"
done

KEYS="$(read_keys)"
[ -n "$KEYS" ] || die "no Shamir unseal keys provided"

migrate_node() {
  local node="$1" applied=0
  step "Migrating $node"

  # Restart so the new seal stanza is loaded; member comes back sealed for migrate.
  # Must use the same project name as deploy.sh (garde-vault-node) or Compose
  # creates a fresh empty raft volume and fights the existing container name.
  on_node "$node" "cd '$REMOTE_ROOT' && docker compose --env-file .env -p garde-vault-node -f compose/vault-node.yml up -d --force-recreate vault"

  # Wait until the API accepts connections (recreate is not instant).
  local i=0
  while [ "$i" -lt 60 ]; do
    if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1" \
      || on_node "$node" "docker exec garde-vault vault status 2>&1 | grep -qi sealed"; then
      break
    fi
    sleep 2
    i=$((i + 1))
  done
  [ "$i" -lt 60 ] || die "$node Vault API never came up after recreate — check docker logs garde-vault"

  if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
    ok "$node already unsealed (migration may already be done)"
    return 0
  fi

  while IFS= read -r key; do
    [ -z "$key" ] && continue
    applied=$((applied + 1))
    on_node "$node" "docker exec -e VAULT_ADDR=http://127.0.0.1:8200 garde-vault \
      vault operator unseal -migrate '$key' >/dev/null" || warn "migrate key $applied rejected on $node"
    if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
      ok "$node migrated and unsealed after $applied key(s)"
      return 0
    fi
    [ "$applied" -ge "$THRESHOLD" ] && break
  done <<<"$KEYS"

  on_node "$node" "docker logs --tail 40 garde-vault" || true
  die "$node still sealed after migrate — check Vault logs and KMS permissions"
}

# Raft leader last when detectable; otherwise inventory app-primary last.
ORDER=""
LEADER=""
for node in $NODES; do
  if on_node "$node" "docker exec garde-vault vault status -format=json 2>/dev/null" \
      | grep -q '"is_self"[[:space:]]*:[[:space:]]*true'; then
    LEADER="$node"
  fi
done
if [ -n "$LEADER" ]; then
  for node in $NODES; do
    [ "$node" = "$LEADER" ] && continue
    ORDER="$ORDER $node"
  done
  ORDER="$ORDER $LEADER"
  log "Raft leader $LEADER will migrate last"
else
  for node in $NODES; do
    case "$(node_role "$node")" in
      app-primary) ;;
      *) ORDER="$ORDER $node" ;;
    esac
  done
  for node in $NODES; do
    case "$(node_role "$node")" in
      app-primary) ORDER="$ORDER $node" ;;
    esac
  done
  warn "could not detect Raft leader — migrating inventory app-primary last"
fi

for node in $ORDER; do
  migrate_node "$node"
done

step "Verifying cluster"
"$DEPLOY_DIR/scripts/healthcheck.sh" --all || warn "healthcheck reported issues; inspect before leaving"

cat <<EOF

Seal migration complete.

  - Reboots should auto-unseal via KMS ($VAULT_KMS_KEY_ID).
  - Keep offline recovery/unseal material from $CREDS_FILE (or your Shamir
    key backup) for break-glass generate-root / rekey.
  - unseal.sh is no longer part of the reboot runbook.

EOF
