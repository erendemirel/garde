#!/usr/bin/env bash
# Report bring-up progress for a garde cluster without requiring a working app.
#
#   ./deploy/scripts/doctor.sh
#   ./deploy/scripts/doctor.sh --strict          # exit 1 if any required stage fails
#   ./deploy/scripts/doctor.sh --provider aws    # also check terraform/aws state
#
# Stages (automated evidence where possible; otherwise missing/skipped):
#   infra -> inventory -> dns -> access -> host-baseline -> vault -> images -> app
#
# Manual checklist that pairs with this: docs/AWS_BRINGUP.md

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

STRICT=false
FORCE_PROVIDER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --strict)   STRICT=true; shift ;;
    --provider) FORCE_PROVIDER="$2"; shift 2 ;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

MISSING=0
skip() { printf '  skip  %s\n' "$*"; }
miss() { MISSING=$((MISSING + 1)); printf '%s  miss%s  %s\n' "$_c_red" "$_c_reset" "$*"; }
have() { printf '%s  ok%s    %s\n' "$_c_green" "$_c_reset" "$*"; }
note() { printf '  ....  %s\n' "$*"; }

INV_OK=false
reachable=0
if [ -f "$INVENTORY_FILE" ]; then
  # load_inventory calls die on hard errors; isolate that in a subshell.
  if ( load_inventory ); then
    load_inventory
    INV_OK=true
  else
    # shellcheck disable=SC1090
    set -a; . <(sed 's/\r$//' "$INVENTORY_FILE"); set +a
    INV_OK=true
    warn "load_inventory failed — continuing with raw inventory (access checks may fail)"
  fi
else
  miss "inventory file missing: $INVENTORY_FILE"
fi

PROVIDER_NAME_EFFECTIVE="${FORCE_PROVIDER:-${PROVIDER:-}}"

printf '\n==> 1/8 infra (cloud resources)\n'
case "$PROVIDER_NAME_EFFECTIVE" in
  aws)
    TF_DIR="$REPO_ROOT/terraform/aws"
    tf_ok=false
    if [ -d "$TF_DIR/.terraform" ] || [ -f "$TF_DIR/terraform.tfstate" ] \
        || [ -f "$TF_DIR/terraform.tfstate.d/default/terraform.tfstate" ]; then
      if command -v terraform >/dev/null 2>&1; then
        count="$(cd "$TF_DIR" && terraform state list 2>/dev/null | wc -l | tr -d ' ')"
        if [ "${count:-0}" -gt 0 ]; then
          have "terraform/aws state has $count resources"
          tf_ok=true
        else
          note "terraform/aws initialized but state is empty"
        fi
      else
        note "terraform CLI not installed; cannot list state"
      fi
    else
      note "no local terraform/aws state (ok if apply ran elsewhere / remote backend)"
    fi
    if [ -n "${NODE1_PROVIDER_ID:-}" ] && [ -n "${NODE2_PROVIDER_ID:-}" ] && [ -n "${NODE3_PROVIDER_ID:-}" ] \
        && [ -n "${FAILOVER_IP:-}" ]; then
      have "inventory has 3 instance ids + FAILOVER_IP (infra was provisioned)"
      tf_ok=true
    fi
    if [ "$tf_ok" != "true" ]; then
      miss "no terraform state and no AWS instance ids in inventory — run ./terraform/aws/bring-up.sh"
    fi
    ;;
  "")
    skip "PROVIDER unset — fill inventory or pass --provider aws"
    ;;
  *)
    skip "PROVIDER=$PROVIDER_NAME_EFFECTIVE (infra doctor focuses on aws terraform module)"
    ;;
esac

printf '\n==> 2/8 inventory\n'
if [ "$INV_OK" = "true" ]; then
  have "inventory.env present"
  for key in PROVIDER NODES SSH_USER REMOTE_ROOT PRIMARY_NODE STANDBY_NODE FAILOVER_IP; do
    eval "val=\${$key:-}"
    if [ -z "$val" ]; then miss "inventory missing $key"
    else have "$key=$val"; fi
  done
  if [ "${PROVIDER:-}" = "aws" ]; then
    for key in AWS_REGION ADMIN_SSH_SOURCES AWS_IMAGE_BUCKET \
               NODE1_PROVIDER_ID NODE2_PROVIDER_ID NODE3_PROVIDER_ID \
               NODE1_MESH_ENDPOINT NODE2_MESH_ENDPOINT NODE3_MESH_ENDPOINT; do
      eval "val=\${$key:-}"
      if [ -z "$val" ]; then miss "AWS inventory missing $key (merge bring-up fragment)"
      else have "$key set"; fi
    done
  fi
  case "${API_DOMAIN:-}" in
    ''|*.example.com|*.example.org) note "API_DOMAIN is placeholder (${API_DOMAIN:-empty}) — OK until real DNS" ;;
    *) have "API_DOMAIN=$API_DOMAIN" ;;
  esac
else
  miss "cannot validate inventory keys"
fi

printf '\n==> 3/8 dns / tls intent\n'
case "${API_DOMAIN:-}${APP_DOMAIN:-}" in
  *example.com*|*example.org*|*example.net*|'')
    skip "domains still placeholders — public HTTPS not expected yet"
    ;;
  *)
    have "real-looking domains configured"
    if [ "${PROVIDER:-}" = "aws" ] && [ -n "${AWS_ACME_ACCESS_KEY_ID:-}" ]; then
      have "AWS_ACME_ACCESS_KEY_ID present in environment"
    elif [ "${PROVIDER:-}" = "aws" ]; then
      note "AWS_ACME_* not in this shell (needed for Caddy DNS-01 on deploy)"
    fi
    ;;
esac
if [ -n "${ACME_EMAIL:-}" ] && ! printf '%s' "$ACME_EMAIL" | grep -qi 'example'; then
  have "ACME_EMAIL set"
else
  note "ACME_EMAIL missing or placeholder"
fi

printf '\n==> 4/8 access (control plane to hosts)\n'
if [ "$INV_OK" = "true" ] && [ -n "${PROVIDER:-}" ] && [ -n "${NODES:-}" ]; then
  for node in $NODES; do
    if on_node "$node" "true" 2>/dev/null; then
      have "$node reachable"
      reachable=$((reachable + 1))
    else
      miss "$node unreachable (bootstrap / tunnel / SG?)"
    fi
  done
  [ "$reachable" -gt 0 ] || note "no nodes reachable — Ansible/bootstrap likely not done"
else
  skip "need inventory + PROVIDER to probe access"
fi

printf '\n==> 5/8 host baseline (Ansible outcomes)\n'
if [ "$reachable" -gt 0 ]; then
  for node in $NODES; do
    on_node "$node" "true" 2>/dev/null || continue
    if on_node "$node" "command -v docker >/dev/null"; then
      have "$node: docker installed"
    else
      miss "$node: docker missing — run ansible bootstrap"
    fi
    if on_node "$node" "ip link show wg0 >/dev/null 2>&1 || wg show wg0 >/dev/null 2>&1"; then
      have "$node: WireGuard wg0 up"
    else
      miss "$node: wg0 missing — run ansible bootstrap / wg-gen"
    fi
    if on_node "$node" "id '${SSH_USER:-deploy}' >/dev/null 2>&1"; then
      have "$node: deploy user ${SSH_USER:-deploy} exists"
    else
      note "$node: deploy user not found yet (bootstrap creates it)"
    fi
  done
else
  skip "no reachable nodes — cannot check host baseline"
fi

printf '\n==> 6/8 vault\n'
if [ "$reachable" -gt 0 ]; then
  vault_nodes=0; unsealed=0; inited=0
  for node in $NODES; do
    on_node "$node" "true" 2>/dev/null || continue
    if ! on_node "$node" "docker inspect garde-vault >/dev/null 2>&1"; then
      note "$node: no garde-vault container yet"
      continue
    fi
    vault_nodes=$((vault_nodes + 1))
    json="$(on_node "$node" "docker exec garde-vault vault status -format=json 2>/dev/null || true")"
    if printf '%s' "$json" | grep -q '"initialized"[[:space:]]*:[[:space:]]*true'; then
      inited=$((inited + 1))
    fi
    if on_node "$node" "docker exec garde-vault vault status >/dev/null 2>&1"; then
      unsealed=$((unsealed + 1))
      have "$node: vault unsealed"
    elif [ -n "$json" ]; then
      note "$node: vault present but sealed (or not ready)"
    fi
  done
  if [ "$vault_nodes" -eq 0 ]; then
    miss "no Vault containers — deploy vault stack"
  else
    have "vault containers on $vault_nodes node(s); initialized≈$inited unsealed=$unsealed"
  fi
else
  skip "no reachable nodes — cannot check Vault"
fi

printf '\n==> 7/8 images\n'
if [ "$reachable" -gt 0 ]; then
  for node in ${PRIMARY_NODE:-} ${STANDBY_NODE:-}; do
    [ -n "$node" ] || continue
    on_node "$node" "true" 2>/dev/null || continue
    if on_node "$node" "docker images --format '{{.Repository}}' | grep -q '^garde/'"; then
      have "$node: garde/* images present"
    else
      miss "$node: no garde/* images — build + ship-image"
    fi
  done
else
  skip "no reachable nodes — cannot check images"
fi

printf '\n==> 8/8 app (optional for bring-up tracking)\n'
if [ -n "${PRIMARY_NODE:-}" ] && on_node "${PRIMARY_NODE}" "true" 2>/dev/null; then
  if on_node "$PRIMARY_NODE" "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health" 2>/dev/null; then
    have "primary /health OK"
  else
    note "primary /health not OK yet — expected until app deploy finishes"
  fi
else
  skip "primary not reachable — app stage later"
fi

printf '\n==> secrets in this environment (presence only)\n'
for key in REDIS_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_ACME_ACCESS_KEY_ID; do
  eval "val=\${$key:-}"
  if [ -n "$val" ]; then have "$key is set"
  else note "$key not set in this shell"; fi
done
if [ -n "${VAULT_UNSEAL_KEYS_FILE:-}" ] && [ -f "$VAULT_UNSEAL_KEYS_FILE" ]; then
  have "VAULT_UNSEAL_KEYS_FILE present"
else
  note "VAULT_UNSEAL_KEYS_FILE unset (needed for unseal / hard HA tests)"
fi

printf '\n==> result\n'
if [ "$MISSING" -eq 0 ]; then
  ok "doctor: no missing required evidence in checked stages"
  summary "doctor: all checked stages ok or skipped"
else
  warn "doctor: $MISSING item(s) missing — see docs/AWS_BRINGUP.md"
  summary "doctor: $MISSING missing"
  if [ "$STRICT" = "true" ]; then
    die "$MISSING required bring-up item(s) missing"
  fi
fi
