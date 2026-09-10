#!/usr/bin/env bash
# Deploy one or more stacks across the cluster.
#
#   ./deploy/scripts/deploy.sh all
#   ./deploy/scripts/deploy.sh app --node node2
#   ./deploy/scripts/deploy.sh vault --dry-run
#
# Stacks:
#   vault      Raft member (all nodes)      - rolling, one at a time
#   metrics    exporters (all nodes)
#   app        caddy/garde/redis/agent      - app nodes only, standby first
#   monitoring prometheus + grafana         - witness only
#   all        every stack, in a safe order
#
# Order matters. Vault members are updated one at a time so quorum survives,
# and the standby app node is updated before the primary so a bad build is
# caught on the node that serves no traffic.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory

STACK=""; ONLY_NODE=""; DRY_RUN=false; SKIP_SHIP=false; SKIP_SYNC=false
while [ $# -gt 0 ]; do
  case "$1" in
    --node)     ONLY_NODE="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=true; shift ;;
    --no-ship)  SKIP_SHIP=true; shift ;;
    --no-sync)  SKIP_SYNC=true; shift ;;
    -h|--help)  sed -n '2,18p' "$0"; exit 0 ;;
    *)          STACK="$1"; shift ;;
  esac
done
[ -n "$STACK" ] || die "usage: deploy.sh <vault|metrics|app|monitoring|all> [--node X]"

TAG="${IMAGE_TAG:-latest}"

run() {
  if [ "$DRY_RUN" = "true" ]; then
    printf '  would run: %s\n' "$*"
  else
    "$@"
  fi
}

nodes_for_stack() {
  case "$1" in
    vault|metrics) printf '%s' "$NODES" ;;
    app)
      # Standby first, then primary.
      local out="" n
      for n in $NODES; do
        [ "$(node_role "$n")" = "app-standby" ] && out="$out $n"
      done
      for n in $NODES; do
        [ "$(node_role "$n")" = "app-primary" ] && out="$out $n"
      done
      printf '%s' "${out# }"
      ;;
    monitoring)
      local n
      for n in $NODES; do
        [ "$(node_role "$n")" = "witness" ] && printf '%s ' "$n"
      done
      ;;
  esac
}

filter_node() {
  [ -z "$ONLY_NODE" ] && { printf '%s' "$1"; return; }
  local n out=""
  for n in $1; do [ "$n" = "$ONLY_NODE" ] && out="$n"; done
  printf '%s' "$out"
}

# --- config sync ----------------------------------------------------------

sync_targets="$(filter_node "$NODES")"
if [ "$SKIP_SYNC" = "false" ] && [ -n "${sync_targets// /}" ]; then
  step "Syncing configuration"
  # shellcheck disable=SC2086
  run "$DEPLOY_DIR/scripts/sync-config.sh" $sync_targets
fi

# --- image shipping -------------------------------------------------------

ship_app_images() {
  local node="$1"
  [ "$SKIP_SHIP" = "true" ] && return 0
  run "$DEPLOY_DIR/scripts/ship-image.sh" "$node" \
    "${GARDE_IMAGE:-garde/api}:$TAG" \
    "${UI_IMAGE:-garde/ui}:$TAG" \
    "${CADDY_IMAGE:-garde/caddy}:$TAG"
}

# --- stack deployers ------------------------------------------------------

deploy_vault() {
  local node="$1"
  step "vault -> $node ($(node_vault_id "$node"))"
  run compose_on "$node" vault-node up -d

  [ "$DRY_RUN" = "true" ] && return 0

  # A restarted member comes back sealed under Shamir; with awskms it should
  # auto-unseal via KMS. Wait briefly, but do not block the deploy.
  if retry_until 15 4 on_node "$node" \
      "docker exec garde-vault vault status >/dev/null 2>&1"; then
    ok "$node vault is unsealed and serving"
  else
    warn "$node vault is sealed or still starting"
    if [ -n "${VAULT_KMS_KEY_ID:-}" ]; then
      warn "  awskms: check instance profile, IMDS hop limit 2, and KMS key $VAULT_KMS_KEY_ID"
    else
      warn "  unseal it with: ./deploy/scripts/unseal.sh $node"
    fi
    warn "  the other members keep serving in the meantime"
  fi
}

deploy_metrics() {
  local node="$1"
  step "metrics -> $node"
  run compose_on "$node" metrics-agent up -d
}

deploy_app() {
  local node="$1" role
  role="$(node_role "$node")"
  step "app -> $node ($role)"

  if ! on_node "$node" "test -s '$REMOTE_ROOT/vault/role-id' && test -s '$REMOTE_ROOT/vault/secret-id'"; then
    die "$node has no Vault AppRole credentials at $REMOTE_ROOT/vault/{role-id,secret-id}
     Run the one-time Vault init described in docs/DEPLOY.md first."
  fi

  ship_app_images "$node"
  run compose_on "$node" app up -d --remove-orphans

  [ "$DRY_RUN" = "true" ] && return 0

  if retry_until 20 5 on_node "$node" \
      "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health"; then
    ok "$node garde is healthy"
  else
    on_node "$node" "cd '$REMOTE_ROOT' && docker compose -f compose/app.yml -p garde-app logs --tail 40 garde" || true
    die "$node garde did not become healthy"
  fi
}

deploy_monitoring() {
  local node="$1"
  step "monitoring -> $node"
  run compose_on "$node" monitoring up -d
}

# --- run ------------------------------------------------------------------

deploy_stack() {
  local stack="$1" node
  for node in $(filter_node "$(nodes_for_stack "$stack")"); do
    case "$stack" in
      vault)      deploy_vault "$node" ;;
      metrics)    deploy_metrics "$node" ;;
      app)        deploy_app "$node" ;;
      monitoring) deploy_monitoring "$node" ;;
    esac
  done
}

case "$STACK" in
  all)
    deploy_stack metrics
    deploy_stack vault
    deploy_stack app
    deploy_stack monitoring
    ;;
  vault|metrics|app|monitoring) deploy_stack "$STACK" ;;
  *) die "unknown stack: $STACK" ;;
esac

if [ "$DRY_RUN" = "true" ]; then
  ok "dry run complete, nothing was changed"
  exit 0
fi

step "Post-deploy health"
if [ -n "$ONLY_NODE" ]; then
  "$DEPLOY_DIR/scripts/healthcheck.sh" "$ONLY_NODE"
else
  "$DEPLOY_DIR/scripts/healthcheck.sh" --all
fi

summary "Deployed stack '$STACK' at tag $TAG"
