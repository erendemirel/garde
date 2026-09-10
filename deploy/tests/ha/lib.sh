#!/usr/bin/env bash
# Shared helpers for the HA infra test suite.
# Source from a test script:  . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
# or from a nested test:      . "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh"

# Resolve this file's directory regardless of how deep the caller sits.
_HA_TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$_HA_TEST_DIR/../../scripts/lib.sh"

HA_CURL_IMG="${HA_CURL_IMG:-curlimages/curl:8.5.0}"

# Operator-facing prerequisites. Secrets never live in the suite.
ha_require_env() {
  : "${REDIS_PASSWORD:?set REDIS_PASSWORD (same value seeded into Vault)}"
  export ASSUME_YES="${ASSUME_YES:-true}"
  # Placeholder DNS-01 so sync-config does not die on example.com domains.
  export NETCUP_CUSTOMER_NUMBER="${NETCUP_CUSTOMER_NUMBER:-0}"
  export NETCUP_API_KEY="${NETCUP_API_KEY:-unused}"
  export NETCUP_API_PASSWORD="${NETCUP_API_PASSWORD:-unused}"
  export AWS_ACME_ACCESS_KEY_ID="${AWS_ACME_ACCESS_KEY_ID:-unused}"
  export AWS_ACME_SECRET_ACCESS_KEY="${AWS_ACME_SECRET_ACCESS_KEY:-unused}"
}

ha_boot() {
  ha_require_env
  load_inventory
  load_provider
}

ha_scripts() { printf '%s' "$DEPLOY_DIR/scripts"; }

redis_cli_on() {
  local node="$1"; shift
  on_node "$node" "set -a; . '$REMOTE_ROOT/.env'; set +a; \
    docker exec garde-redis redis-cli -a \"\$REDIS_PASSWORD\" --no-auth-warning $*"
}

# HTTP against garde-api via a curl sidecar sharing its network namespace.
ha_ensure_curl_image() {
  local node
  for node in ${PRIMARY_NODE:-} ${STANDBY_NODE:-}; do
    [ -n "$node" ] || continue
    on_node "$node" "docker image inspect $HA_CURL_IMG >/dev/null 2>&1 || docker pull $HA_CURL_IMG" >/dev/null
  done
}

http_api() {
  local node="$1" method="$2" path="$3" body="${4:-}" token="${5:-}"
  local remote_body="/tmp/ha-http-body.json"
  if [ -n "$body" ]; then
    on_node "$node" "printf '%s' $(printf '%q' "$body") > $remote_body"
  else
    on_node "$node" "rm -f $remote_body"
  fi
  on_node "$node" "
    extra=()
    vol=()
    if [ -n '$body' ]; then
      extra+=(-H 'Content-Type: application/json' --data-binary @$remote_body)
      vol+=(-v $remote_body:$remote_body:ro)
    fi
    [ -n '$token' ] && extra+=(-H 'Authorization: Bearer $token')
    docker run --rm --network container:garde-api \"\${vol[@]}\" $HA_CURL_IMG \
      curl -sS -w '\n%{http_code}' -X $method \"\${extra[@]}\" 'http://127.0.0.1:8443$path'
  "
}

http_code() { printf '%s' "$1" | tail -n1; }
http_body() { printf '%s' "$1" | sed '$d'; }

ha_login() {
  local node="$1"
  : "${SUPERUSER_EMAIL:?set SUPERUSER_EMAIL}"
  : "${SUPERUSER_PASSWORD:?set SUPERUSER_PASSWORD}"
  local out sid
  out="$(http_api "$node" POST /login \
    "$(printf '{"email":"%s","password":"%s"}' "$SUPERUSER_EMAIL" "$SUPERUSER_PASSWORD")")"
  [ "$(http_code "$out")" = "200" ] || die "login failed on $node: $out"
  sid="$(http_body "$out" | sed -n 's/.*"session_id":"\([^"]*\)".*/\1/p')"
  [ -n "$sid" ] || die "no session_id in login response"
  printf '%s' "$sid"
}

ha_set_roles() {
  local primary="$1" standby="$2" n1role n2role
  if [ "$primary" = node1 ]; then n1role=app-primary; n2role=app-standby
  else n1role=app-standby; n2role=app-primary; fi
  [ -w "$INVENTORY_FILE" ] || die "inventory not writable: $INVENTORY_FILE"
  sed -i \
    -e "s/^PRIMARY_NODE=.*/PRIMARY_NODE=$primary/" \
    -e "s/^STANDBY_NODE=.*/STANDBY_NODE=$standby/" \
    -e "s/^NODE1_ROLE=.*/NODE1_ROLE=$n1role/" \
    -e "s/^NODE2_ROLE=.*/NODE2_ROLE=$n2role/" \
    "$INVENTORY_FILE"
  load_inventory
}

# Bring a fenced/powered-off app node back as Redis replica of the current primary.
ha_revive_standby() {
  local node="$1" primary="${2:-$PRIMARY_NODE}"
  ha_set_roles "$primary" "$node"
  compose_on "$node" app up -d || true
  retry_until 24 5 on_node "$node" \
    "docker inspect -f '{{.State.Running}}' garde-redis 2>/dev/null | grep -q true" || true
  "$(ha_scripts)/redis-replicate.sh" "$node"
  compose_on "$node" app up -d
  retry_until 36 5 on_node "$node" \
    "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health" \
    || die "$node did not become healthy as standby"
  ok "$node is standby replica of $primary"
}

ha_restore_default_topology() {
  # Canonical layout used by the AWS reference: node1 primary, node2 standby.
  if [ "${PRIMARY_NODE:-}" != node1 ]; then
    if [ "$(node_role node1 2>/dev/null || true)" != "app-standby" ] \
        || ! on_node node1 "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health" 2>/dev/null; then
      ha_revive_standby node1 "$PRIMARY_NODE"
    fi
    "$(ha_scripts)/sqlite-snapshot.sh" --from "$PRIMARY_NODE"
    "$(ha_scripts)/failover.sh" --to node1 --from "$PRIMARY_NODE" --reason "ha-test restore topology"
    load_inventory
  fi
  ha_set_roles node1 node2
  if ! on_node node2 "docker exec garde-api wget -q -O /dev/null http://127.0.0.1:8443/health" 2>/dev/null; then
    ha_revive_standby node2 node1
  else
    "$(ha_scripts)/redis-replicate.sh" node2 || true
  fi
}

ha_vault_ha_mode() {
  on_node "$1" "docker exec -e VAULT_ADDR=http://127.0.0.1:8200 garde-vault vault status 2>/dev/null" \
    | tr -d '\r' | awk -F'[[:space:]]{2,}' '/HA Mode/{print $2; exit}'
}

ha_find_vault_leader() {
  local node mode
  for node in $NODES; do
    mode="$(ha_vault_ha_mode "$node" || true)"
    if [ "$mode" = "active" ]; then
      printf '%s' "$node"
      return 0
    fi
  done
  return 1
}

ha_require_unseal_keys() {
  # Shamir-only. AWS awskms drills wait via ha_unseal and must not demand a keys file.
  if [ -n "${VAULT_KMS_KEY_ID:-}" ]; then
    return 0
  fi
  [ -n "${VAULT_UNSEAL_KEYS_FILE:-}" ] && [ -f "$VAULT_UNSEAL_KEYS_FILE" ] \
    || die "set VAULT_UNSEAL_KEYS_FILE to an offline file of unseal keys (never commit it), or VAULT_KMS_KEY_ID for awskms"
}

# After reboot/fence: wait for awskms auto-unseal when configured; otherwise Shamir.
ha_unseal() {
  if [ -n "${VAULT_KMS_KEY_ID:-}" ]; then
    local node
    for node in "$@"; do
      log "waiting for awskms auto-unseal on $node"
      retry_until 60 5 on_node "$node" \
        "docker exec garde-vault vault status >/dev/null 2>&1" \
        || die "$node stayed sealed under awskms — check KMS/IMDS"
    done
    return 0
  fi
  ha_require_unseal_keys
  "$(ha_scripts)/unseal.sh" "$@"
}

ha_banner() {
  printf '\n########################################\n# %s\n########################################\n' "$*"
}
