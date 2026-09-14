#!/usr/bin/env bash
# Shared helpers for deploy infra tests.
# Source from a test script:  . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

_TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$_TEST_DIR/../scripts/lib.sh"

HA_CURL_IMG="${HA_CURL_IMG:-curlimages/curl:8.5.0}"

ha_require_env() {
  : "${REDIS_PASSWORD:?set REDIS_PASSWORD (same value seeded into Vault)}"
  export ASSUME_YES="${ASSUME_YES:-true}"
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

ha_ensure_curl_image() {
  local node
  for node in $(app_nodes); do
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

ha_banner() {
  printf '\n########################################\n# %s\n########################################\n' "$*"
}
