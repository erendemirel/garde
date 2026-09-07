#!/usr/bin/env bash
# netcup driver: failover IP routing and server power through the SCP REST API.
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects, because ansible/inventory-to-json.sh reads the
# declared facts out of it without loading the rest of the shell library.
#
# Auth is OAuth2 (Keycloak realm "scp", client "scp"). A long-lived refresh
# token buys a 300-second access token on each run, so only the refresh token
# is stored. Obtain it once with:
#
#   curl -s -X POST 'https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect/token' \
#     -d 'client_id=scp' -d 'grant_type=password' -d 'scope=offline_access openid' \
#     -d 'username=<customer-number>' -d 'password=<scp-password>' | jq -r .refresh_token
#
# It expires after 30 days of inactivity.

PROVIDER_NAME="netcup"
PROVIDER_CREDENTIALS="NETCUP_SCP_REFRESH_TOKEN"

# netcup rejects a second reassignment of the same IP within 301 seconds. This
# is the single most consequential fact about failing over here: it makes a
# cutover one-way for five minutes, so the direction is a decision you commit to.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=301

# Routing is applied asynchronously; the API returns before traffic moves.
PROVIDER_TRAFFIC_PROPAGATION_SECONDS=60

# netcup routes the address to the server, but the host must also have it
# configured on its interface or the kernel drops the packets.
PROVIDER_REQUIRES_IP_BINDING=true

_NETCUP_KEYCLOAK="https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect/token"
_NETCUP_API="https://www.servercontrolpanel.de/scp-core/api/v1"
_netcup_token_cache=""
_netcup_user_cache=""

provider_preflight() {
  need_cmd curl
  need_cmd jq
  provider_require_credentials
}

_netcup_token() {
  if [ -z "$_netcup_token_cache" ]; then
    local resp
    resp="$(curl -s -X POST "$_NETCUP_KEYCLOAK" \
      -d 'client_id=scp' \
      -d 'grant_type=refresh_token' \
      --data-urlencode "refresh_token=$NETCUP_SCP_REFRESH_TOKEN")"
    _netcup_token_cache="$(printf '%s' "$resp" | jq -r '.access_token // empty')"
    [ -n "$_netcup_token_cache" ] \
      || die "could not get a netcup access token. The refresh token may have expired (30 days) - re-issue it."
  fi
  printf '%s' "$_netcup_token_cache"
}

# The /users/{userId}/ endpoints want the internal Keycloak id from the JWT,
# which is not the customer number.
_netcup_user_id() {
  if [ -z "$_netcup_user_cache" ]; then
    local payload
    payload="$(_netcup_token | cut -d. -f2)"
    case $(( ${#payload} % 4 )) in
      2) payload="$payload==" ;;
      3) payload="$payload=" ;;
    esac
    _netcup_user_cache="$(printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.id // empty')"
    [ -n "$_netcup_user_cache" ] || die "could not extract the user id from the netcup access token"
  fi
  printf '%s' "$_netcup_user_cache"
}

_netcup_api() {
  local method="$1" path="$2" body="${3:-}" token
  token="$(_netcup_token)"
  if [ -n "$body" ]; then
    curl -s -X "$method" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/merge-patch+json" \
      -d "$body" "$_NETCUP_API$path"
  else
    curl -s -X "$method" -H "Authorization: Bearer $token" "$_NETCUP_API$path"
  fi
}

_netcup_failover_ips() {
  _netcup_api GET "/users/$(_netcup_user_id)/failoverips/v4"
}

# Responses have been seen both as a bare array and wrapped; accept either.
_netcup_unwrap() { jq '(if type=="array" then . else (.data // .items // []) end)'; }

_netcup_ip_id() {
  if [ -n "${FAILOVER_IP_ID:-}" ]; then printf '%s' "$FAILOVER_IP_ID"; return; fi
  : "${FAILOVER_IP:?set FAILOVER_IP or FAILOVER_IP_ID in the inventory}"

  local list id editable
  list="$(_netcup_failover_ips | _netcup_unwrap)"
  id="$(printf '%s' "$list" | jq -r --arg ip "$FAILOVER_IP" '.[] | select(.ip == $ip) | .id' | head -n1)"
  [ -n "$id" ] && [ "$id" != "null" ] || die "failover IP $FAILOVER_IP not found in your SCP account"

  editable="$(printf '%s' "$list" | jq -r --arg ip "$FAILOVER_IP" '.[] | select(.ip == $ip) | .editable' | head -n1)"
  [ "$editable" = "true" ] || die "failover IP $FAILOVER_IP is not editable via the API (editable=$editable)"

  printf '%s' "$id"
}

provider_route_traffic_to() {
  local node="$1" server_id resp
  server_id="$(node_provider_id "$node")"
  [ -n "$server_id" ] || die "no provider id configured for $node (set NODE*_PROVIDER_ID)"
  provider_preflight

  resp="$(_netcup_api PATCH "/users/$(_netcup_user_id)/failoverips/v4/$(_netcup_ip_id)" \
    "$(jq -nc --arg s "$server_id" '{serverId: $s}')")"

  if printf '%s' "$resp" | jq -e '.error // .message // empty' >/dev/null 2>&1; then
    printf '%s\n' "$resp" >&2
    die "netcup rejected the reassignment"
  fi
  ok "netcup accepted the reassignment to $node ($server_id)"
}

provider_traffic_location() {
  provider_preflight
  local server_id
  server_id="$(_netcup_failover_ips | _netcup_unwrap \
    | jq -r --arg ip "${FAILOVER_IP:-}" '.[] | select(.ip == $ip) | .serverId // empty' | head -n1)"
  [ -n "$server_id" ] || return 0
  node_for_provider_id "$server_id"
}

provider_set_power() {
  local node="$1" state="$2" server_id resp netcup_state
  server_id="$(node_provider_id "$node")"
  [ -n "$server_id" ] || die "no provider id configured for $node"
  provider_preflight

  # The API is case-sensitive and calls the running state "running".
  case "$state" in
    off)   netcup_state="off" ;;
    on)    netcup_state="running" ;;
    reset) netcup_state="reset" ;;
    *) die "unsupported power state '$state'" ;;
  esac

  # One attribute per PATCH, with merge-patch semantics.
  resp="$(_netcup_api PATCH "/servers/$server_id" \
    "$(jq -nc --arg s "$netcup_state" '{state: $s}')")"
  printf '%s\n' "$resp" | jq '.' 2>/dev/null || printf '%s\n' "$resp"
  ok "netcup accepted the power request (applied asynchronously)"
}
