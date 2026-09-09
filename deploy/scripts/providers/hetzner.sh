#!/usr/bin/env bash
# Hetzner Cloud driver: floating IP routing and server power through the
# public API at api.hetzner.cloud.
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects.
#
# Auth is a single project API token, created under Security > API tokens in
# the Hetzner Cloud console with read/write scope:
#
#   HCLOUD_TOKEN=...
#
# It does not expire, so unlike the netcup refresh token there is nothing to
# re-issue on a schedule.
#
# Inventory mapping for this provider:
#   NODE*_PROVIDER_ID   numeric server id (hcloud server list)
#   FAILOVER_IP_ID      numeric floating IP id, or leave empty to resolve by IP
#   FAILOVER_IP         the floating IP address itself

PROVIDER_NAME="Hetzner Cloud"
PROVIDER_CREDENTIALS="HCLOUD_TOKEN"

# Hetzner imposes no per-IP cooldown; the limit is 3600 API requests per hour
# across the project, which this tooling comes nowhere near. Failing back
# immediately is therefore possible here, which it is not on netcup.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=0

# The assign action is asynchronous and the driver waits for it, but the route
# still needs a moment to converge afterwards.
PROVIDER_TRAFFIC_PROPAGATION_SECONDS=30

# Hetzner floating IPs are routed to the server, not delivered to it: the host
# must carry the address on its interface or the packets are dropped. Same
# requirement as netcup, for the same reason.
PROVIDER_REQUIRES_IP_BINDING=true

_HCLOUD_API="https://api.hetzner.cloud/v1"

provider_preflight() {
  need_cmd curl
  need_cmd jq
  provider_require_credentials
}

_hcloud_api() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -s -X "$method" \
      -H "Authorization: Bearer $HCLOUD_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body" "$_HCLOUD_API$path"
  else
    curl -s -X "$method" -H "Authorization: Bearer $HCLOUD_TOKEN" "$_HCLOUD_API$path"
  fi
}

_hcloud_check_error() {
  local resp="$1" context="$2" message
  message="$(printf '%s' "$resp" | jq -r '.error.message // empty' 2>/dev/null)"
  [ -z "$message" ] || die "Hetzner rejected $context: $message"
}

# Actions are asynchronous. Returning before the action succeeds would report a
# move that has not happened, so wait for a terminal status.
_hcloud_wait_action() {
  local action_id="$1" context="$2" waited=0 status resp
  [ -n "$action_id" ] && [ "$action_id" != "null" ] || return 0

  while [ "$waited" -lt 60 ]; do
    resp="$(_hcloud_api GET "/actions/$action_id")"
    status="$(printf '%s' "$resp" | jq -r '.action.status // empty')"
    case "$status" in
      success) return 0 ;;
      error)   die "Hetzner action for $context failed: $(printf '%s' "$resp" | jq -r '.action.error.message // "unknown"')" ;;
    esac
    sleep 2
    waited=$(( waited + 2 ))
  done
  warn "Hetzner action for $context did not report success within ${waited}s; it may still be running"
}

_hcloud_floating_ip_id() {
  if [ -n "${FAILOVER_IP_ID:-}" ]; then printf '%s' "$FAILOVER_IP_ID"; return; fi
  : "${FAILOVER_IP:?set FAILOVER_IP or FAILOVER_IP_ID in the inventory}"

  local id
  id="$(_hcloud_api GET "/floating_ips" \
    | jq -r --arg ip "$FAILOVER_IP" '.floating_ips[]? | select(.ip == $ip) | .id' | head -n1)"
  [ -n "$id" ] && [ "$id" != "null" ] || die "floating IP $FAILOVER_IP not found in this Hetzner project"
  printf '%s' "$id"
}

provider_route_traffic_to() {
  local node="$1" server_id resp action_id
  server_id="$(node_provider_id "$node")"
  [ -n "$server_id" ] || die "no provider id configured for $node (set NODE*_PROVIDER_ID)"
  provider_preflight

  # The server id is numeric here, unlike netcup's opaque string.
  resp="$(_hcloud_api POST "/floating_ips/$(_hcloud_floating_ip_id)/actions/assign" \
    "$(jq -nc --argjson s "$server_id" '{server: $s}')")"
  _hcloud_check_error "$resp" "the floating IP assignment"

  action_id="$(printf '%s' "$resp" | jq -r '.action.id // empty')"
  _hcloud_wait_action "$action_id" "the floating IP assignment"
  ok "Hetzner assigned the floating IP to $node ($server_id)"
}

provider_traffic_location() {
  provider_preflight
  local server_id
  server_id="$(_hcloud_api GET "/floating_ips/$(_hcloud_floating_ip_id)" \
    | jq -r '.floating_ip.server // empty')"
  [ -n "$server_id" ] && [ "$server_id" != "null" ] || return 0
  node_for_provider_id "$server_id"
}

provider_set_power() {
  local node="$1" state="$2" server_id action resp action_id
  server_id="$(node_provider_id "$node")"
  [ -n "$server_id" ] || die "no provider id configured for $node"
  provider_preflight

  # poweroff is the hard stop, which is what fencing wants: shutdown asks the
  # guest politely and a wedged host may ignore it.
  case "$state" in
    off)   action="poweroff" ;;
    on)    action="poweron" ;;
    reset) action="reset" ;;
    *) die "unsupported power state '$state'" ;;
  esac

  resp="$(_hcloud_api POST "/servers/$server_id/actions/$action")"
  _hcloud_check_error "$resp" "the $action request"

  action_id="$(printf '%s' "$resp" | jq -r '.action.id // empty')"
  _hcloud_wait_action "$action_id" "the $action request"
  ok "Hetzner completed $action on $node ($server_id)"
}
