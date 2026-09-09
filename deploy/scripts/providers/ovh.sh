#!/usr/bin/env bash
# OVHcloud driver: Additional/failover IP routing and VPS power through the
# OVHcloud API (/1.0).
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects.
#
# Targets OVHcloud **VPS**. Dedicated servers use different power endpoints
# (/dedicated/server/...), and OVH Public Cloud instances are OpenStack and use
# a different IP model entirely. Both would be separate drivers.
#
# Credentials: OVH signs every request rather than using a bearer token, so it
# needs three values from https://api.ovh.com/createToken/ :
#
#   OVH_APPLICATION_KEY
#   OVH_APPLICATION_SECRET
#   OVH_CONSUMER_KEY
#
# Grant the consumer key at least:
#   GET /ip/*   POST /ip/*   GET /vps/*   POST /vps/*
#
# Inventory mapping:
#   NODE*_PROVIDER_ID   the VPS service name, e.g. vps-a1b2c3d4.vps.ovh.net
#   FAILOVER_IP         the Additional IP; FAILOVER_IP_ID is not used here
#
# Note: OVH only moves an Additional IP between services in the same country.
# Put all three hosts in one region or the cutover will be refused.

PROVIDER_NAME="OVHcloud"
PROVIDER_CREDENTIALS="OVH_APPLICATION_KEY OVH_APPLICATION_SECRET OVH_CONSUMER_KEY"

# OVH documents no fixed cooldown, but a move runs as a task and a second move
# cannot start while one is in flight. provider_route_traffic_to waits for the
# routing to actually change, which enforces that more precisely than a timer.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=0

# OVH re-announces the route through its network; community reports and the
# vendor's own HA guidance put this around a minute, sometimes longer.
PROVIDER_TRAFFIC_PROPAGATION_SECONDS=120

# The IP is routed to the service, not delivered to the guest: it has to be
# configured on the interface or the packets are dropped.
PROVIDER_REQUIRES_IP_BINDING=true

# eu | ca | us - the API is regional and a key is only valid in its own region.
_OVH_ENDPOINT="${OVH_ENDPOINT:-https://eu.api.ovh.com/1.0}"

provider_preflight() {
  need_cmd curl
  need_cmd jq
  provider_require_credentials
}

_ovh_sha1() {
  if command -v sha1sum >/dev/null 2>&1; then sha1sum | cut -d' ' -f1
  else shasum | cut -d' ' -f1; fi
}

# OVH rejects requests whose timestamp drifts from its own clock, so take the
# time from the API rather than from this machine.
_ovh_time() { curl -s "$_OVH_ENDPOINT/auth/time"; }

# Every call is signed: "$1$" + sha1(secret+consumer+method+url+body+timestamp),
# joined with literal plus signs.
_ovh_api() {
  local method="$1" path="$2" body="${3:-}"
  local url="$_OVH_ENDPOINT$path" ts signature

  ts="$(_ovh_time)"
  [ -n "$ts" ] || die "could not read the time from the OVHcloud API"

  signature="\$1\$$(printf '%s+%s+%s+%s+%s+%s' \
    "$OVH_APPLICATION_SECRET" "$OVH_CONSUMER_KEY" "$method" "$url" "$body" "$ts" | _ovh_sha1)"

  if [ -n "$body" ]; then
    curl -s -X "$method" \
      -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
      -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY" \
      -H "X-Ovh-Timestamp: $ts" \
      -H "X-Ovh-Signature: $signature" \
      -H "Content-Type: application/json" \
      -d "$body" "$url"
  else
    curl -s -X "$method" \
      -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
      -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY" \
      -H "X-Ovh-Timestamp: $ts" \
      -H "X-Ovh-Signature: $signature" \
      "$url"
  fi
}

_ovh_check_error() {
  local resp="$1" context="$2" message
  message="$(printf '%s' "$resp" | jq -r 'if type=="object" then (.message // empty) else empty end' 2>/dev/null)"
  [ -z "$message" ] || die "OVHcloud rejected $context: $message"
}

_ovh_routed_to() {
  : "${FAILOVER_IP:?set FAILOVER_IP in the inventory}"
  _ovh_api GET "/ip/$FAILOVER_IP%2F32" \
    | jq -r 'if type=="object" then (.routedTo.serviceName // empty) else empty end'
}

provider_route_traffic_to() {
  local node="$1" service resp waited=0 current
  service="$(node_provider_id "$node")"
  [ -n "$service" ] || die "no provider id configured for $node (set NODE*_PROVIDER_ID to the VPS service name)"
  provider_preflight
  : "${FAILOVER_IP:?set FAILOVER_IP in the inventory}"

  resp="$(_ovh_api POST "/ip/$FAILOVER_IP%2F32/move" "$(jq -nc --arg to "$service" '{to: $to}')")"
  _ovh_check_error "$resp" "the IP move"

  # OVH returns a task; rather than tracking its id, wait for the end state the
  # move is supposed to produce. That verifies the outcome, not the paperwork.
  while [ "$waited" -lt "$PROVIDER_TRAFFIC_PROPAGATION_SECONDS" ]; do
    current="$(_ovh_routed_to)"
    if [ "$current" = "$service" ]; then
      ok "OVHcloud routed $FAILOVER_IP to $node ($service)"
      return 0
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  warn "OVHcloud accepted the move but $FAILOVER_IP is still routed to '${current:-nothing}' after ${waited}s"
}

provider_traffic_location() {
  provider_preflight
  local service
  service="$(_ovh_routed_to)"
  [ -n "$service" ] || return 0
  node_for_provider_id "$service"
}

provider_set_power() {
  local node="$1" state="$2" service action resp
  service="$(node_provider_id "$node")"
  [ -n "$service" ] || die "no provider id configured for $node"
  provider_preflight

  case "$state" in
    off)   action="stop" ;;
    on)    action="start" ;;
    reset) action="reboot" ;;
    *) die "unsupported power state '$state'" ;;
  esac

  resp="$(_ovh_api POST "/vps/$service/$action")"
  _ovh_check_error "$resp" "the $action request"
  ok "OVHcloud accepted $action on $node ($service)"
}
