#!/usr/bin/env bash
# IONOS Cloud driver: reserved IP reassignment and server power through the
# Cloud API v6.
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects.
#
# Targets IONOS **Cloud** (the DCD / Cloud API v6 product). The older IONOS
# shared-hosting VPS range has no comparable API and would not work here.
#
# Credentials: a token from `ionosctl token generate`, which does not expire on
# a fixed schedule:
#
#   IONOS_TOKEN
#
# Inventory mapping. IONOS addresses a NIC by three ids, so NODE*_PROVIDER_ID
# is a triple, slash separated:
#
#   NODE1_PROVIDER_ID=<datacenterId>/<serverId>/<nicId>
#
# The generic layer never interprets this - only the driver splits it - which is
# the point of keeping the id opaque above the seam.
#
# IONOS differs from the routed-IP providers in a way that matters. netcup,
# Hetzner and OVH route the address to a machine that must already carry it;
# IONOS *delivers* it, by attaching the reserved IP to a NIC. Moving it is
# therefore two calls, detach then attach, and the guest gets the address from
# the platform.
#
# That is why this driver declares PROVIDER_REQUIRES_IP_BINDING=false. Binding
# the address statically on both app nodes - correct and necessary on the routed
# providers - would put the same IP on two hosts of the same virtual LAN and
# risk an ARP conflict that breaks the node actually serving. The bootstrap
# playbook skips the failover_ip role entirely here.

PROVIDER_NAME="IONOS Cloud"
PROVIDER_CREDENTIALS="IONOS_TOKEN"

# No documented rate limit on reassignment. Each call is a provisioning request
# and this driver waits for it to reach DONE, which serialises moves naturally.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=0

# Detach plus attach, each a provisioning request against the virtual NIC.
PROVIDER_TRAFFIC_PROPAGATION_SECONDS=60

# See the note above: the platform puts the address on the NIC.
PROVIDER_REQUIRES_IP_BINDING=false

_IONOS_API="https://api.ionos.com/cloudapi/v6"
_ionos_last_location=""

provider_preflight() {
  need_cmd curl
  need_cmd jq
  provider_require_credentials
}

_ionos_api() {
  local method="$1" path="$2" body="${3:-}" headers response
  headers="$(mktemp)"

  if [ -n "$body" ]; then
    response="$(curl -s -D "$headers" -X "$method" \
      -H "Authorization: Bearer $IONOS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body" "$_IONOS_API$path")"
  else
    response="$(curl -s -D "$headers" -X "$method" \
      -H "Authorization: Bearer $IONOS_TOKEN" "$_IONOS_API$path")"
  fi

  # Provisioning calls return the request to poll in the Location header.
  _ionos_last_location="$(tr -d '\r' <"$headers" | sed -n 's/^[Ll]ocation: //p' | head -n1)"
  rm -f "$headers"
  printf '%s' "$response"
}

_ionos_check_error() {
  local resp="$1" context="$2" message
  message="$(printf '%s' "$resp" | jq -r 'if type=="object" then (.messages[0].message // .message // empty) else empty end' 2>/dev/null)"
  [ -z "$message" ] || die "IONOS rejected $context: $message"
}

# Changes are asynchronous provisioning requests; returning before they are DONE
# would report a move that has not happened yet.
_ionos_wait_request() {
  local context="$1" url="$_ionos_last_location" waited=0 status resp
  [ -n "$url" ] || return 0

  while [ "$waited" -lt "$PROVIDER_TRAFFIC_PROPAGATION_SECONDS" ]; do
    resp="$(curl -s -H "Authorization: Bearer $IONOS_TOKEN" "$url")"
    status="$(printf '%s' "$resp" | jq -r '.metadata.status // empty')"
    case "$status" in
      DONE)   return 0 ;;
      FAILED) die "IONOS request for $context failed: $(printf '%s' "$resp" | jq -r '.metadata.message // "unknown"')" ;;
    esac
    sleep 3
    waited=$(( waited + 3 ))
  done
  warn "IONOS request for $context did not reach DONE within ${waited}s; it may still be provisioning"
}

# NODE*_PROVIDER_ID is <datacenterId>/<serverId>/<nicId>.
_ionos_nic_path() {
  local node="$1" id dc server nic
  id="$(node_provider_id "$node")"
  [ -n "$id" ] || die "no provider id configured for $node"
  IFS='/' read -r dc server nic <<<"$id"
  { [ -n "$dc" ] && [ -n "$server" ] && [ -n "$nic" ]; } \
    || die "NODE*_PROVIDER_ID for $node must be <datacenterId>/<serverId>/<nicId>, got '$id'"
  printf '/datacenters/%s/servers/%s/nics/%s' "$dc" "$server" "$nic"
}

_ionos_server_path() {
  local node="$1" id dc server nic
  id="$(node_provider_id "$node")"
  [ -n "$id" ] || die "no provider id configured for $node"
  IFS='/' read -r dc server nic <<<"$id"
  printf '/datacenters/%s/servers/%s' "$dc" "$server"
}

_ionos_nic_ips() {
  _ionos_api GET "$(_ionos_nic_path "$1")" | jq -c '.properties.ips // []'
}

_ionos_set_nic_ips() {
  local node="$1" ips="$2" resp
  resp="$(_ionos_api PATCH "$(_ionos_nic_path "$node")" "$(jq -nc --argjson ips "$ips" '{ips: $ips}')")"
  _ionos_check_error "$resp" "the NIC update on $node"
  _ionos_wait_request "the NIC update on $node"
}

provider_route_traffic_to() {
  local node="$1" other ips target_ips
  provider_preflight
  : "${FAILOVER_IP:?set FAILOVER_IP in the inventory}"
  [ -n "$(node_provider_id "$node")" ] || die "no provider id configured for $node"

  # Detach first. IONOS delivers the address rather than routing it, so leaving
  # it on the old NIC would put the same IP on two machines.
  for other in $NODES; do
    [ "$other" = "$node" ] && continue
    [ -n "$(node_provider_id "$other")" ] || continue
    ips="$(_ionos_nic_ips "$other")"
    if printf '%s' "$ips" | jq -e --arg ip "$FAILOVER_IP" 'index($ip) != null' >/dev/null 2>&1; then
      log "detaching $FAILOVER_IP from $other"
      _ionos_set_nic_ips "$other" "$(printf '%s' "$ips" | jq -c --arg ip "$FAILOVER_IP" 'map(select(. != $ip))')"
    fi
  done

  target_ips="$(_ionos_nic_ips "$node")"
  if printf '%s' "$target_ips" | jq -e --arg ip "$FAILOVER_IP" 'index($ip) != null' >/dev/null 2>&1; then
    ok "$FAILOVER_IP is already attached to $node"
    return 0
  fi

  _ionos_set_nic_ips "$node" "$(printf '%s' "$target_ips" | jq -c --arg ip "$FAILOVER_IP" '. + [$ip]')"
  ok "IONOS attached $FAILOVER_IP to $node"
}

provider_traffic_location() {
  provider_preflight
  : "${FAILOVER_IP:?set FAILOVER_IP in the inventory}"
  local node
  for node in $NODES; do
    [ -n "$(node_provider_id "$node")" ] || continue
    if _ionos_nic_ips "$node" | jq -e --arg ip "$FAILOVER_IP" 'index($ip) != null' >/dev/null 2>&1; then
      printf '%s' "$node"
      return 0
    fi
  done
  return 0
}

provider_set_power() {
  local node="$1" state="$2" action resp
  provider_preflight

  # `stop` deallocates cores and RAM, which is a harder stop than a shutdown -
  # appropriate for fencing. Reserved IPs survive it; unreserved ones would not,
  # which is why the public address must come from a reserved IP block.
  case "$state" in
    off)   action="stop" ;;
    on)    action="start" ;;
    reset) action="reboot" ;;
    *) die "unsupported power state '$state'" ;;
  esac

  resp="$(_ionos_api POST "$(_ionos_server_path "$node")/$action")"
  _ionos_check_error "$resp" "the $action request"
  _ionos_wait_request "the $action request"
  ok "IONOS completed $action on $node"
}
