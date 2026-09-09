#!/usr/bin/env bash
# Scaleway driver: flexible IP attachment and power through the Instance v1 API.
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects.
#
# Targets Scaleway **Instances**. Elastic Metal is a separate product with its
# own API (/baremetal/v1) and would be a separate driver.
#
# Credentials: an API secret key from IAM, sent as X-Auth-Token:
#
#   SCW_SECRET_KEY
#
# Inventory mapping:
#   NODE*_PROVIDER_ID   Instance UUID
#   FAILOVER_IP         the flexible IP address; FAILOVER_IP_ID optional
#   SCW_ZONE            zone, default fr-par-1
#
# All three hosts and the flexible IP must live in one zone: Scaleway cannot
# attach an IP to an Instance in a different zone, so a cutover across zones is
# not possible.
#
# This uses the stable Instance v1 endpoints rather than the v2alpha1
# attach-ip call, because production failover should not depend on an alpha API.

PROVIDER_NAME="Scaleway"
PROVIDER_CREDENTIALS="SCW_SECRET_KEY"

# No documented rate limit on reattaching a flexible IP.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=0

# Flexible IPs are routed at the network edge and the guest is reconfigured by
# Scaleway's own agent, so this is quick.
PROVIDER_TRAFFIC_PROPAGATION_SECONDS=30

# Scaleway configures and deconfigures the address inside the guest itself, via
# the automatic network hot-reconfiguration mechanism (scw-net-reconfig), which
# has been enabled by default on Linux images since October 2024.
#
# So the address is delivered, not merely routed, and this driver declares
# false. Binding it statically on both app nodes would fight that agent: it
# deconfigures the address on detach, and a static binding would put the same IP
# on the node that no longer owns it. The bootstrap playbook skips the
# failover_ip role here.
#
# If you disable scw-net-reconfig, or run an image predating it, flip this to
# true and re-run the playbook.
PROVIDER_REQUIRES_IP_BINDING=false

_SCW_API="https://api.scaleway.com/instance/v1"
_scw_zone() { printf '%s' "${SCW_ZONE:-fr-par-1}"; }

provider_preflight() {
  need_cmd curl
  need_cmd jq
  provider_require_credentials
}

_scw_api() {
  local method="$1" path="$2" body="${3:-}"
  local url="$_SCW_API/zones/$(_scw_zone)$path"
  if [ -n "$body" ]; then
    curl -s -X "$method" \
      -H "X-Auth-Token: $SCW_SECRET_KEY" \
      -H "Content-Type: application/json" \
      -d "$body" "$url"
  else
    curl -s -X "$method" -H "X-Auth-Token: $SCW_SECRET_KEY" "$url"
  fi
}

_scw_check_error() {
  local resp="$1" context="$2" message
  message="$(printf '%s' "$resp" | jq -r 'if type=="object" then (.message // empty) else empty end' 2>/dev/null)"
  [ -z "$message" ] || die "Scaleway rejected $context: $message"
}

_scw_ip_id() {
  if [ -n "${FAILOVER_IP_ID:-}" ]; then printf '%s' "$FAILOVER_IP_ID"; return; fi
  : "${FAILOVER_IP:?set FAILOVER_IP or FAILOVER_IP_ID in the inventory}"

  local id
  id="$(_scw_api GET "/ips" | jq -r --arg ip "$FAILOVER_IP" '.ips[]? | select(.address == $ip) | .id' | head -n1)"
  [ -n "$id" ] && [ "$id" != "null" ] \
    || die "flexible IP $FAILOVER_IP not found in zone $(_scw_zone) - check SCW_ZONE"
  printf '%s' "$id"
}

_scw_ip_holder() {
  _scw_api GET "/ips/$(_scw_ip_id)" | jq -r '.ip.server.id // empty'
}

provider_route_traffic_to() {
  local node="$1" server_id resp holder
  server_id="$(node_provider_id "$node")"
  [ -n "$server_id" ] || die "no provider id configured for $node (set NODE*_PROVIDER_ID to the Instance UUID)"
  provider_preflight

  resp="$(_scw_api PATCH "/ips/$(_scw_ip_id)" "$(jq -nc --arg s "$server_id" '{server: $s}')")"
  _scw_check_error "$resp" "the flexible IP attachment"

  # Confirm the end state rather than trusting the response body.
  holder="$(printf '%s' "$resp" | jq -r '.ip.server.id // empty')"
  [ -n "$holder" ] || holder="$(_scw_ip_holder)"
  [ "$holder" = "$server_id" ] \
    || die "Scaleway accepted the request but the IP is attached to '${holder:-nothing}', not $node"

  ok "Scaleway attached $FAILOVER_IP to $node ($server_id)"
}

provider_traffic_location() {
  provider_preflight
  local server_id
  server_id="$(_scw_ip_holder)"
  [ -n "$server_id" ] || return 0
  node_for_provider_id "$server_id"
}

provider_set_power() {
  local node="$1" state="$2" server_id action want resp waited=0 current
  server_id="$(node_provider_id "$node")"
  [ -n "$server_id" ] || die "no provider id configured for $node"
  provider_preflight

  # `stop_in_place`, not `poweroff`. Scaleway's poweroff archives the local
  # volume to a volume store and releases the hypervisor slot, which takes as
  # long as the data needs and is far more than fencing asks for. stop_in_place
  # halts the machine and keeps the slot, so the host stops writing immediately
  # and comes back quickly.
  #
  # `terminate` deletes local volumes and is deliberately unreachable here.
  case "$state" in
    off)   action="stop_in_place"; want="stopped" ;;
    on)    action="poweron";       want="running" ;;
    reset) action="reboot";        want="running" ;;
    *) die "unsupported power state '$state'" ;;
  esac

  resp="$(_scw_api POST "/servers/$server_id/action" "$(jq -nc --arg a "$action" '{action: $a}')")"
  _scw_check_error "$resp" "the $action request"

  # The action returns a task; wait for the server state it is meant to produce.
  while [ "$waited" -lt 120 ]; do
    current="$(_scw_api GET "/servers/$server_id" | jq -r '.server.state // empty')"
    if [ "$current" = "$want" ]; then
      ok "Scaleway completed $action on $node (state=$current)"
      return 0
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done
  warn "Scaleway accepted $action on $node but the state is '${current:-unknown}' after ${waited}s"
}
