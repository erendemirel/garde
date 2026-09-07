#!/usr/bin/env bash
# Where public traffic goes, and how to move it.
#
#   ./deploy/scripts/traffic.sh status
#   ./deploy/scripts/traffic.sh route node2
#
# Provider-neutral: the mechanism is whatever the driver named by PROVIDER in
# the inventory implements. On netcup and Hetzner that is a floating IP.
#
# This moves traffic and nothing else. It does not fence the old primary or
# promote Redis, so calling it directly on a live cluster will send requests to
# a node that is not ready for them. Use failover.sh for a real cutover; this
# is for the initial setup and for inspection.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
load_provider

ACTION="${1:-status}"
TARGET_NODE="${2:-}"

case "$ACTION" in
  status)
    step "Traffic status ($PROVIDER_NAME)"
    location="$(provider_traffic_location)"
    if [ -n "$location" ]; then
      log "public traffic is routed to: $location"
    else
      warn "public traffic is not routed to any known node"
    fi
    log "inventory says the primary is: ${PRIMARY_NODE:-unset}"
    if [ -n "$location" ] && [ -n "${PRIMARY_NODE:-}" ] && [ "$location" != "$PRIMARY_NODE" ]; then
      warn "traffic and the inventory disagree - one of them is stale"
    fi

    remaining="$(traffic_cooldown_remaining)"
    if [ "$remaining" -gt 0 ]; then
      log "traffic cannot be moved again for ${remaining}s"
    else
      log "traffic can be moved now (cooldown $(traffic_cooldown_seconds)s)"
    fi
    ;;

  route|assign)
    [ -n "$TARGET_NODE" ] || die "usage: traffic.sh route <node>"
    require_node "$TARGET_NODE"

    if [ "$PROVIDER_REQUIRES_IP_BINDING" = "true" ] && [ -n "${FAILOVER_IP:-}" ]; then
      on_node "$TARGET_NODE" "ip -4 -oneline address show | grep -qF '$FAILOVER_IP'" \
        || die "$TARGET_NODE does not have $FAILOVER_IP bound - it would drop the routed traffic.
     cd ansible && ansible-playbook playbooks/bootstrap.yml --limit $TARGET_NODE"
    fi

    enforce_traffic_cooldown
    step "Routing public traffic to $TARGET_NODE via $PROVIDER_NAME"
    provider_route_traffic_to "$TARGET_NODE"
    record_traffic_move

    ok "accepted; propagation takes up to ${PROVIDER_TRAFFIC_PROPAGATION_SECONDS}s"
    summary "Public traffic routed to $TARGET_NODE"
    ;;

  *)
    die "usage: traffic.sh <status|route <node>>"
    ;;
esac
