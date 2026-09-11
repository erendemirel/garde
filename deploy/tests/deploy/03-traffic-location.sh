#!/usr/bin/env bash
# Impact: none — public traffic address/target matches the inventory primary.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: traffic location"

provider_preflight
mode="$(traffic_mode)"

case "$mode" in
  managed_lb)
    # Driver-specific inventory (AWS_TARGET_GROUP_ARN, NODE*_INSTANCE_GROUP, …)
    # is validated inside provider_traffic_location — keep this check portable.
    loc="$(provider_traffic_location 2>/dev/null || true)"
    if [ -z "$loc" ]; then
      die "provider_traffic_location returned empty (is anything registered behind the LB?)"
    fi
    [ "$loc" = "$PRIMARY_NODE" ] \
      || die "traffic on $loc but PRIMARY_NODE=$PRIMARY_NODE"
    ok "$PROVIDER_NAME managed_lb reports traffic on $PRIMARY_NODE ($(node_provider_id "$PRIMARY_NODE"))"
    ;;
  floating_ip|*)
    : "${FAILOVER_IP:?FAILOVER_IP missing from inventory}"
    loc="$(provider_traffic_location 2>/dev/null || true)"
    if [ -z "$loc" ]; then
      die "provider_traffic_location returned empty (is $FAILOVER_IP associated?)"
    fi
    [ "$loc" = "$PRIMARY_NODE" ] \
      || die "traffic on $loc but PRIMARY_NODE=$PRIMARY_NODE"
    ok "$PROVIDER_NAME reports $FAILOVER_IP on $PRIMARY_NODE ($(node_provider_id "$PRIMARY_NODE"))"
    ;;
esac
