#!/usr/bin/env bash
# Impact: none — public traffic is routed to a known app node (or LB has targets).
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

ha_boot
ha_banner "deploy: traffic location"

provider_preflight
mode="$(traffic_mode)"
apps="$(app_nodes)"
[ -n "$apps" ] || die "no app nodes"

case "$mode" in
  managed_lb)
    loc="$(provider_traffic_location 2>/dev/null || true)"
    if [ -z "$loc" ]; then
      die "provider_traffic_location returned empty (is anything registered behind the LB?)"
    fi
    case " $apps " in
      *" $loc "*) ok "$PROVIDER_NAME managed_lb reports traffic on app node $loc" ;;
      *) die "traffic on $loc but that is not an app node (app nodes: $apps)" ;;
    esac
    ;;
  floating_ip|*)
    : "${FAILOVER_IP:?FAILOVER_IP missing from inventory}"
    loc="$(provider_traffic_location 2>/dev/null || true)"
    if [ -z "$loc" ]; then
      die "provider_traffic_location returned empty (is $FAILOVER_IP associated?)"
    fi
    case " $apps " in
      *" $loc "*) ok "$PROVIDER_NAME reports $FAILOVER_IP on app node $loc" ;;
      *) die "traffic on $loc but that is not an app node (app nodes: $apps)" ;;
    esac
    ;;
esac
