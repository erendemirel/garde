#!/usr/bin/env bash
# Impact: none — public traffic address is on the inventory primary.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: traffic location"

: "${FAILOVER_IP:?FAILOVER_IP missing from inventory}"
provider_preflight

loc="$(provider_traffic_location 2>/dev/null || true)"
if [ -z "$loc" ]; then
  die "provider_traffic_location returned empty (is $FAILOVER_IP associated?)"
fi
[ "$loc" = "$PRIMARY_NODE" ] \
  || die "traffic on $loc but PRIMARY_NODE=$PRIMARY_NODE"
ok "$PROVIDER_NAME reports $FAILOVER_IP on $PRIMARY_NODE ($(node_provider_id "$PRIMARY_NODE"))"
