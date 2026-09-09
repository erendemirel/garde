#!/usr/bin/env bash
# Impact: none — mesh reachability + provider credential/tooling preflight.
set -euo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ha/lib.sh"

ha_boot
ha_banner "deploy: mesh + provider preflight"

for node in $NODES; do
  on_node "$node" "true" || die "$node unreachable over the control plane"
  ok "$node reachable ($(node_role "$node"))"
done

provider_preflight
ok "provider_preflight ($PROVIDER_NAME) OK"
