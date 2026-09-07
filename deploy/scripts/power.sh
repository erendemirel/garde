#!/usr/bin/env bash
# Power a host on or off through the hosting provider.
#
#   ./deploy/scripts/power.sh node1 off
#   ./deploy/scripts/power.sh node1 on
#   ./deploy/scripts/power.sh node1 reset
#
# Used by fence.sh when a host cannot be reached over the mesh and stopping the
# machine is the only way left to stop it writing.
#
# `off` is a hard stop, not a graceful shutdown. That is the point: a host that
# needs fencing is one that is not responding to polite requests.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
load_provider

NODE="${1:-}"; STATE="${2:-}"
[ -n "$NODE" ] && [ -n "$STATE" ] || die "usage: power.sh <node> <off|on|reset>"
require_node "$NODE"

case "$STATE" in
  off|on|reset) ;;
  *) die "state must be one of: off, on, reset" ;;
esac

step "Setting $NODE to '$STATE' via $PROVIDER_NAME"
provider_set_power "$NODE" "$STATE"
