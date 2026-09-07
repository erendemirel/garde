#!/usr/bin/env bash
# Shared helpers for the garde deploy scripts.
# Source this, do not execute it:  . "$(dirname "$0")/lib.sh"

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"
INVENTORY_FILE="${INVENTORY_FILE:-$DEPLOY_DIR/inventory.env}"

# --- output ---------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  _c_red=$'\033[31m'; _c_yellow=$'\033[33m'; _c_green=$'\033[32m'
  _c_blue=$'\033[34m'; _c_reset=$'\033[0m'
else
  _c_red=""; _c_yellow=""; _c_green=""; _c_blue=""; _c_reset=""
fi

log()  { printf '%s[%s]%s %s\n' "$_c_blue"  "$(date -u +%H:%M:%S)" "$_c_reset" "$*"; }
ok()   { printf '%s  ok%s   %s\n' "$_c_green" "$_c_reset" "$*"; }
warn() { printf '%swarn%s   %s\n' "$_c_yellow" "$_c_reset" "$*" >&2; }
die()  { printf '%sfail%s   %s\n' "$_c_red" "$_c_reset" "$*" >&2; exit 1; }

step() { printf '\n%s==>%s %s\n' "$_c_blue" "$_c_reset" "$*"; }

# Print to the GitHub Actions job summary when running in CI, otherwise stdout.
summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$*" >>"$GITHUB_STEP_SUMMARY"
  else
    printf '%s\n' "$*"
  fi
}

# --- inventory ------------------------------------------------------------

load_inventory() {
  [ -f "$INVENTORY_FILE" ] || die "inventory not found: $INVENTORY_FILE (copy deploy/inventory.example.env)"
  # shellcheck disable=SC1090
  set -a; . "$INVENTORY_FILE"; set +a
  : "${NODES:?NODES missing from inventory}"
  : "${SSH_USER:?SSH_USER missing from inventory}"
  : "${REMOTE_ROOT:?REMOTE_ROOT missing from inventory}"
}

# node_var node1 WG_IP  ->  value of NODE1_WG_IP
node_var() {
  local node="$1" suffix="$2" name
  name="$(printf '%s_%s' "$node" "$suffix" | tr '[:lower:]-' '[:upper:]_')"
  printf '%s' "${!name:-}"
}

node_role()      { node_var "$1" ROLE; }
node_wg_ip()     { node_var "$1" WG_IP; }
node_public_ip() { node_var "$1" PUBLIC_IP; }
node_vault_id()  { node_var "$1" VAULT_ID; }

# The provider's own identifier for the machine: an opaque vXXXXXXXX string on
# netcup, a numeric id on Hetzner. Only drivers should care what it looks like.
node_provider_id() { node_var "$1" PROVIDER_ID; }

# Reverse lookup, so a driver can answer "which node holds the traffic" with a
# node name instead of an id the rest of the tooling would have to decode.
node_for_provider_id() {
  local want="$1" node
  for node in $NODES; do
    if [ "$(node_provider_id "$node")" = "$want" ]; then
      printf '%s' "$node"
      return 0
    fi
  done
  return 0
}

require_node() {
  local node="$1"
  case " $NODES " in
    *" $node "*) ;;
    *) die "unknown node '$node' (known: $NODES)" ;;
  esac
}

# Resolve a role name (app-primary/app-standby/witness) to a node name.
node_with_role() {
  local want="$1" node
  for node in $NODES; do
    if [ "$(node_role "$node")" = "$want" ]; then printf '%s' "$node"; return 0; fi
  done
  return 1
}

# --- ssh ------------------------------------------------------------------

# All SSH goes over the WireGuard address, never the public IP.
ssh_target() {
  local node="$1" ip
  ip="$(node_wg_ip "$node")"
  [ -n "$ip" ] || die "no WireGuard IP configured for $node"
  printf '%s@%s' "$SSH_USER" "$ip"
}

on_node() {
  local node="$1"; shift
  require_node "$node"
  # shellcheck disable=SC2086
  ssh -p "${SSH_PORT:-22}" ${SSH_OPTS:-} "$(ssh_target "$node")" "$@"
}

# Same as on_node but feeds stdin through (used by ship-image.sh).
on_node_stdin() {
  local node="$1"; shift
  require_node "$node"
  # shellcheck disable=SC2086
  ssh -p "${SSH_PORT:-22}" ${SSH_OPTS:-} "$(ssh_target "$node")" "$@"
}

rsync_to_node() {
  local node="$1" src="$2" dest="$3"
  require_node "$node"
  rsync -az --delete \
    -e "ssh -p ${SSH_PORT:-22} ${SSH_OPTS:-}" \
    "$src" "$(ssh_target "$node"):$dest"
}

# Run docker compose for one stack on a node.
compose_on() {
  local node="$1" stack="$2"; shift 2
  on_node "$node" "cd '$REMOTE_ROOT' && docker compose --env-file .env -f 'compose/$stack.yml' -p 'garde-$stack' $*"
}

# --- misc -----------------------------------------------------------------

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

confirm() {
  [ "${ASSUME_YES:-false}" = "true" ] && return 0
  local prompt="$1" answer
  read -r -p "$prompt [type 'yes' to continue] " answer
  [ "$answer" = "yes" ] || die "aborted"
}

# Wait until a command succeeds, or fail after N attempts.
retry_until() {
  local attempts="$1" delay="$2"; shift 2
  local i=0
  while [ "$i" -lt "$attempts" ]; do
    if "$@"; then return 0; fi
    i=$((i + 1))
    sleep "$delay"
  done
  return 1
}

# --- provider seam --------------------------------------------------------
#
# Definitions only. Scripts that talk to the hosting provider call
# load_provider() after load_inventory(), because the driver to load is named
# by the inventory.
# shellcheck disable=SC1091
. "$DEPLOY_DIR/scripts/provider.sh"
