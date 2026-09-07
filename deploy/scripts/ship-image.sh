#!/usr/bin/env bash
# Stream a locally built image to a node over SSH.
#
#   ./deploy/scripts/ship-image.sh node1 garde/api:abc123
#   ./deploy/scripts/ship-image.sh --all garde/api:abc123 garde/ui:abc123
#
# There is no registry in this deployment on purpose: the hosts hold no
# credentials, pull from nothing, and compile nothing. CI builds the image and
# pipes `docker save` straight into `docker load` on the far side, compressed
# in flight.
#
# The image is skipped if the node already has that exact image id, which makes
# redeploying an unchanged component nearly free.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
need_cmd docker

TARGETS=""; IMAGES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --all) TARGETS="$NODES"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *:*) IMAGES="$IMAGES $1"; shift ;;
    *) TARGETS="$TARGETS $1"; shift ;;
  esac
done

[ -n "${TARGETS// /}" ] || die "usage: ship-image.sh <node>|--all <image:tag>..."
[ -n "${IMAGES// /}" ] || die "no image given"

# zstd is much faster than gzip for this and is installed by the Ansible
# baseline; fall back to gzip if either side lacks it.
choose_compressor() {
  local node="$1"
  if command -v zstd >/dev/null 2>&1 && on_node "$node" "command -v zstd >/dev/null 2>&1"; then
    printf 'zstd'
  else
    printf 'gzip'
  fi
}

for node in $TARGETS; do
  require_node "$node"
  comp="$(choose_compressor "$node")"

  for image in $IMAGES; do
    local_id="$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null)" \
      || die "image not found locally: $image"

    remote_id="$(on_node "$node" "docker image inspect --format '{{.Id}}' '$image' 2>/dev/null || true")"
    if [ "$local_id" = "$remote_id" ]; then
      ok "$node already has $image"
      continue
    fi

    size="$(docker image inspect --format '{{.Size}}' "$image")"
    step "Shipping $image to $node ($((size / 1024 / 1024)) MB uncompressed, $comp)"

    started="$(date +%s)"
    case "$comp" in
      zstd)
        docker save "$image" | zstd -T0 -3 -c \
          | on_node_stdin "$node" "zstd -d -c | docker load"
        ;;
      gzip)
        docker save "$image" | gzip -1 -c \
          | on_node_stdin "$node" "gzip -d -c | docker load"
        ;;
    esac
    ok "$image loaded on $node in $(( $(date +%s) - started ))s"
  done

  # Old image layers accumulate on hosts with small disks; keep it tidy but
  # never touch images that a running container still references.
  on_node "$node" "docker image prune -f --filter 'until=168h' >/dev/null 2>&1 || true"
done
