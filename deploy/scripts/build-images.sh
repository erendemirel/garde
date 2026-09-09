#!/usr/bin/env bash
# Build the three images this deployment ships: the API, the UI and a Caddy
# with the netcup DNS module compiled in.
#
#   ./deploy/scripts/build-images.sh                 # tag from git sha
#   ./deploy/scripts/build-images.sh --tag v1.2.3
#   ./deploy/scripts/build-images.sh --only ui
#
# Nothing is pushed anywhere. ship-image.sh streams the results to the hosts.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

load_inventory
need_cmd docker

TAG=""; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tag)  TAG="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [ -z "$TAG" ]; then
  TAG="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M)"
fi

want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

if want api; then
  step "Building ${GARDE_IMAGE:-garde/api}:$TAG"
  docker build --target service -t "${GARDE_IMAGE:-garde/api}:$TAG" "$REPO_ROOT"
  ok "api built"
fi

if want ui; then
  step "Building ${UI_IMAGE:-garde/ui}:$TAG"
  # The API URL is baked in at build time by SvelteKit, so the UI image is
  # environment-specific. Rebuild it if API_DOMAIN ever changes.
  docker build \
    --build-arg "PUBLIC_API_URL=https://${API_DOMAIN:?API_DOMAIN is required to build the UI}" \
    -t "${UI_IMAGE:-garde/ui}:$TAG" "$REPO_ROOT/web"
  ok "ui built"
fi

if want caddy; then
  step "Building ${CADDY_IMAGE:-garde/caddy}:$TAG"
  docker build -t "${CADDY_IMAGE:-garde/caddy}:$TAG" "$DEPLOY_DIR/images/caddy"
  ok "caddy built"
fi

printf '\n'
ok "tag: $TAG"
printf 'Ship with: IMAGE_TAG=%s ./deploy/scripts/deploy.sh all\n' "$TAG"

# Consumed by the CI workflow to pass the tag between jobs.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'tag=%s\n' "$TAG" >>"$GITHUB_OUTPUT"
fi
