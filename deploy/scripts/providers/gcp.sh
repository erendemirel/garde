#!/usr/bin/env bash
# Google Cloud driver: static external IP reassignment and instance power
# through the gcloud CLI.
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects.
#
# Targets Compute Engine instances you run yourself, in one of two traffic
# modes.
#
#   TRAFFIC_MODE=floating_ip   (default) a static external IP, reassigned
#   TRAFFIC_MODE=managed_lb    an HTTPS load balancer, repointed
#
# floating_ip keeps the three-host architecture every VPS provider runs.
# managed_lb is the GCP-shaped answer: a global HTTPS load balancer with a
# Google-managed certificate in front of the instances, so no host ever holds
# the public address or proves domain control.
#
# managed_lb here still routes deliberately rather than load-balancing across
# both app nodes: this is a warm-standby cluster whose standby runs a Redis
# replica. Each node sits in its own zonal unmanaged instance group, all
# attached to one backend service, and routing means making sure only the
# intended node's group holds its instance.
#
# Credentials: a service account key with compute.instances.get,
# compute.instances.start/stop/reset, compute.instances.addAccessConfig and
# compute.instances.deleteAccessConfig (roles/compute.instanceAdmin.v1 covers
# it), plus the project to act in:
#
#   GOOGLE_APPLICATION_CREDENTIALS   path to the service account JSON
#   GOOGLE_CLOUD_PROJECT             project id
#
# Inventory mapping. An instance is addressed by zone and name, so
# NODE*_PROVIDER_ID is a pair:
#
#   NODE1_PROVIDER_ID=<zone>/<instance-name>     e.g. europe-west1-b/garde-1
#
# A static external IP is regional: it moves between zones of one region, so
# spread the three hosts across zones but keep them in a single region.
#
# A Compute Engine network interface holds at most one external IPv4 address, in
# a single access config, so giving a node the failover address would replace
# any public address it had. That would be a problem if the nodes needed one -
# so they don't have one. This driver declares tunnel access: the hosts have no
# external addresses, node-to-node WireGuard peers over internal addresses, and
# the control plane arrives through IAP TCP forwarding.
#
# Additional inventory keys:
#   NODE*_MESH_ENDPOINT    internal address peers dial for WireGuard
#   GCP_IMAGE_BUCKET       Cloud Storage bucket used to stage images
#   NODE*_INSTANCE_GROUP   managed_lb only: <zone>/<unmanaged-group-name>, the
#                          backend this node is served through

PROVIDER_NAME="Google Cloud"
PROVIDER_CREDENTIALS="GOOGLE_APPLICATION_CREDENTIALS GOOGLE_CLOUD_PROJECT"

PROVIDER_TRAFFIC_MODES="floating_ip managed_lb"

# No rate limit on either mechanism.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=0

# floating_ip: two zonal operations, delete then add, each taking a few seconds.
# managed_lb: Google's global load balancers take noticeably longer to converge
# on a backend change than a zonal address swap does.
if [ "${TRAFFIC_MODE:-floating_ip}" = "managed_lb" ]; then
  PROVIDER_TRAFFIC_PROPAGATION_SECONDS=120
else
  PROVIDER_TRAFFIC_PROPAGATION_SECONDS=60
fi

# Compute Engine translates the external address to the instance's internal one
# and the guest interface only ever carries the internal address, so there is
# nothing for the host to bind. The bootstrap playbook skips the failover_ip
# role here.
PROVIDER_REQUIRES_IP_BINDING=false

# IAP TCP forwarding: an identity-aware tunnel into instances with no external
# address. Free for administrative access and entirely agentless - the only
# host-side requirement is a firewall rule allowing Google's 35.235.240.0/20
# range, which the bootstrap playbook adds.
PROVIDER_ADMIN_ACCESS="tunnel"

# IAP is explicitly not for bulk transfer and Google reserves the right to
# rate-limit it, so images take the route in provider_publish_image instead.
PROVIDER_IMAGE_TRANSPORT="url"

# Google publishes a fixed range that IAP forwards from, so this needs no
# per-deployment value - unlike AWS, where the tunnel arrives from an interface
# inside your own VPC and only you know its CIDR.
PROVIDER_ADMIN_SSH_SOURCES="35.235.240.0/20"

# The name given to an access config this driver creates. Console-created
# instances use "External NAT" and gcloud's own default is "external-nat";
# because the name is not predictable, the driver always reads the existing name
# before deleting and only imposes this one on configs it adds itself.
_GCP_ACCESS_CONFIG="External NAT"

provider_preflight() {
  need_cmd gcloud
  provider_require_credentials
  [ -f "$GOOGLE_APPLICATION_CREDENTIALS" ] \
    || die "GOOGLE_APPLICATION_CREDENTIALS points at '$GOOGLE_APPLICATION_CREDENTIALS', which does not exist"

  # gcloud keeps credentials in its own store rather than reading the env var,
  # so activate the service account once per run if nothing is active yet.
  if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q .; then
    gcloud auth activate-service-account \
      --key-file="$GOOGLE_APPLICATION_CREDENTIALS" --quiet >/dev/null 2>&1 \
      || die "could not activate the service account in $GOOGLE_APPLICATION_CREDENTIALS"
  fi
}

_gcp() {
  local out
  if ! out="$(gcloud --project "$GOOGLE_CLOUD_PROJECT" --quiet "$@" 2>&1)"; then
    die "Google Cloud rejected 'gcloud $*': $out"
  fi
  printf '%s' "$out"
}

# NODE*_PROVIDER_ID is <zone>/<instance-name>.
_gcp_zone_of() {
  local id; id="$(node_provider_id "$1")"
  [ -n "$id" ] || die "no provider id configured for $1"
  case "$id" in */*) printf '%s' "${id%%/*}" ;;
    *) die "NODE*_PROVIDER_ID for $1 must be <zone>/<instance-name>, got '$id'" ;;
  esac
}

_gcp_name_of() {
  local id; id="$(node_provider_id "$1")"
  [ -n "$id" ] || die "no provider id configured for $1"
  case "$id" in */*) printf '%s' "${id##*/}" ;;
    *) die "NODE*_PROVIDER_ID for $1 must be <zone>/<instance-name>, got '$id'" ;;
  esac
}

_gcp_describe() {
  local node="$1" field="$2"
  _gcp compute instances describe "$(_gcp_name_of "$node")" \
    --zone "$(_gcp_zone_of "$node")" --format "value($field)"
}

_gcp_nat_ip()             { _gcp_describe "$1" 'networkInterfaces[0].accessConfigs[0].natIP'; }
_gcp_access_config_name() { _gcp_describe "$1" 'networkInterfaces[0].accessConfigs[0].name'; }

_gcp_drop_access_config() {
  local node="$1" name
  name="$(_gcp_access_config_name "$node")"
  [ -n "$name" ] || return 0
  _gcp compute instances delete-access-config "$(_gcp_name_of "$node")" \
    --zone "$(_gcp_zone_of "$node")" --access-config-name "$name" >/dev/null
}

# --- managed_lb --------------------------------------------------------------

# NODE*_INSTANCE_GROUP is <zone>/<group-name>, the same shape as the instance id.
_gcp_group_field() {
  local node="$1" part="$2" id
  id="$(node_var "$node" INSTANCE_GROUP)"
  [ -n "$id" ] \
    || die "no instance group configured for $node (set NODE*_INSTANCE_GROUP=<zone>/<group> for TRAFFIC_MODE=managed_lb)"
  case "$id" in
    */*) ;;
    *) die "NODE*_INSTANCE_GROUP for $node must be <zone>/<group-name>, got '$id'" ;;
  esac
  case "$part" in
    zone) printf '%s' "${id%%/*}" ;;
    name) printf '%s' "${id##*/}" ;;
  esac
}

_gcp_group_holds_instance() {
  local node="$1" instance
  instance="$(_gcp compute instance-groups unmanaged list-instances \
    "$(_gcp_group_field "$node" name)" --zone "$(_gcp_group_field "$node" zone)" \
    --format 'value(instance)' 2>/dev/null | head -n1)"
  [ -n "$instance" ]
}

_gcp_route_via_backend() {
  local node="$1" other
  provider_preflight

  # Add before removing, for the same reason the AWS driver registers first: a
  # backend service with no instances anywhere answers 502.
  if _gcp_group_holds_instance "$node"; then
    log "$node is already the backend instance"
  else
    _gcp compute instance-groups unmanaged add-instances \
      "$(_gcp_group_field "$node" name)" \
      --zone "$(_gcp_group_field "$node" zone)" \
      --instances "$(_gcp_name_of "$node")" >/dev/null
  fi

  for other in $NODES; do
    [ "$other" = "$node" ] && continue
    [ -n "$(node_var "$other" INSTANCE_GROUP)" ] || continue
    _gcp_group_holds_instance "$other" || continue
    log "removing $other from its instance group"
    _gcp compute instance-groups unmanaged remove-instances \
      "$(_gcp_group_field "$other" name)" \
      --zone "$(_gcp_group_field "$other" zone)" \
      --instances "$(_gcp_name_of "$other")" >/dev/null
  done

  _gcp_group_holds_instance "$node" \
    || die "Google Cloud accepted the change but $node is not in its instance group"

  ok "Google Cloud pointed the backend service at $node"
}

_gcp_backend_location() {
  provider_preflight
  local node
  for node in $NODES; do
    [ -n "$(node_var "$node" INSTANCE_GROUP)" ] || continue
    if _gcp_group_holds_instance "$node"; then
      printf '%s' "$node"
      return 0
    fi
  done
  return 0
}

# --- traffic -----------------------------------------------------------------

provider_route_traffic_to() {
  if [ "$(traffic_mode)" = "managed_lb" ]; then
    _gcp_route_via_backend "$1"
    return
  fi

  local node="$1" other status
  provider_preflight
  : "${FAILOVER_IP:?set FAILOVER_IP in the inventory}"
  [ -n "$(node_provider_id "$node")" ] || die "no provider id configured for $node"

  if [ "$(_gcp_nat_ip "$node")" = "$FAILOVER_IP" ]; then
    ok "$FAILOVER_IP is already on $node"
    return 0
  fi

  # An ephemeral address would be lost the moment it is released and could not
  # be reattached, so check before taking anything down.
  status="$(gcloud --project "$GOOGLE_CLOUD_PROJECT" --quiet compute addresses list \
            --filter="address=$FAILOVER_IP" --format='value(status)' 2>/dev/null | head -n1)"
  [ -n "$status" ] \
    || die "$FAILOVER_IP is not a reserved static address in project $GOOGLE_CLOUD_PROJECT.
     Reserve it first - an ephemeral address cannot be moved and would be lost."

  # Unlike AWS, this is not atomic: Compute Engine has no move operation, and an
  # external address may be attached to only one interface at a time. The
  # address is therefore unattached between these two steps, which is the window
  # PROVIDER_TRAFFIC_PROPAGATION_SECONDS accounts for.
  for other in $NODES; do
    [ "$other" = "$node" ] && continue
    [ -n "$(node_provider_id "$other")" ] || continue
    if [ "$(_gcp_nat_ip "$other")" = "$FAILOVER_IP" ]; then
      log "releasing $FAILOVER_IP from $other"
      _gcp_drop_access_config "$other"
    fi
  done

  # The target's own access config occupies the only external-IPv4 slot on the
  # interface, so it has to go before the failover address can take its place.
  _gcp_drop_access_config "$node"

  _gcp compute instances add-access-config "$(_gcp_name_of "$node")" \
    --zone "$(_gcp_zone_of "$node")" \
    --access-config-name "$_GCP_ACCESS_CONFIG" \
    --address "$FAILOVER_IP" >/dev/null

  [ "$(_gcp_nat_ip "$node")" = "$FAILOVER_IP" ] \
    || die "Google Cloud accepted the request but $node does not carry $FAILOVER_IP"

  ok "Google Cloud attached $FAILOVER_IP to $node"
}

provider_traffic_location() {
  if [ "$(traffic_mode)" = "managed_lb" ]; then
    _gcp_backend_location
    return
  fi

  provider_preflight
  : "${FAILOVER_IP:?set FAILOVER_IP in the inventory}"
  local node
  for node in $NODES; do
    [ -n "$(node_provider_id "$node")" ] || continue
    if [ "$(_gcp_nat_ip "$node")" = "$FAILOVER_IP" ]; then
      printf '%s' "$node"
      return 0
    fi
  done
  return 0
}

# --- control plane ---------------------------------------------------------

# `start-iap-tunnel --listen-on-stdin` speaks the stdio protocol ssh wants from
# a ProxyCommand. The zone is baked in per node, which is why this takes the
# node rather than returning one command for all of them.
provider_admin_host() { _gcp_name_of "$1"; }

provider_admin_proxy_command() {
  printf 'gcloud compute start-iap-tunnel %%h %%p --listen-on-stdin --zone=%s --project=%s' \
    "$(_gcp_zone_of "$1")" "$GOOGLE_CLOUD_PROJECT"
}

# Staged in Cloud Storage and fetched by the host over a signed URL that
# expires. Turn on Private Google Access for the subnet - it is free - so
# instances without external addresses can reach storage.googleapis.com.
provider_publish_image() {
  local file="$1" object="garde-images/$(basename "$file")" url
  provider_preflight
  : "${GCP_IMAGE_BUCKET:?set GCP_IMAGE_BUCKET in the inventory to stage images}"

  _gcp storage cp "$file" "gs://$GCP_IMAGE_BUCKET/$object" >/dev/null
  url="$(_gcp storage sign-url "gs://$GCP_IMAGE_BUCKET/$object" \
          --private-key-file="$GOOGLE_APPLICATION_CREDENTIALS" \
          --duration=15m --format='value(signed_url)')"
  [ -n "$url" ] || die "could not sign gs://$GCP_IMAGE_BUCKET/$object"
  printf '%s' "$url"
}

# --- power -----------------------------------------------------------------

provider_set_power() {
  local node="$1" state="$2" action
  provider_preflight

  # `reset` is a hard reset that does not shut the guest down cleanly, which is
  # what the verb means here. `stop` is a graceful shutdown; Compute Engine has
  # no forced variant, so unlike AWS this cannot guarantee an immediate halt.
  case "$state" in
    off)   action="stop" ;;
    on)    action="start" ;;
    reset) action="reset" ;;
    *) die "unsupported power state '$state'" ;;
  esac

  _gcp compute instances "$action" "$(_gcp_name_of "$node")" \
    --zone "$(_gcp_zone_of "$node")" >/dev/null
  ok "Google Cloud completed $action on $node"
}
