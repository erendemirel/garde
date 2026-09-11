#!/usr/bin/env bash
# AWS driver: Elastic IP reassociation and EC2 power through the AWS CLI.
#
# Sourced by load_provider(). Defines functions and facts only - sourcing this
# file must have no side effects.
#
# Targets EC2 instances you run yourself, in one of two traffic modes.
#
#   TRAFFIC_MODE=floating_ip   (default) an Elastic IP, moved between hosts
#   TRAFFIC_MODE=managed_lb    an Application Load Balancer, repointed
#
# floating_ip keeps the same three-host architecture every VPS provider runs,
# which is the point of the seam: portability. managed_lb is what AWS itself
# would suggest - a load balancer terminating TLS with an ACM certificate in
# front of the instances - and if you are building for AWS alone it is the
# better design: no Elastic IP remaps, no ACME on the hosts, and health checks
# rather than an operator deciding a node is gone.
#
# Both modes move traffic deliberately. Even in managed_lb the target group
# holds exactly one instance, because this is a warm-standby cluster: the
# standby's Redis is a replica and must not serve writes. Health checks remove
# a broken node; they do not add the standby on their own.
#
# Credentials: an IAM access key whose policy allows ec2:AssociateAddress,
# ec2:DescribeAddresses, ec2:DescribeInstances, ec2:StartInstances,
# ec2:StopInstances and ec2:RebootInstances - plus, in managed_lb mode,
# elasticloadbalancing:RegisterTargets, :DeregisterTargets and
# :DescribeTargetHealth.
#
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#
# Inventory mapping:
#   NODE*_PROVIDER_ID       EC2 instance id (i-0123456789abcdef0)
#   FAILOVER_IP             the Elastic IP; FAILOVER_IP_ID optional (eipalloc-...)
#   AWS_REGION              region, read by the CLI directly
#   AWS_TARGET_GROUP_ARN    managed_lb only: the target group the listener
#                           forwards to (terraform output target_group_arn)
#
# An Elastic IP moves freely between availability zones within one region, so
# the three hosts can and should sit in different AZs. They cannot span regions.
#
# Associating an Elastic IP by instance id replaces whatever public address the
# instance already had, because EC2 gives a network interface one public address
# per private address and this driver targets the primary one. That would be a
# problem if the nodes needed public addresses of their own - so they don't have
# any. This driver declares tunnel access: the hosts sit in a VPC with no public
# address at all, node-to-node WireGuard peers over private addresses, and the
# control plane arrives through EC2 Instance Connect Endpoint.
#
# The only public address in the deployment is the Elastic IP, held by whichever
# node is currently primary. sshd is never reachable from the internet.
#
# Additional inventory keys:
#   NODE*_MESH_ENDPOINT   private address peers dial for WireGuard
#   AWS_IMAGE_BUCKET      S3 bucket used to stage images (see below)

PROVIDER_NAME="AWS"
PROVIDER_CREDENTIALS="AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY"

PROVIDER_TRAFFIC_MODES="floating_ip managed_lb"

# No rate limit on either mechanism. AWS bills a small charge per Elastic IP
# remap, which is a cost signal rather than a constraint on how soon you may
# move.
PROVIDER_TRAFFIC_COOLDOWN_SECONDS=0

# floating_ip: one API call, and the remap takes effect in seconds.
# managed_lb: registration is immediate but the listener only forwards once the
# target passes its health checks, and the old target drains first. The default
# target group in terraform/aws checks every 10s and needs 2 passes.
if [ "${TRAFFIC_MODE:-floating_ip}" = "managed_lb" ]; then
  PROVIDER_TRAFFIC_PROPAGATION_SECONDS=90
else
  PROVIDER_TRAFFIC_PROPAGATION_SECONDS=30
fi

# EC2 never puts the public address on the guest interface: the VPC translates
# the Elastic IP to the instance's private address, and `ip addr` inside the
# instance shows only the private one. There is nothing for the host to bind,
# and binding it would be wrong. The bootstrap playbook skips the failover_ip
# role here.
PROVIDER_REQUIRES_IP_BINDING=false

# EC2 Instance Connect Endpoint: an identity-aware TCP proxy, authorised by IAM,
# reaching instances that have no public address and no inbound rule from the
# internet. It costs nothing beyond data transfer and needs no agent installed
# on the host.
PROVIDER_ADMIN_ACCESS="tunnel"

# That endpoint is documented as being for administrative use rather than bulk
# transfer, so images do not go through it. See provider_publish_image below.
PROVIDER_IMAGE_TRANSPORT="url"

# Deliberately empty. The tunnel arrives from the endpoint's network interface
# inside your own VPC, so the range is your subnet CIDR and only you know it -
# set ADMIN_SSH_SOURCES in the inventory. load_provider refuses to continue
# without it, because the firewall would otherwise lock the tunnel out.

_aws_region() { printf '%s' "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"; }

provider_preflight() {
  need_cmd aws
  provider_require_credentials
  [ -n "$(_aws_region)" ] || die "AWS needs AWS_REGION (or AWS_DEFAULT_REGION) set"
}

# The CLI exits non-zero and explains itself on stderr; surface that rather than
# letting a bare failure propagate with no context.
_aws() {
  local out
  if ! out="$(aws --region "$(_aws_region)" --output text "$@" 2>&1)"; then
    die "AWS rejected '$*': $out"
  fi
  printf '%s' "$out"
}

_aws_allocation_id() {
  if [ -n "${FAILOVER_IP_ID:-}" ]; then printf '%s' "$FAILOVER_IP_ID"; return; fi
  : "${FAILOVER_IP:?set FAILOVER_IP or FAILOVER_IP_ID in the inventory}"

  local id
  id="$(_aws ec2 describe-addresses --public-ips "$FAILOVER_IP" \
        --query 'Addresses[0].AllocationId')"
  [ -n "$id" ] && [ "$id" != "None" ] \
    || die "Elastic IP $FAILOVER_IP not found in $(_aws_region) - check AWS_REGION"
  printf '%s' "$id"
}

_aws_eip_holder() {
  local id
  id="$(_aws ec2 describe-addresses --allocation-ids "$(_aws_allocation_id)" \
        --query 'Addresses[0].InstanceId')"
  [ "$id" = "None" ] && return 0
  printf '%s' "$id"
}

# --- managed_lb --------------------------------------------------------------

_aws_target_group_arn() {
  printf '%s' "${AWS_TARGET_GROUP_ARN:?set AWS_TARGET_GROUP_ARN in the inventory (terraform output target_group_arn)}"
}

# Instance ids currently registered, one per line. Draining targets are still
# registered and still listed, which is what we want: a second registration
# while the old one drains would put two writers behind the balancer.
_aws_registered_targets() {
  _aws elbv2 describe-target-health \
    --target-group-arn "$(_aws_target_group_arn)" \
    --query 'TargetHealthDescriptions[].Target.Id' | tr '\t' '\n' | grep -v '^$' || true
}

_aws_route_via_target_group() {
  local node="$1" instance_id other other_id registered
  instance_id="$(node_provider_id "$node")"
  [ -n "$instance_id" ] || die "no provider id configured for $node (set NODE*_PROVIDER_ID to the EC2 instance id)"
  provider_preflight

  # Register first, deregister second. The reverse order would empty the target
  # group for as long as the new target takes to pass its first health check,
  # and an ALB with no healthy targets answers 503.
  _aws elbv2 register-targets \
    --target-group-arn "$(_aws_target_group_arn)" \
    --targets "Id=$instance_id" >/dev/null

  registered="$(_aws_registered_targets)"
  for other in $NODES; do
    [ "$other" = "$node" ] && continue
    other_id="$(node_provider_id "$other")"
    [ -n "$other_id" ] || continue
    printf '%s\n' "$registered" | grep -qx "$other_id" || continue
    log "deregistering $other ($other_id) from the target group"
    _aws elbv2 deregister-targets \
      --target-group-arn "$(_aws_target_group_arn)" \
      --targets "Id=$other_id" >/dev/null
  done

  printf '%s\n' "$(_aws_registered_targets)" | grep -qx "$instance_id" \
    || die "AWS accepted the registration but $node ($instance_id) is not in the target group"

  ok "AWS registered $node ($instance_id) as the load balancer target"
}

_aws_target_group_location() {
  provider_preflight
  local instance_id
  # Healthy first: during a cutover both the new and the draining target are
  # registered, and the healthy one is the honest answer to "where is traffic
  # arriving".
  instance_id="$(_aws elbv2 describe-target-health \
    --target-group-arn "$(_aws_target_group_arn)" \
    --query 'TargetHealthDescriptions[?TargetHealth.State==`healthy`].Target.Id | [0]')"
  if [ -z "$instance_id" ] || [ "$instance_id" = "None" ]; then
    instance_id="$(_aws_registered_targets | head -n1)"
  fi
  [ -n "$instance_id" ] || return 0
  node_for_provider_id "$instance_id"
}

# --- traffic -----------------------------------------------------------------

provider_route_traffic_to() {
  if [ "$(traffic_mode)" = "managed_lb" ]; then
    _aws_route_via_target_group "$1"
    return
  fi

  local node="$1" instance_id holder
  instance_id="$(node_provider_id "$node")"
  [ -n "$instance_id" ] || die "no provider id configured for $node (set NODE*_PROVIDER_ID to the EC2 instance id)"
  provider_preflight

  # A single call. Unlike the detach-then-attach providers, AWS moves the
  # address atomically: if it is currently on another instance it is
  # disassociated and reassociated in one operation, so there is no moment when
  # the address belongs to nobody.
  _aws ec2 associate-address \
    --allocation-id "$(_aws_allocation_id)" \
    --instance-id "$instance_id" \
    --allow-reassociation >/dev/null

  holder="$(_aws_eip_holder)"
  [ "$holder" = "$instance_id" ] \
    || die "AWS accepted the request but the Elastic IP is on '${holder:-nothing}', not $node"

  ok "AWS associated $FAILOVER_IP with $node ($instance_id)"
}

provider_traffic_location() {
  if [ "$(traffic_mode)" = "managed_lb" ]; then
    _aws_target_group_location
    return
  fi

  provider_preflight
  local instance_id
  instance_id="$(_aws_eip_holder)"
  [ -n "$instance_id" ] || return 0
  node_for_provider_id "$instance_id"
}

# --- control plane ---------------------------------------------------------

# `open-tunnel` speaks the stdio protocol ssh expects from a ProxyCommand, and
# %h expands to the hostname ssh was given - which is why the admin host is the
# instance id rather than an address.
provider_admin_host() { node_provider_id "$1"; }

provider_admin_proxy_command() {
  local instance_id; instance_id="$(node_provider_id "$1")"
  [ -n "$instance_id" ] || die "no provider id configured for $1"
  printf 'aws ec2-instance-connect open-tunnel --region %s --instance-id %%h' "$(_aws_region)"
}

# Images are staged in S3 and fetched by the host over a presigned URL, which
# expires and carries no identity of its own. Two reasons for the indirection:
# the admin tunnel is not for bulk data, and a host that pulled from a registry
# would need a credential to do it. This way the hosts still hold nothing.
#
# Give the VPC an S3 *gateway* endpoint - they are free - so instances with no
# public address and no NAT gateway can still reach the bucket.
provider_publish_image() {
  local file="$1" key url
  # key must be assigned after file: bash evaluates all locals before any of
  # them is visible, so basename "$file" in the same local line is unbound.
  key="garde-images/$(basename "$file")"
  provider_preflight
  : "${AWS_IMAGE_BUCKET:?set AWS_IMAGE_BUCKET in the inventory to stage images}"

  # Do not route these through _aws: that helper forces --output text and
  # merges stderr into the captured string, which would corrupt the URL.
  if ! aws --region "$(_aws_region)" s3 cp "$file" "s3://$AWS_IMAGE_BUCKET/$key" \
        --only-show-errors; then
    die "failed to upload $file to s3://$AWS_IMAGE_BUCKET/$key"
  fi
  url="$(aws --region "$(_aws_region)" s3 presign "s3://$AWS_IMAGE_BUCKET/$key" --expires-in 900)" \
    || die "could not presign s3://$AWS_IMAGE_BUCKET/$key"
  [ -n "$url" ] || die "could not presign s3://$AWS_IMAGE_BUCKET/$key"
  printf '%s' "$url"
}

# --- power -----------------------------------------------------------------

provider_set_power() {
  local node="$1" state="$2" instance_id
  instance_id="$(node_provider_id "$node")"
  [ -n "$instance_id" ] || die "no provider id configured for $node"
  provider_preflight

  case "$state" in
    off)
      # --force is deliberate. This verb has exactly one caller, fence.sh, and
      # it only reaches here when the node is already unreachable over the mesh.
      # A graceful stop asks the OS to cooperate, and an unresponsive node is
      # precisely the one that will not; AWS then waits minutes before forcing
      # it anyway, which is minutes of a possible second writer. --force stops
      # the instance at the hypervisor, the same choice Pacemaker's fence_aws
      # agent makes with skip_os_shutdown for the same reason.
      #
      # The cost is unflushed writes on the fenced host, which is acceptable:
      # we are about to promote the other node, and a host we cannot reach is
      # one we could not have flushed anyway.
      _aws ec2 stop-instances --instance-ids "$instance_id" --force >/dev/null
      if aws --region "$(_aws_region)" ec2 wait instance-stopped --instance-ids "$instance_id" 2>/dev/null; then
        ok "AWS stopped $node ($instance_id)"
      else
        warn "AWS accepted the stop for $node but it did not reach 'stopped' in time"
      fi
      ;;
    on)
      _aws ec2 start-instances --instance-ids "$instance_id" >/dev/null
      if aws --region "$(_aws_region)" ec2 wait instance-running --instance-ids "$instance_id" 2>/dev/null; then
        ok "AWS started $node ($instance_id)"
      else
        warn "AWS accepted the start for $node but it did not reach 'running' in time"
      fi
      ;;
    reset)
      _aws ec2 reboot-instances --instance-ids "$instance_id" >/dev/null
      ok "AWS rebooted $node ($instance_id)"
      ;;
    *) die "unsupported power state '$state'" ;;
  esac
}
