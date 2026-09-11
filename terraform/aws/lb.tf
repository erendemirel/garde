# The managed-load-balancer lane: an ALB in front of the same three hosts.
#
# Created only when traffic_mode = "managed_lb". The default, "floating_ip",
# leaves every resource here at zero and the cluster behaves exactly as before.
#
# What moves off the hosts in this mode:
#
#   public TLS      an ACM certificate on the listener, renewed by AWS. No
#                   Caddy ACME, no DNS-01 credentials, no warm-standby
#                   certificate problem to solve.
#   the address     the ALB owns it. Failover no longer remaps an Elastic IP,
#                   so there is no window where it belongs to nobody.
#   liveness        health checks pull a broken node out in seconds rather
#                   than waiting for an operator to notice.
#
# What does not change: the cluster is still warm-standby, not active-active.
# The target group holds one instance at a time because the standby's Redis is
# a replica. Terraform deliberately creates no target attachments — membership
# is operational state that failover.sh owns through the provider driver, and
# a Terraform-managed attachment would fight it on every apply.
#
# Caddy stays on the hosts, listening on plain :80, because the Host-header
# split between the UI and the API is one rule in one file here and two more
# target groups plus listener rules there.
#
# The Elastic IP is still allocated in this mode, deliberately. It costs cents
# while unassociated and it is what makes the two modes reversible: switching
# back is a tfvars change and a traffic.sh route, not a new address and a DNS
# change waiting out a TTL.

variable "traffic_mode" {
  description = <<-EOT
    floating_ip (default) or managed_lb. floating_ip keeps the Elastic IP that
    every VPS provider's design uses. managed_lb builds the ALB below and is
    what AWS itself would suggest.
  EOT
  type        = string
  default     = "floating_ip"

  validation {
    condition     = contains(["floating_ip", "managed_lb"], var.traffic_mode)
    error_message = "traffic_mode must be floating_ip or managed_lb."
  }
}

variable "lb_certificate_arn" {
  description = "Existing ACM certificate for the app/api names. Empty = Terraform requests one, which needs a managed Route 53 zone."
  type        = string
  default     = ""
}

variable "lb_health_check_path" {
  description = "Served by Caddy in load-balancer mode and proxied to garde's /health, so an API that cannot reach Redis fails the check."
  type        = string
  default     = "/healthz"
}

variable "lb_deregistration_delay" {
  description = "Seconds an outgoing target keeps draining. Short, because a failover has already fenced it."
  type        = number
  default     = 15
}

locals {
  managed_lb = var.traffic_mode == "managed_lb"
  # Terraform requests the certificate only when it also controls the zone that
  # has to answer the validation records.
  create_certificate = local.managed_lb && var.lb_certificate_arn == ""
  certificate_arn = local.managed_lb ? (
    var.lb_certificate_arn != "" ? var.lb_certificate_arn : try(aws_acm_certificate_validation.main[0].certificate_arn, "")
  ) : ""

  # Assembled here so the inventory output stays a flat template. In
  # floating_ip mode the keys are emitted as comments rather than omitted:
  # someone reading a generated fragment should be able to see which lane it
  # came from.
  lb_inventory_lines = local.managed_lb ? join("\n", [
    "AWS_TARGET_GROUP_ARN=${try(aws_lb_target_group.app[0].arn, "")}",
    "LB_SOURCE_CIDRS=${var.vpc_cidr}",
    "LB_TRUSTED_PROXIES=${var.vpc_cidr}",
  ]) : "# AWS_TARGET_GROUP_ARN / LB_SOURCE_CIDRS / LB_TRUSTED_PROXIES: managed_lb only"
}

resource "terraform_data" "managed_lb_preconditions" {
  count = local.managed_lb ? 1 : 0

  lifecycle {
    precondition {
      condition     = local.manage_dns || var.lb_certificate_arn != ""
      error_message = "traffic_mode=managed_lb needs either a Route 53 zone (dns_zone / dns_zone_id) so Terraform can request and validate a certificate, or an existing lb_certificate_arn."
    }
  }
}

# --- certificate -------------------------------------------------------------

resource "aws_acm_certificate" "main" {
  count = local.create_certificate ? 1 : 0

  domain_name               = local.app_fqdn
  subject_alternative_names = [local.api_fqdn]
  validation_method         = "DNS"

  # The listener references this certificate, so it has to exist before the old
  # one can go.
  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = var.name }
}

resource "aws_route53_record" "cert_validation" {
  for_each = local.create_certificate ? {
    for option in aws_acm_certificate.main[0].domain_validation_options :
    option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  } : {}

  zone_id         = local.hosted_zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "main" {
  count = local.create_certificate ? 1 : 0

  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# --- the balancer ------------------------------------------------------------

resource "aws_security_group" "lb" {
  count = local.managed_lb ? 1 : 0

  name        = "${var.name}-lb"
  description = "garde public load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP, redirected to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To the nodes Caddy (HTTP)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${var.name}-lb" }
}

resource "aws_lb" "main" {
  count = local.managed_lb ? 1 : 0

  name               = "${var.name}-edge"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.lb[0].id]
  # All three subnets: an ALB needs at least two AZs, and the target may be in
  # any of them after a failover.
  subnets = aws_subnet.nodes[*].id

  # Malformed headers are dropped rather than forwarded. The client address
  # still arrives in X-Forwarded-For, which Caddy believes because
  # LB_TRUSTED_PROXIES names this VPC and garde believes because
  # TRUSTED_PROXIES names the compose subnet — without that chain, rate
  # limiting would see one address for every request.
  drop_invalid_header_fields = true

  tags = { Name = "${var.name}-edge" }
}

resource "aws_lb_target_group" "app" {
  count = local.managed_lb ? 1 : 0

  name                 = "${var.name}-app"
  port                 = 80
  protocol             = "HTTP"
  vpc_id               = aws_vpc.main.id
  target_type          = "instance"
  deregistration_delay = var.lb_deregistration_delay

  health_check {
    path                = var.lb_health_check_path
    protocol            = "HTTP"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }

  tags = { Name = "${var.name}-app" }
}

resource "aws_lb_listener" "https" {
  count = local.managed_lb ? 1 : 0

  load_balancer_arn = aws_lb.main[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app[0].arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  count = local.managed_lb ? 1 : 0

  load_balancer_arn = aws_lb.main[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
