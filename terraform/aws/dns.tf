# DNS for the AWS garde cluster: Route 53 A records for app and api.
#
# Where they point depends on traffic_mode.
#
#   floating_ip  the Elastic IP. Failover moves that address between EC2
#                instances, so DNS never changes and there is no TTL wait on
#                cutover. Caddy solves ACME DNS-01 against the same hosted zone
#                (see AWS_ACME_* credentials). Do not declare _acme-challenge
#                records here — Caddy creates and removes them.
#
#   managed_lb   alias records to the load balancer, which holds the address
#                and an ACM certificate. Nothing on the hosts issues
#                certificates, so there is no DNS-01 at all.

variable "dns_zone" {
  description = <<-EOT
    Public Route 53 zone name, e.g. example.com. Leave empty to skip DNS
    resources (compute-only apply). When set, Terraform creates the zone unless
    dns_zone_id is also set (then it attaches records to that existing zone).
  EOT
  type        = string
  default     = ""
}

variable "dns_zone_id" {
  description = "Existing public hosted zone id (Z…). When set, dns_zone is only used for validation/display."
  type        = string
  default     = ""
}

variable "app_hostname" {
  description = "Hostname for the web UI, relative to the zone"
  type        = string
  default     = "app"
}

variable "api_hostname" {
  description = "Hostname for the garde API, relative to the zone"
  type        = string
  default     = "api"
}

variable "dns_record_ttl" {
  description = "TTL for the app/api A records. Keep low so abandoning the EIP is recoverable without a long wait."
  type        = number
  default     = 60
}

locals {
  manage_dns      = var.dns_zone != "" || var.dns_zone_id != ""
  create_dns_zone = var.dns_zone != "" && var.dns_zone_id == ""
  # DNS-01 exists only where Caddy issues the certificates. Under a managed
  # load balancer ACM does, and the ACME IAM user is never created.
  manage_acme = local.manage_dns && !local.managed_lb
}

resource "aws_route53_zone" "main" {
  count = local.create_dns_zone ? 1 : 0
  name  = var.dns_zone

  tags = { Name = "${var.name}-dns" }
}

data "aws_route53_zone" "existing" {
  count   = var.dns_zone_id != "" ? 1 : 0
  zone_id = var.dns_zone_id
}

locals {
  hosted_zone_id = local.manage_dns ? (
    var.dns_zone_id != "" ? data.aws_route53_zone.existing[0].zone_id : aws_route53_zone.main[0].zone_id
  ) : ""
  hosted_zone_name = local.manage_dns ? (
    var.dns_zone_id != "" ? data.aws_route53_zone.existing[0].name : aws_route53_zone.main[0].name
  ) : ""
  hosted_zone_arn = local.manage_dns ? (
    var.dns_zone_id != "" ? data.aws_route53_zone.existing[0].arn : aws_route53_zone.main[0].arn
  ) : ""

  zone_suffix = trimsuffix(local.hosted_zone_name, ".")
  app_fqdn    = local.manage_dns ? "${var.app_hostname}.${local.zone_suffix}" : ""
  api_fqdn    = local.manage_dns ? "${var.api_hostname}.${local.zone_suffix}" : ""
}

resource "aws_route53_record" "app" {
  count = local.manage_dns && !local.managed_lb ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = local.app_fqdn
  type    = "A"
  ttl     = var.dns_record_ttl
  records = [aws_eip.failover.public_ip]
}

resource "aws_route53_record" "api" {
  count = local.manage_dns && !local.managed_lb ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = local.api_fqdn
  type    = "A"
  ttl     = var.dns_record_ttl
  records = [aws_eip.failover.public_ip]
}

# Alias rather than a plain A record: an ALB's addresses change without notice,
# and an alias follows them with no TTL of its own to wait out.
resource "aws_route53_record" "app_lb" {
  count = local.manage_dns && local.managed_lb ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = local.app_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.main[0].dns_name
    zone_id                = aws_lb.main[0].zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "api_lb" {
  count = local.manage_dns && local.managed_lb ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = local.api_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.main[0].dns_name
    zone_id                = aws_lb.main[0].zone_id
    evaluate_target_health = false
  }
}
