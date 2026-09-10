# DNS for the AWS garde cluster: Route 53 A records for app/api → Elastic IP.
#
# Failover moves the Elastic IP between EC2 instances; DNS stays pointed at
# that address, so there is no TTL wait on cutover. Caddy solves ACME DNS-01
# against the same hosted zone (see AWS_ACME_* credentials).
#
# Do not declare _acme-challenge records here — Caddy creates and removes them.

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
}

resource "aws_route53_record" "app" {
  count = local.manage_dns ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = "${var.app_hostname}.${trimsuffix(local.hosted_zone_name, ".")}"
  type    = "A"
  ttl     = var.dns_record_ttl
  records = [aws_eip.failover.public_ip]
}

resource "aws_route53_record" "api" {
  count = local.manage_dns ? 1 : 0

  zone_id = local.hosted_zone_id
  name    = "${var.api_hostname}.${trimsuffix(local.hosted_zone_name, ".")}"
  type    = "A"
  ttl     = var.dns_record_ttl
  records = [aws_eip.failover.public_ip]
}
