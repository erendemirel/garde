# DNS for the garde deployment on netcup.
#
# Both hostnames resolve to the failover IP. Failover moves that IP between
# servers through the SCP API, so DNS stays untouched during a cutover and
# there is no TTL to wait out.
#
# DNS follows the hosting provider: this root is for PROVIDER=netcup only.
# AWS clusters manage Route 53 inside terraform/aws/ instead.
#
# What Terraform does NOT manage here is the failover IP routing itself. A
# `netcup_scp_failover_ip_v4` resource would record "the IP belongs to node1" in
# state, and the next plan after a failover would try to route it back to the
# dead node. Routing is owned by deploy/scripts/traffic.sh, which goes through
# the provider driver and honours its cooldown. See the block at the bottom.

resource "netcup_dns_zone" "main" {
  name = var.zone
  ttl  = var.zone_ttl
}

resource "netcup_dns_record" "app" {
  zone        = var.zone
  hostname    = var.app_hostname
  type        = "A"
  destination = var.failover_ip

  depends_on = [netcup_dns_zone.main]
}

resource "netcup_dns_record" "api" {
  zone        = var.zone
  hostname    = var.api_hostname
  type        = "A"
  destination = var.failover_ip

  depends_on = [netcup_dns_zone.main]
}

# Let's Encrypt validation happens over DNS-01 with the netcup provider, so
# Caddy creates and removes _acme-challenge records itself. Do not declare them
# here: Terraform would delete records mid-issuance.

# --- deliberately not enabled ------------------------------------------------
#
# resource "netcup_scp_failover_ip_v4" "public" {
#   user_id        = var.netcup_scp_user_id
#   failover_ip_id = var.failover_ip_id
#   server_id      = var.primary_server_id
# }
#
# Enabling this makes Terraform an active participant in failover, which is the
# wrong place for it: an emergency cutover must not depend on a plan/apply
# cycle, and Terraform has no notion of the 301-second cooldown.
