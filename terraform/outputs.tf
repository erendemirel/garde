output "app_fqdn" {
  description = "Public hostname of the web UI"
  value       = "${var.app_hostname}.${var.zone}"
}

output "api_fqdn" {
  description = "Public hostname of the garde API"
  value       = "${var.api_hostname}.${var.zone}"
}

output "failover_ip" {
  description = "IP both hostnames resolve to, routed to whichever node is primary"
  value       = var.failover_ip
}
