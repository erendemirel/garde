output "failover_ip" {
  description = "The Elastic IP. app/api A records point here (see Route 53 resources when dns_zone is set)."
  value       = aws_eip.failover.public_ip
}

output "dns_nameservers" {
  description = "Delegate the domain to these when Terraform created the hosted zone."
  value       = try(aws_route53_zone.main[0].name_servers, [])
}

output "dns_zone_id" {
  description = "Hosted zone id Caddy / ops tools may need."
  value       = local.manage_dns ? local.hosted_zone_id : null
}

output "instance_ids" {
  description = "In node order. These are NODE*_PROVIDER_ID and the hostnames the tunnel addresses."
  value       = aws_instance.nodes[*].id
}

output "private_ips" {
  description = "In node order. These are NODE*_MESH_ENDPOINT."
  value       = aws_instance.nodes[*].private_ip
}

output "ci_access_key_id" {
  description = "Store as the AWS_ACCESS_KEY_ID secret (compute / failover)."
  value       = aws_iam_access_key.ci.id
}

output "ci_secret_access_key" {
  description = "Store as the AWS_SECRET_ACCESS_KEY secret."
  value       = aws_iam_access_key.ci.secret
  sensitive   = true
}

output "acme_access_key_id" {
  description = "Store as AWS_ACME_ACCESS_KEY_ID (Caddy DNS-01 only). Empty when dns_zone is unset."
  value       = try(aws_iam_access_key.acme[0].id, null)
}

output "acme_secret_access_key" {
  description = "Store as AWS_ACME_SECRET_ACCESS_KEY."
  value       = try(aws_iam_access_key.acme[0].secret, null)
  sensitive   = true
}

output "target_group_arn" {
  description = "Store as AWS_TARGET_GROUP_ARN in the inventory. Null unless traffic_mode = managed_lb."
  value       = try(aws_lb_target_group.app[0].arn, null)
}

output "lb_dns_name" {
  description = "The load balancer's own name. app/api alias records point here; useful for checking the edge before DNS propagates."
  value       = try(aws_lb.main[0].dns_name, null)
}

output "vault_kms_key_id" {
  description = "Pass to inventory as VAULT_KMS_KEY_ID (alias or key id for seal awskms)."
  value       = aws_kms_alias.vault.name
}

output "vault_kms_key_arn" {
  description = "Full ARN of the Vault auto-unseal CMK."
  value       = aws_kms_key.vault.arn
}

# Everything the inventory needs for this provider, ready to paste. Generated
# rather than transcribed, because an instance id copied wrongly fails in a way
# that looks like a permissions problem.
output "inventory_fragment" {
  description = "Append to deploy/inventory.env with `terraform output -raw inventory_fragment`"
  value       = <<-EOT
    PROVIDER=aws
    AWS_REGION=${var.region}
    ADMIN_SSH_SOURCES=${var.vpc_cidr}
    AWS_IMAGE_BUCKET=${aws_s3_bucket.images.id}
    BOOTSTRAP_SSH_USER=ubuntu
    VAULT_KMS_KEY_ID=${aws_kms_alias.vault.name}

    TRAFFIC_MODE=${var.traffic_mode}
    ${local.lb_inventory_lines}

    FAILOVER_IP=${aws_eip.failover.public_ip}

    NODE1_PROVIDER_ID=${try(aws_instance.nodes[0].id, "")}
    NODE2_PROVIDER_ID=${try(aws_instance.nodes[1].id, "")}
    NODE3_PROVIDER_ID=${try(aws_instance.nodes[2].id, "")}

    NODE1_MESH_ENDPOINT=${try(aws_instance.nodes[0].private_ip, "")}
    NODE2_MESH_ENDPOINT=${try(aws_instance.nodes[1].private_ip, "")}
    NODE3_MESH_ENDPOINT=${try(aws_instance.nodes[2].private_ip, "")}
  EOT
}
