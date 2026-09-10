variable "region" {
  description = "Region for every resource here. An Elastic IP cannot cross regions, so the whole cluster lives in one."
  type        = string
  default     = "eu-central-1"
}

variable "name" {
  description = "Prefix for resource names and the basis of the instance names the driver addresses."
  type        = string
  default     = "garde"
}

variable "vpc_cidr" {
  description = "Also becomes ADMIN_SSH_SOURCES, because the tunnel reaches the hosts from an interface inside this range."
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "t3.small is the floor: Vault, Redis, the API, the UI and Caddy on one host. t3.medium if you want headroom."
  type        = string
  default     = "t3.small"
}

variable "root_volume_gb" {
  description = "Images, Vault data and snapshots. 30 is comfortable; the default 8 is not."
  type        = number
  default     = 30
}

variable "ssh_public_key" {
  description = <<-EOT
    Public half of the key Ansible bootstraps with, as an authorized_keys line.
    Required when create_bootstrap_key is true (greenfield). Ignored when the
    key already exists and is only looked up by name.
  EOT
  type    = string
  default = ""
}

variable "create_bootstrap_key" {
  description = "Create aws_key_pair.bootstrap. Set false when adopting an existing key (import)."
  type        = bool
  default     = true
}

variable "image_bucket_name" {
  description = "Globally unique. Images are staged here and fetched by the hosts over presigned URLs."
  type        = string
}

variable "image_retention_days" {
  description = "Staged images are disposable; a short expiry keeps the bucket near free."
  type        = number
  default     = 7
}

# Optional overrides when adopting an existing VPC layout (import). When null,
# subnets are cidrsubnet(vpc_cidr, 8, 1..3) and private IPs are host .10.
variable "subnet_cidrs" {
  description = "Exact /length-3 CIDR list for the three node subnets. Null = derive from vpc_cidr."
  type        = list(string)
  default     = null

  validation {
    condition     = var.subnet_cidrs == null || length(var.subnet_cidrs) == 3
    error_message = "subnet_cidrs must be null or a list of exactly 3 CIDRs."
  }
}

variable "node_private_ips" {
  description = "Exact private IPs for the three nodes (mesh endpoints). Null = cidrhost(subnet, 10)."
  type        = list(string)
  default     = null

  validation {
    condition     = var.node_private_ips == null || length(var.node_private_ips) == 3
    error_message = "node_private_ips must be null or a list of exactly 3 addresses."
  }
}
