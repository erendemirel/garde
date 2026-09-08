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
    This is not the deploy key CI uses - the playbook creates that account.
  EOT
  type        = string
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
