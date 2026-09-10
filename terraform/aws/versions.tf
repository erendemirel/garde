# Provisions the AWS side of a garde cluster: three hosts, the failover address,
# the tunnel the control plane arrives through, the bucket images are staged
# in, and (when dns_zone is set) Route 53 A records plus an ACME IAM user.
# Everything above the operating system is Ansible's job, not this module's.
#
#   cd terraform/aws
#   cp terraform.tfvars.example terraform.tfvars   # edit it
#   ./bring-up.sh                                  # preferred: apply + merge inventory
#   # or: terraform init && terraform apply
#   #     terraform output -raw inventory_fragment >> ../../deploy/inventory.env
#
# Track remaining host/app steps with ../../deploy/scripts/doctor.sh
# (see docs/AWS_BRINGUP.md).
#
# DNS: leave dns_zone empty for compute-only; set it for Route 53 + ACME IAM.
# AWS clusters use this module's Route 53 resources when dns_zone is set.
#
# Tear it down with `terraform destroy` when the test is over. The only resource
# that survives is anything you put in the bucket, which the lifecycle rule
# expires anyway.
#
# Remote state (shared by laptop + GitHub Infra):
#   bucket  garde-tfstate-518040093343-eu-central-1
#   key     garde/aws/terraform.tfstate
#   locks   DynamoDB table garde-terraform-locks
# Use the garde-terraform IAM user (AWS_TF_* secrets), not garde-ci.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }

  # Shared state for laptop + GitHub Infra. Bucket/table created once
  # (see docs/AWS_BRINGUP.md / deploy scripts); do not put credentials here.
  backend "s3" {
    bucket         = "garde-tfstate-518040093343-eu-central-1"
    key            = "garde/aws/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "garde-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "garde"
      ManagedBy = "terraform"
    }
  }
}
