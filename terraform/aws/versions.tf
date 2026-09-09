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
# DNS lives with the compute provider: netcup clusters use terraform/ (CCP DNS);
# AWS clusters use this module's Route 53 resources. They share no state.
#
# Tear it down with `terraform destroy` when the test is over. The only resource
# that survives is anything you put in the bucket, which the lifecycle rule
# expires anyway.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
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
