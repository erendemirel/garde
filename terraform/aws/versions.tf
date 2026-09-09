# Provisions the AWS side of a garde cluster: three hosts, the failover address,
# the tunnel the control plane arrives through, and the bucket images are staged
# in. Everything above the operating system is Ansible's job, not this module's.
#
#   cd terraform/aws
#   cp terraform.tfvars.example terraform.tfvars   # edit it
#   terraform init && terraform apply
#   terraform output -raw inventory_fragment >> ../../deploy/inventory.env
#
# A separate root module from terraform/, which drives netcup DNS. They share no
# state and no provider, so keep them apart rather than teaching one module to
# span two clouds.
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
