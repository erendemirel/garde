terraform {
  required_version = ">= 1.6.0"

  required_providers {
    netcup = {
      source  = "rixlhq/netcup"
      version = "~> 0.1"
    }
  }

  # State contains DNS records and server ids rather than credentials, but keep
  # it out of the repository regardless. A remote backend is worth configuring
  # once more than one person can run this.
  #
  # backend "s3" {
  #   bucket = "..."
  #   key    = "garde/terraform.tfstate"
  # }
}

provider "netcup" {
  # CCP credentials (Customer Control Panel > Master Data > API) drive DNS.
  customer_number = var.netcup_customer_number
  api_key         = var.netcup_api_key
  api_password    = var.netcup_api_password

  # SCP credentials (OAuth device flow) drive server and failover IP resources.
  scp_refresh_token = var.netcup_scp_refresh_token
}
