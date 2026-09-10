# Non-secret layout of the live AWS garde account. Loaded automatically.
# Greenfield accounts should delete this file (or override) and set
# create_bootstrap_key = true + ssh_public_key in terraform.tfvars.

create_bootstrap_key = false

subnet_cidrs = [
  "10.0.0.0/20",
  "10.0.16.0/20",
  "10.0.32.0/20",
]

node_private_ips = [
  "10.0.9.185",
  "10.0.22.97",
  "10.0.35.224",
]

instance_type  = "t3.small"
root_volume_gb = 30
