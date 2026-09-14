# Three hosts, one per availability zone. Ubuntu because the Ansible roles
# assume apt and ufw.
#
# Roles: two (or more) identical `app` nodes behind the edge, plus a `witness`
# for Vault Raft quorum and monitoring.
#
# Private addresses are fixed rather than left to DHCP. They become
# NODE*_MESH_ENDPOINT, and a WireGuard endpoint that changed when an instance
# restarted would silently partition the mesh.

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

# Greenfield: create the key. Import / adopt: look up the existing key by name
# (aws_key_pair import cannot store public_key, so managing it ForceNews forever).
resource "aws_key_pair" "bootstrap" {
  count = var.create_bootstrap_key ? 1 : 0

  key_name   = "${var.name}-bootstrap"
  public_key = var.ssh_public_key
}

data "aws_key_pair" "bootstrap" {
  count = var.create_bootstrap_key ? 0 : 1

  key_name = "${var.name}-bootstrap"
}

locals {
  # Index 0 and 1 are identical app nodes; index 2 is the witness (Vault vote +
  # monitoring). Adjust roles here if you add more app instances.
  roles                = ["app", "app", "witness"]
  app_instance_indexes = [for i, r in local.roles : i if r == "app"]
  bootstrap_key_name   = var.create_bootstrap_key ? aws_key_pair.bootstrap[0].key_name : data.aws_key_pair.bootstrap[0].key_name
}

resource "aws_instance" "nodes" {
  count = 3

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.nodes[count.index].id
  vpc_security_group_ids = [aws_security_group.nodes.id]
  key_name               = local.bootstrap_key_name
  private_ip             = local.node_private_ips[count.index]
  iam_instance_profile   = aws_iam_instance_profile.vault.name

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  # Require IMDSv2. Hop limit 2 so the Vault container (bridge network) can
  # reach the metadata service for the instance role used by seal "awskms".
  # Hop 1 would leave Vault sealed after every reboot with "access denied".
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tags = {
    Name    = "${var.name}-${count.index + 1}"
    Role    = local.roles[count.index]
    Project = "garde"
  }

  # AMI / root disk drift must not rebuild live nodes after import.
  lifecycle {
    ignore_changes = [ami, root_block_device]
  }
}

# Allocated for the floating_ip traffic mode (and kept for reversibility when
# using managed_lb). Terraform may initially associate it with the first app
# node; day-to-day routing in floating_ip mode is via traffic.sh / the provider
# driver, which is why instance association is ignored after create.
resource "aws_eip" "failover" {
  domain   = "vpc"
  instance = aws_instance.nodes[0].id

  tags = { Name = "${var.name}-edge-ip" }

  lifecycle {
    ignore_changes = [instance]
  }

  depends_on = [aws_internet_gateway.main]
}
