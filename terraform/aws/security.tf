# Two groups and the tunnel that uses them.
#
# The node group opens exactly three things: SSH from the tunnel and nowhere
# else, WireGuard from its own members, and the public web ports. Vault, Redis
# and the exporters need no rules at all - they travel inside WireGuard, so the
# UDP rule below is the only inter-node opening, and ufw enforces which services
# may be reached once traffic is inside the mesh.

resource "aws_security_group" "eice" {
  name        = "${var.name}-eice"
  description = "EC2 Instance Connect Endpoint"
  vpc_id      = aws_vpc.main.id

  # Inbound needs no rules. Traffic reaches the endpoint from the Instance
  # Connect service itself and is authorised by IAM before it enters the VPC.
  egress {
    description = "SSH to the nodes"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${var.name}-eice" }
}

resource "aws_security_group" "nodes" {
  name        = "${var.name}-nodes"
  description = "garde cluster hosts"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-nodes" }
}

# Separate resources rather than inline blocks, because the WireGuard rule has
# to reference the group it is attached to and an inline rule cannot.
resource "aws_vpc_security_group_ingress_rule" "ssh_from_tunnel" {
  description                  = "SSH, only from the Instance Connect Endpoint"
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.eice.id
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "wireguard" {
  description                  = "WireGuard between cluster members"
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.nodes.id
  from_port                    = 51820
  to_port                      = 51820
  ip_protocol                  = "udp"
}

# floating_ip: the node holding the Elastic IP is the public edge, so it has to
# answer the web ports from anywhere.
resource "aws_vpc_security_group_ingress_rule" "http" {
  for_each = local.managed_lb ? toset([]) : toset(["80", "443"])

  description       = "Public edge"
  security_group_id = aws_security_group.nodes.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  ip_protocol       = "tcp"
}

# managed_lb: the load balancer is the only client, it speaks plain HTTP inside
# the VPC, and 443 on the host stays shut — the certificate lives on the ALB,
# so anything answering 443 here would be serving the wrong one.
resource "aws_vpc_security_group_ingress_rule" "http_from_lb" {
  count = local.managed_lb ? 1 : 0

  description                  = "Public edge, via the load balancer"
  security_group_id            = aws_security_group.nodes.id
  referenced_security_group_id = aws_security_group.lb[0].id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
}

# One endpoint per VPC is what lets the driver's ProxyCommand pass only an
# instance id: with a single endpoint in the instance's VPC, the CLI finds it
# without being told which one to use.
#
# Client IP preservation stays off, the default. That is why the firewall admits
# the VPC range rather than your own address - the tunnel arrives from this
# endpoint's network interface, not from you.
resource "aws_ec2_instance_connect_endpoint" "main" {
  subnet_id          = aws_subnet.nodes[0].id
  security_group_ids = [aws_security_group.eice.id]
  preserve_client_ip = false

  tags = { Name = var.name }
}
