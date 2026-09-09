# Three subnets in three availability zones, all routed to an internet gateway.
#
# WHY THE SUBNETS ARE PUBLIC, GIVEN THE HOSTS ARE MEANT TO BE PRIVATE.
#
# An Elastic IP only works where the subnet's route table has a default route to
# an internet gateway - the address is a one-to-one translation performed at that
# gateway, and return traffic has to leave the same way it arrived. So the app
# nodes cannot sit behind a NAT instance: a NAT default route and an internet
# gateway default route are the same entry in the same table, and you may only
# have one.
#
# That is also why auto-assigned public addresses are on. The node holding the
# Elastic IP is reachable and can reach out; the node that is not holding it
# would otherwise have no route at all, and it still needs to install packages
# and renew its own certificates. Auto-assignment gives it an address of its own
# for exactly as long as it is not the primary.
#
# The two do not collide. Associating the Elastic IP replaces whatever public
# address the instance had, and releasing it takes public connectivity away
# until the instance is stopped and started - which is precisely what fencing
# does, so a demoted node comes back with a fresh address.
#
# Node-to-node traffic never depends on any of this: WireGuard peers over the
# private addresses below, which nothing here ever changes.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.name }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "nodes" {
  count = 3

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # See the note above: without this, only the node holding the Elastic IP has
  # any path to the internet.
  map_public_ip_on_launch = true

  tags = { Name = "${var.name}-${count.index + 1}" }
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = var.name }
}

resource "aws_route_table_association" "nodes" {
  count = 3

  subnet_id      = aws_subnet.nodes[count.index].id
  route_table_id = aws_route_table.main.id
}

# Free, and it keeps image transfer off the public path entirely: the hosts
# fetch staged images over the AWS network rather than through the gateway.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.main.id]

  tags = { Name = "${var.name}-s3" }
}
