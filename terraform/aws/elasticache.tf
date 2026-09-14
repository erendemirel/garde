# Shared Redis for sessions and ephemeral data. App nodes treat Redis as
# ephemeral shared state — prefer this ElastiCache cluster (or another managed
# Redis) over per-node Redis.
#
# AUTH token is supplied as a Terraform variable — never hardcoded. Seed
# redis_host / redis_password into Vault after apply.

variable "redis_auth_token" {
  description = "Redis AUTH token (16+ chars). Leave empty to skip creating ElastiCache."
  type        = string
  sensitive   = true
  default     = ""

  validation {
    condition     = var.redis_auth_token == "" || length(var.redis_auth_token) >= 16
    error_message = "redis_auth_token must be empty (skip) or at least 16 characters."
  }
}

variable "redis_node_type" {
  description = "Small default suitable for bring-up; raise for production."
  type        = string
  default     = "cache.t4g.micro"
}

locals {
  create_redis = var.redis_auth_token != ""
}

resource "aws_elasticache_subnet_group" "main" {
  count = local.create_redis ? 1 : 0

  name       = "${var.name}-redis"
  subnet_ids = aws_subnet.nodes[*].id
}

resource "aws_security_group" "redis" {
  count = local.create_redis ? 1 : 0

  name        = "${var.name}-redis"
  description = "garde ElastiCache Redis"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from app nodes"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.nodes.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-redis" }
}

resource "aws_elasticache_replication_group" "main" {
  count = local.create_redis ? 1 : 0

  replication_group_id = "${var.name}-redis"
  description          = "garde shared Redis (ephemeral)"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_clusters   = 2
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.main[0].name
  security_group_ids = [aws_security_group.redis[0].id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_auth_token
  automatic_failover_enabled = true
  multi_az_enabled           = true
  apply_immediately          = true

  tags = { Name = "${var.name}-redis" }
}
