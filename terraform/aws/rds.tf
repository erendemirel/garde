# Shared PostgreSQL for durable garde state (permissions, users catalog, …).
# App nodes are stateless aside from Vault Agent credentials; every instance
# points at this endpoint via Vault secrets (DATABASE_URL or POSTGRES_*).
#
# Password is supplied as a Terraform variable (or TF_VAR_*) — never hardcoded.
# Seed the resulting endpoint into Vault after apply.

variable "postgres_password" {
  description = "Master password for the garde RDS instance. Leave empty to skip creating RDS."
  type        = string
  sensitive   = true
  default     = ""
}

variable "postgres_username" {
  description = "Master username for RDS."
  type        = string
  default     = "garde"
}

variable "postgres_db_name" {
  description = "Initial database name."
  type        = string
  default     = "garde"
}

variable "postgres_instance_class" {
  description = "Small default suitable for bring-up; raise for production."
  type        = string
  default     = "db.t4g.micro"
}

locals {
  create_rds = var.postgres_password != ""
}

resource "aws_db_subnet_group" "main" {
  count = local.create_rds ? 1 : 0

  name       = "${var.name}-postgres"
  subnet_ids = aws_subnet.nodes[*].id

  tags = { Name = "${var.name}-postgres" }
}

resource "aws_security_group" "postgres" {
  count = local.create_rds ? 1 : 0

  name        = "${var.name}-postgres"
  description = "garde RDS PostgreSQL"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Postgres from app nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.nodes.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name}-postgres" }
}

resource "aws_db_instance" "main" {
  count = local.create_rds ? 1 : 0

  identifier     = "${var.name}-postgres"
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.postgres_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.postgres_db_name
  username = var.postgres_username
  password = var.postgres_password

  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.main[0].name
  vpc_security_group_ids = [aws_security_group.postgres[0].id]
  publicly_accessible    = false
  skip_final_snapshot    = true
  deletion_protection    = false
  apply_immediately      = true

  tags = { Name = "${var.name}-postgres" }
}
