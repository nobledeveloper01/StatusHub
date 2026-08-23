# StatusHub on AWS: the managed pieces the application needs, and nothing it
# does not.
#
# This module provisions the database, the secrets and the network boundary.
# It deliberately does not provision compute: the Helm chart does that, and a
# Terraform module that also templates Deployments means two places disagree
# about replica counts the first time somebody scales in a hurry.
#
# What is here is what has to exist before a pod can start, and what has to
# outlive one.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = ">= 5.0" }
    random = { source = "hashicorp/random", version = ">= 3.5" }
  }
}

locals {
  name = "${var.name_prefix}-statushub"

  tags = merge(var.tags, {
    Application = "statushub"
    ManagedBy   = "terraform"
    Environment = var.environment
  })
}

# --- database ----------------------------------------------------------------

# raw_events is the irreplaceable asset: the provider will not resend, so it
# cannot be regenerated from anywhere. Every setting below is chosen for that
# one fact.
resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = var.private_subnet_ids
  tags       = local.tags
}

resource "aws_security_group" "database" {
  name        = "${local.name}-db"
  description = "StatusHub Postgres — reachable only from the application"
  vpc_id      = var.vpc_id
  tags        = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "database" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = var.application_security_group_id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Postgres from the StatusHub workloads only"
}

resource "random_password" "database" {
  length  = 48
  special = false # avoids the URL-escaping class of connection-string bug
}

resource "aws_db_instance" "this" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = var.postgres_version
  instance_class = var.database_instance_class

  allocated_storage     = var.database_storage_gb
  max_allocated_storage = var.database_max_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  db_name  = "statushub"
  username = "statushub"
  password = random_password.database.result

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false

  # RPO 5 minutes, RTO 1 hour (§11.7). Point-in-time recovery is what makes
  # the first of those achievable at all.
  backup_retention_period = var.backup_retention_days
  backup_window           = "02:00-03:00"
  copy_tags_to_snapshot   = true

  # Multi-AZ in live. The receiver's availability target is 99.99% and a
  # single-AZ database cannot support it: a provider that gets a 500 during a
  # failover may never retry.
  multi_az = var.environment == "live"

  maintenance_window         = "sun:03:30-sun:04:30"
  auto_minor_version_upgrade = true
  apply_immediately          = false

  # A final snapshot on destroy, and deletion protection in live. The one
  # thing worse than losing this database is losing it to a `terraform
  # destroy` somebody ran in the wrong directory.
  deletion_protection       = var.environment == "live"
  skip_final_snapshot       = var.environment != "live"
  final_snapshot_identifier = var.environment == "live" ? "${local.name}-final-${formatdate("YYYYMMDDhhmmss", timestamp())}" : null

  performance_insights_enabled = true
  monitoring_interval          = 60
  monitoring_role_arn          = var.rds_monitoring_role_arn

  enabled_cloudwatch_logs_exports = ["postgresql"]

  # The dispatcher's claim query and the audit chain walk are the two places
  # a slow query would be felt first, so anything over a second is logged.
  parameter_group_name = aws_db_parameter_group.this.name

  tags = local.tags

  lifecycle {
    # The snapshot identifier embeds a timestamp, which would otherwise show
    # as a diff on every plan.
    ignore_changes = [final_snapshot_identifier]
  }
}

resource "aws_db_parameter_group" "this" {
  name   = local.name
  family = "postgres${split(".", var.postgres_version)[0]}"
  tags   = local.tags

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  # Row-level security is layer three of the tenancy model. Forcing it means
  # even the owning role is subject to the policies, so a migration run as the
  # owner cannot quietly bypass them.
  parameter {
    name  = "row_security"
    value = "on"
  }
}

# --- secrets -----------------------------------------------------------------

# The database only ever holds references; the values live here. A database
# dump is therefore not a credential breach (§10.2).
resource "aws_secretsmanager_secret" "app" {
  name        = "${local.name}/app"
  description = "StatusHub application secrets: database URL, tenant salt master, audit checkpoint seed"
  kms_key_id  = var.kms_key_arn
  # Long enough to recover from a mistaken delete, short enough that a
  # rotated secret does not linger.
  recovery_window_in_days = 14
  tags                    = local.tags
}

# Every tenant's pseudonymisation salt is derived from this one value
# (ADR-004). Replacing it re-derives every salt and orphans every hash already
# stored, so it is created once and never rotated casually — hence
# ignore_changes on the version.
resource "random_password" "tenant_salt_master" {
  length  = 44
  special = false
}

# The ed25519 seed the nightly audit checkpoints are signed with. Held here
# rather than in the database on purpose: an attacker who alters an audit
# record must also forge every checkpoint since, which needs this key, so a
# full database compromise does not include it.
resource "random_password" "audit_checkpoint_seed" {
  length  = 44
  special = false
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    "database-url" = format(
      "postgres://%s:%s@%s/%s?sslmode=require",
      aws_db_instance.this.username,
      random_password.database.result,
      aws_db_instance.this.endpoint,
      aws_db_instance.this.db_name,
    )
    "tenant-salt-master"    = base64encode(random_password.tenant_salt_master.result)
    "audit-checkpoint-seed" = base64encode(random_password.audit_checkpoint_seed.result)
  })

  lifecycle {
    # Rotating the salt master orphans every stored customer hash: correlation
    # breaks across the boundary and an erasure request matches only half a
    # subject's events. Terraform must not do that as a side effect of a
    # provider upgrade regenerating a random_password.
    ignore_changes = [secret_string]
  }
}

# --- object storage for audit replication ------------------------------------

# Audit records are replicated here with a write-once lock, so immutability
# survives a full database compromise (§8.3).
resource "aws_s3_bucket" "audit" {
  bucket = "${local.name}-audit"
  tags   = local.tags

  # Object lock cannot be enabled after creation, so getting it wrong here
  # means recreating the bucket later — with the records in it.
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    default_retention {
      # Compliance mode, not governance: governance can be overridden by a
      # sufficiently privileged principal, which is exactly the principal an
      # attacker is trying to become.
      mode = "COMPLIANCE"
      days = var.audit_retention_days
    }
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
