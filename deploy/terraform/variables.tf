variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
}

variable "environment" {
  description = <<-EOT
    "live" or "test". Live turns on the settings that cost money and exist to
    protect the one asset that cannot be regenerated: Multi-AZ, deletion
    protection and a final snapshot.
  EOT
  type        = string

  validation {
    condition     = contains(["live", "test"], var.environment)
    error_message = "environment must be live or test — the same two StatusHub itself recognises."
  }
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  description = "At least two, in different availability zones, or Multi-AZ cannot be satisfied."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "at least two subnets are required; a single-subnet group cannot support Multi-AZ."
  }
}

variable "application_security_group_id" {
  description = <<-EOT
    The security group the StatusHub pods run in. The database accepts
    connections from this and nothing else — not a CIDR, because a CIDR
    quietly grows to include whatever else lands in the subnet.
  EOT
  type        = string
}

variable "postgres_version" {
  description = "Postgres major.minor. 16 or later: the schema uses NULLS NOT DISTINCT semantics and partition-wise features that older majors handle differently."
  type        = string
  default     = "16.4"
}

variable "database_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "database_storage_gb" {
  type    = number
  default = 100
}

variable "database_max_storage_gb" {
  description = <<-EOT
    Autoscaling ceiling. raw_events grows fastest and retention drops whole
    partitions rather than deleting rows, so storage is sawtoothed rather than
    monotonic — but the ceiling matters: running out of disk is the one
    failure that stops the receiver acknowledging.
  EOT
  type        = number
  default     = 1000
}

variable "backup_retention_days" {
  description = "Point-in-time recovery window. §11.7 targets RPO 5 minutes, RTO 1 hour."
  type        = number
  default     = 14
}

variable "audit_retention_days" {
  description = <<-EOT
    Object-lock retention for replicated audit records. Seven years by
    default, per §11.7. Note this is COMPLIANCE mode: it cannot be shortened
    afterwards, by anybody, which is the point.
  EOT
  type        = number
  default     = 2557
}

variable "kms_key_arn" {
  description = "Customer-managed key for the database, secrets and audit bucket. Null uses AWS-managed keys."
  type        = string
  default     = null
}

variable "rds_monitoring_role_arn" {
  description = "IAM role for enhanced monitoring."
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
