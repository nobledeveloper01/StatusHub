output "secret_arn" {
  description = <<-EOT
    The Secrets Manager secret holding the database URL, the tenant salt
    master and the audit checkpoint seed. Point the Helm chart's
    secrets.existingSecret at a Kubernetes Secret synced from this — with the
    External Secrets Operator or Secrets Store CSI driver — rather than
    copying the values, so rotation happens in one place.
  EOT
  value       = aws_secretsmanager_secret.app.arn
}

output "database_endpoint" {
  value = aws_db_instance.this.endpoint
}

output "database_security_group_id" {
  value = aws_security_group.database.id
}

output "audit_bucket" {
  description = "Write-once bucket for replicated audit records."
  value       = aws_s3_bucket.audit.id
}

output "next_steps" {
  description = "What Terraform cannot do for you."
  value       = <<-EOT
    1. Sync ${aws_secretsmanager_secret.app.arn} into a Kubernetes Secret named
       "statushub" with keys: database-url, tenant-salt-master,
       audit-checkpoint-seed.

    2. helm install statushub deploy/helm/statushub \
         --set config.baseURL=https://hooks.example.com \
         --set config.environment=${var.environment}

    3. Run `statushubctl doctor` in the cluster before pointing a provider at
       it. Clock skew is the check worth reading: it breaks HMAC timestamp
       windows in both directions and produces an error that tells you
       nothing.

    Compute is not managed here on purpose. The Helm chart owns replica counts
    and scaling, and two places disagreeing about those is a bad afternoon the
    first time somebody scales in a hurry.
  EOT
}
