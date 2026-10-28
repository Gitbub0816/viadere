# Write-once storage for exported audit-chain heads (WP6, OPS-004 tamper resistance). The server (`AUDIT_HEAD_EXPORT=gcs`) writes one object
# per head with `ifGenerationMatch=0` (create-only); the bucket's LOCKED retention policy makes every object immutable for the whole period,
# so a database or server compromise cannot rewrite or delete an old head. Each head is also signed by the HSM `audit-head` key (kms.tf).
#
# Alternative without Google Cloud storage: a Cloudflare R2 bucket with Object Lock (a bucket lock rule `retention` of the same period) and
# `AUDIT_HEAD_EXPORT=r2` (S3-compatible endpoint, access key limited to PutObject on that bucket; see docs/ops/RUNBOOKS.md "Audit-head export").
# R2 needs no resource here: create the bucket and lock rule in the Cloudflare dashboard or with the cloudflare provider's r2 resources.

resource "google_storage_bucket" "audit_heads" {
  project  = var.gcp_project_id
  name     = "viadere-audit-heads-${var.environment}-${var.gcp_project_id}"
  location = var.audit_bucket_location

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  storage_class               = "STANDARD"
  # Versioning stays off: objects are create-only and immutable; a soft delete window would only extend what an attacker with admin rights could read.
  versioning { enabled = false }
  soft_delete_policy { retention_duration_seconds = 0 }

  retention_policy {
    retention_period = var.audit_head_retention_seconds
    # A locked policy can never be shortened or removed and the bucket cannot be deleted until every object has aged out. Keep false in
    # staging and until counsel has agreed the period (docs/ops/DATA-INVENTORY.md, audit log retention); set true in production.
    is_locked = var.audit_bucket_lock
  }

  labels = { purpose = "audit-heads", environment = var.environment }

  lifecycle {
    prevent_destroy = true
  }
}

# Create-only: roles/storage.objectCreator carries storage.objects.create and nothing else (no get, list, update or delete). Reading is done by auditors with a
# separate, human-held viewer role granted out of band.
resource "google_storage_bucket_iam_member" "server_creator" {
  bucket = google_storage_bucket.audit_heads.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.server_kms.email}"
}

resource "google_storage_bucket_iam_member" "auditor_viewer" {
  for_each = toset(var.audit_bucket_auditors)
  bucket   = google_storage_bucket.audit_heads.name
  role     = "roles/storage.objectViewer"
  member   = each.value
}

variable "audit_bucket_location" {
  description = "Location of the audit-head bucket (a region near the Fly primary region, or a multi-region such as US)."
  type        = string
  default     = "US-EAST1"
}

variable "audit_head_retention_seconds" {
  description = "Retention period of exported audit heads. Default 7 years; agree the final period with counsel before locking."
  type        = number
  default     = 220752000
}

variable "audit_bucket_lock" {
  description = "Lock the retention policy (IRREVERSIBLE). Production only, after the period is agreed."
  type        = bool
  default     = false
}

variable "audit_bucket_auditors" {
  description = "Principals (group:/user:) that may read exported heads. Never the server."
  type        = list(string)
  default     = []
}

output "audit_head_bucket" {
  description = "AUDIT_HEAD_EXPORT_TARGET when AUDIT_HEAD_EXPORT=gcs."
  value       = google_storage_bucket.audit_heads.name
}

output "audit_head_kms_key" {
  description = "Crypto key of AUDIT_HEAD_KMS_KEY (append /cryptoKeyVersions/<n> of the primary version)."
  value       = google_kms_crypto_key.signing["audit-head"].id
}
