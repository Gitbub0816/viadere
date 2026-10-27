# Google Cloud KMS (ADR-03): HSM-backed, non-exportable service keys behind the server's KeyManagementService protocol.
# Least privilege: the server's service account can only SIGN (and read public keys) on signing keys and ENCRYPT/DECRYPT on key-
# encryption keys. Key administration and key use are different principals. Every key operation is in Cloud Audit Logs (ADMIN_READ,
# DATA_READ, DATA_WRITE) and exported to a locked log bucket. Alerts fire on destroy/disable and on use by anyone but the server.

locals {
  kms_services = ["cloudkms.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com", "logging.googleapis.com", "monitoring.googleapis.com"]

  # Asymmetric signing keys: EC P-256 / SHA-256 HSM keys, one per purpose so a compromise or a rotation never crosses purposes.
  # Asymmetric keys have no automatic rotation in Cloud KMS: rotate by creating a new key version and publishing the new key id
  # (docs/ops/RUNBOOKS.md "Signing-key compromise").
  signing_keys = {
    "audit-head"   = "Signs exported audit chain heads (ViadereServer audit-head); verifiable by anyone with the public key, independent of AUDIT_CHAIN_KEY."
    "connect-link" = "Signs connect links (QR/buttons). TARGET design: asymmetric ES256 so verifiers need no secret. Today the server uses the HMAC CONNECT_LINK_SIGNING_KEY."
    "webhook"      = "Platform webhook signing with versioned key ids (spec §4.3). TARGET design; today each endpoint has its own HMAC secret."
  }

  # Envelope encryption: Cloud KMS does not offer the HPKE KEM (RFC 9180 DHKEM(P-256), ADR-07) as a decrypt operation, so HPKE private keys and
  # the field-encryption key are generated in the server and stored WRAPPED by these symmetric HSM keys (key-encryption keys).
  # Decision to revisit when Cloud KMS offers ECDH key agreement for HSM keys with the needed KDF integration.
  envelope_keys = {
    "data-kek" = "Wraps DATA_ENCRYPTION_KEY (AES-256-GCM field-encryption key) at rest. Rotation creates a new primary version; rewrap with the re-encryption job."
    "hpke-kek" = "Wraps the service HPKE private keys (identity disclosure E2EE, key directory)."
  }
}

resource "google_project_service" "kms" {
  for_each           = toset(local.kms_services)
  project            = var.gcp_project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_kms_key_ring" "viadere" {
  name       = "viadere-${var.environment}"
  location   = var.kms_location
  project    = var.gcp_project_id
  depends_on = [google_project_service.kms]
  # Key rings cannot be deleted in GCP; destroying this resource only removes it from state.
}

resource "google_kms_crypto_key" "signing" {
  for_each = local.signing_keys
  name     = each.key
  key_ring = google_kms_key_ring.viadere.id
  purpose  = "ASYMMETRIC_SIGN"
  labels   = { purpose = each.key, environment = var.environment }

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  # Destroy is a 30-day scheduled, recoverable operation; Terraform may never destroy a key by itself.
  destroy_scheduled_duration = "2592000s"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "envelope" {
  for_each        = local.envelope_keys
  name            = each.key
  key_ring        = google_kms_key_ring.viadere.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_key_rotation_period
  labels          = { purpose = each.key, environment = var.environment }

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  destroy_scheduled_duration = "2592000s"
  lifecycle {
    prevent_destroy = true
  }
}

# ---- Dedicated service account (the only principal that may use the keys) ---------------------------------------------------
resource "google_service_account" "server_kms" {
  project      = var.gcp_project_id
  account_id   = "viadere-server-kms-${var.environment}"
  display_name = "Viadere server (${var.environment}) KMS user"
  description  = "Sign and wrap/unwrap only. No key administration, no other GCP access."
}

# No service-account keys are ever created. The Fly machines impersonate the account through workload identity federation.
resource "google_service_account_iam_member" "server_workload_identity" {
  service_account_id = google_service_account.server_kms.name
  role               = "roles/iam.workloadIdentityUser"
  member             = var.kms_workload_identity_pool
}

# Sign only (no verify-with-private, no decrypt) + read the public key to publish it.
resource "google_kms_crypto_key_iam_member" "signer" {
  for_each      = google_kms_crypto_key.signing
  crypto_key_id = each.value.id
  role          = "roles/cloudkms.signer"
  member        = "serviceAccount:${google_service_account.server_kms.email}"
}

resource "google_kms_crypto_key_iam_member" "public_key_viewer" {
  for_each      = google_kms_crypto_key.signing
  crypto_key_id = each.value.id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.server_kms.email}"
}

# Encrypt/decrypt only on the key-encryption keys.
resource "google_kms_crypto_key_iam_member" "envelope" {
  for_each      = google_kms_crypto_key.envelope
  crypto_key_id = each.value.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.server_kms.email}"
}

# Humans (break-glass groups) may only VIEW metadata. Key administration (roles/cloudkms.admin, which cannot use keys) is granted
# out of band to the security-admin group through a time-bound, approved IAM condition and is intentionally not in this module.
resource "google_kms_key_ring_iam_member" "viewers" {
  for_each    = toset(var.kms_signing_principals)
  key_ring_id = google_kms_key_ring.viadere.id
  role        = "roles/cloudkms.viewer"
  member      = each.value
}

# ---- Audit logs for key access --------------------------------------------------------------------------------------------
resource "google_project_iam_audit_config" "kms" {
  project = var.gcp_project_id
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

resource "google_logging_project_bucket_config" "kms_audit" {
  project          = var.gcp_project_id
  location         = var.kms_location
  bucket_id        = "viadere-kms-audit-${var.environment}"
  retention_days   = 400
  locked           = false # set true after the retention period is agreed with counsel: a locked bucket cannot be shortened or deleted
  enable_analytics = true
  depends_on       = [google_project_service.kms]
}

resource "google_logging_project_sink" "kms_audit" {
  project                = var.gcp_project_id
  name                   = "viadere-kms-audit-${var.environment}"
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.kms_audit.id}"
  filter                 = "protoPayload.serviceName=\"cloudkms.googleapis.com\" AND logName:\"cloudaudit.googleapis.com\""
  unique_writer_identity = true
}

# ---- Alerts: administrative key changes, and key USE by any principal other than the server --------------------------------
resource "google_logging_metric" "kms_admin_change" {
  project = var.gcp_project_id
  name    = "viadere_kms_admin_change_${var.environment}"
  filter  = <<-EOT
    protoPayload.serviceName="cloudkms.googleapis.com"
    AND protoPayload.methodName=~"(DestroyCryptoKeyVersion|DisableCryptoKeyVersion|UpdateCryptoKey|UpdateCryptoKeyPrimaryVersion|SetIamPolicy|CreateCryptoKeyVersion)"
    AND protoPayload.resourceName:"keyRings/viadere-${var.environment}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "kms_unexpected_use" {
  project = var.gcp_project_id
  name    = "viadere_kms_unexpected_use_${var.environment}"
  filter  = <<-EOT
    protoPayload.serviceName="cloudkms.googleapis.com"
    AND protoPayload.methodName=~"(AsymmetricSign|Decrypt|Encrypt)$"
    AND protoPayload.resourceName:"keyRings/viadere-${var.environment}"
    AND NOT protoPayload.authenticationInfo.principalEmail="${google_service_account.server_kms.email}"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "kms" {
  for_each     = { admin_change = google_logging_metric.kms_admin_change.name, unexpected_use = google_logging_metric.kms_unexpected_use.name }
  project      = var.gcp_project_id
  display_name = "Viadere KMS ${each.key} (${var.environment})"
  combiner     = "OR"
  conditions {
    display_name = each.key
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${each.value}\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = var.security_alert_notification_channel_ids
  documentation {
    content   = "A KMS key was changed or used by an unexpected principal. Follow docs/ops/RUNBOOKS.md, Signing-key compromise."
    mime_type = "text/markdown"
  }
}
