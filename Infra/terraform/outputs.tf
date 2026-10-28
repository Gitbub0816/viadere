output "api_hostname" {
  value = local.api_host
}

output "kms_key_ring" {
  value = google_kms_key_ring.viadere.id
}

output "kms_signing_key_ids" {
  description = "Key ids to configure in the server's KeyManagementService (versions are resolved at runtime via the primary version)."
  value       = { for k, v in google_kms_crypto_key.signing : k => v.id }
}

output "kms_envelope_key_ids" {
  value = { for k, v in google_kms_crypto_key.envelope : k => v.id }
}

output "kms_service_account_email" {
  value = google_service_account.server_kms.email
}

output "neon_project_id" {
  value = neon_project.viadere.id
}

output "neon_database_host" {
  description = "Direct (non-pooled) host. Compose DATABASE_URL yourself and store it with `fly secrets set`; passwords are never output."
  value       = neon_project.viadere.database_host
}

output "mtls_hostname" {
  description = "Tier E enterprise hostname (empty unless enable_mtls)."
  value       = var.enable_mtls ? local.mtls_host : ""
}
