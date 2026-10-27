# State backend: PLACEHOLDER. State contains sensitive values (Neon role passwords, provider tokens): use an encrypted, access-logged,
# versioned remote backend with locking and restrict read access to the infrastructure owners. Choose ONE and fill the values via
# `tofu init -backend-config=backend.<env>.hcl` (do not commit the .hcl; backend.example.hcl lists the keys).
#
# Recommended: a GCS bucket in a dedicated project (customer-managed KMS key, object versioning, uniform bucket-level access,
# retention lock) because the GCP project already exists for KMS. Alternative: Cloudflare R2 through the S3 backend.
terraform {
  backend "gcs" {
    # bucket = "..."   # from backend.<env>.hcl
    # prefix = "viadere/infra"
  }
}
