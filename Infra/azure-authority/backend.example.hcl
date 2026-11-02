# Copy to backend.<env>.hcl (gitignored) and run: tofu init -backend-config=backend.<env>.hcl
# Same Entra-only state account as Infra/azure (docs/ops/AZURE-SETUP.md section 3); a DIFFERENT key, and the apply identity
# id-gh-infra-auth-apply-<env> gets Storage Blob Data Contributor on this blob prefix's container only (AUTHORITY-OWNER-CHECKLIST.md).
use_azuread_auth     = true
subscription_id      = "00000000-0000-0000-0000-000000000000"
resource_group_name  = "rg-viadere-stg-tfstate"
storage_account_name = "stviaderestgtfstateREPLACE"
container_name       = "tfstate"
key                  = "viadere/azure-authority/staging.tfstate"
