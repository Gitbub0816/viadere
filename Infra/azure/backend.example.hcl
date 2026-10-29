# Copy to backend.<env>.hcl (gitignored) and run: tofu init -backend-config=backend.<env>.hcl
# The storage account is created by the bootstrap in docs/ops/AZURE-SETUP.md section 3 (shared keys disabled, versioning, soft delete, lock).
use_azuread_auth     = true
tenant_id            = "00000000-0000-0000-0000-000000000000"
subscription_id      = "00000000-0000-0000-0000-000000000000"
resource_group_name  = "rg-viadere-stg-tfstate"
storage_account_name = "stviaderestgtfstateREPLACE"
container_name       = "tfstate"
key                  = "viadere/azure/staging.tfstate"
