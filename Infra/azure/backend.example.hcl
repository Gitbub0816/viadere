# Copy to backend.<env>.hcl (gitignored) and run: tofu init -backend-config=backend.<env>.hcl
# The storage account is created by the bootstrap in docs/ops/AZURE-SETUP.md section 3 (shared keys disabled, versioning, soft delete, lock).
# No tenant_id: with Azure CLI sign-in the backend refuses both tenant and subscription ("specify only one"); the CLI session sets the tenant.
use_azuread_auth     = true
subscription_id      = "00000000-0000-0000-0000-000000000000"
resource_group_name  = "rg-viadere-stg-tfstate"
storage_account_name = "stviaderestgtfstateREPLACE"
container_name       = "tfstate"
key                  = "viadere/azure/staging.tfstate"
