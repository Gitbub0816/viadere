#!/bin/bash
# Plans, policy-checks and applies the lean staging environment from Cloud Shell (ephemeral sessions included: it installs OpenTofu,
# checksum-verified, on every run). Run from the checkout: bash Infra/azure/cloudshell/apply-staging.sh
# Required: SUB_ID STATE_SA SUFFIX DB_ADMINS_ID IMAGE. Optional: CRYPTO_OFFICERS_ID, GHCR_USER, STATE_RG (default rg-viadere-stg-tfstate).
set -uo pipefail
source "$(dirname "$0")/common.sh"
need SUB_ID STATE_SA SUFFIX DB_ADMINS_ID IMAGE
STATE_RG="${STATE_RG:-rg-viadere-stg-tfstate}"
TOFU_VERSION=1.13.2
cd "$(dirname "$0")/.." || fail "cd Infra/azure"

step "1/5 subscription"
az account set --subscription "$SUB_ID" || fail "az account set"
TENANT_ID="$(az account show --query tenantId -o tsv)" || fail "tenant"

step "2/5 OpenTofu $TOFU_VERSION"
if ! ~/bin/tofu version 2>/dev/null | grep -q "v$TOFU_VERSION"; then
  dl="$(mktemp -d)" && mkdir -p ~/bin || fail "mkdir"
  base="https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}"
  curl --proto '=https' --tlsv1.2 -fsSL -o "$dl/tofu.zip" "$base/tofu_${TOFU_VERSION}_linux_amd64.zip" || fail "download tofu"
  curl --proto '=https' --tlsv1.2 -fsSL -o "$dl/sums" "$base/tofu_${TOFU_VERSION}_SHA256SUMS" || fail "download sums"
  want="$(grep " tofu_${TOFU_VERSION}_linux_amd64.zip\$" "$dl/sums" | cut -d' ' -f1)"
  [ -n "$want" ] && echo "$want  $dl/tofu.zip" | sha256sum --check --quiet || fail "checksum"
  unzip -o -q "$dl/tofu.zip" tofu -d "$dl" && install "$dl/tofu" ~/bin/ || fail "install tofu"
fi
export PATH=~/bin:$PATH; tofu version | head -1

step "3/5 settings"
cat > backend.staging.hcl <<HCL
use_azuread_auth     = true
subscription_id      = "$SUB_ID"
resource_group_name  = "$STATE_RG"
storage_account_name = "$STATE_SA"
container_name       = "tfstate"
key                  = "viadere/azure/staging.tfstate"
HCL
cp terraform.tfvars.example terraform.tfvars
sed -i \
  -e "s/^subscription_id *= .*/subscription_id = \"$SUB_ID\"/" \
  -e "s/^tenant_id *= .*/tenant_id       = \"$TENANT_ID\"/" \
  -e "s/^name_suffix *= .*/name_suffix     = \"$SUFFIX\"/" \
  -e "s#^github_repository = .*#github_repository = \"Gitbub0816/viadere\"#" \
  -e "s/^db_admin_group_object_id .*/db_admin_group_object_id                   = \"$DB_ADMINS_ID\"/" \
  -e "s/^key_vault_crypto_officers_group_object_id .*/key_vault_crypto_officers_group_object_id  = \"${CRYPTO_OFFICERS_ID:-}\"/" \
  -e "s#^image .*#image              = \"$IMAGE\"#" \
  -e "s/^ghcr_pull_username .*/ghcr_pull_username = \"${GHCR_USER:-}\"/" \
  terraform.tfvars
if grep -nE "REPLACE|OWNER/|00000000-0000" terraform.tfvars; then fail "placeholder left in terraform.tfvars"; fi
grep -E "^(location|name_suffix)" terraform.tfvars

step "4/5 init + plan + policy check"
tofu init -input=false -backend-config=backend.staging.hcl || fail "tofu init"
tofu plan -input=false -var profile=lean -out tfplan || fail "tofu plan"
tofu show -json tfplan > plan.json || fail "tofu show"
python3 -I policy_check.py plan.json || fail "policy check"
rm -f plan.json

step "5/5 apply (20-30 minutes; press Enter now and then so Cloud Shell stays connected)"
tofu apply -input=false tfplan || fail "tofu apply"
rm -f tfplan
echo; echo "------ send these to Claude ------"
tofu output -json github_deploy
tofu output -json workload_identities
echo "DONE"
