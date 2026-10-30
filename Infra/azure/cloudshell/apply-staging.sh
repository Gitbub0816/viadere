#!/bin/bash
# Plans, policy-checks and applies the lean staging environment from Cloud Shell (ephemeral sessions included: it installs OpenTofu,
# checksum-verified, on every run). Run from the checkout: bash Infra/azure/cloudshell/apply-staging.sh
# Required: SUB_ID STATE_SA SUFFIX DB_ADMINS_ID IMAGE. Optional: CRYPTO_OFFICERS_ID, GHCR_USER, STATE_RG (default rg-viadere-stg-tfstate).
set -uo pipefail
source "$(dirname "$0")/common.sh"
need SUB_ID STATE_SA SUFFIX DB_ADMINS_ID IMAGE
cd "$(dirname "$0")/.." || fail "cd Infra/azure"

step "1/4 subscription and OpenTofu"
az account set --subscription "$SUB_ID" || fail "az account set"
TENANT_ID="$(az account show --query tenantId -o tsv)" || fail "tenant"
tofu_ready

step "2/4 settings"
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
# api_min_replicas = 0 is for the first apply only (no replica before secrets and database roles exist); after the first migration the
# module default (1) applies, so a later apply does not scale the api back to zero.
if migrate_has_run; then sed -i '/^api_min_replicas *=/d' terraform.tfvars; echo "first deploy done: api_min_replicas uses the default"; fi
if grep -nE "REPLACE|OWNER/|00000000-0000" terraform.tfvars; then fail "placeholder left in terraform.tfvars"; fi
grep -E "^(location|name_suffix|api_min_replicas)" terraform.tfvars

step "3/4 plan + policy check"
tofu plan -input=false -var profile=lean -out tfplan || fail "tofu plan"
tofu show -json tfplan > plan.json || fail "tofu show"
python3 -I policy_check.py plan.json || fail "policy check"
rm -f plan.json

step "4/4 apply (20-30 minutes the first time; press Enter now and then so Cloud Shell stays connected)"
tofu apply -input=false tfplan || fail "tofu apply"
rm -f tfplan
echo; echo "------ send these to Claude ------"
tofu output -json github_deploy
tofu output -json workload_identities
echo "DONE"
