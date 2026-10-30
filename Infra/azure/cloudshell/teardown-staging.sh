#!/bin/bash
# Removes a lean staging environment (not the OpenTofu state storage) so it can be rebuilt, e.g. in another region.
# Log settings are deleted first: Azure keeps a diagnostic setting after its resource is deleted and re-attaches it to a new resource with
# the same ID, which then fails the next apply with "already exists". The Key Vault stays soft-deleted (purge protection): use a new
# name_suffix for the rebuild. Usage: SUB_ID=... STATE_SA=... bash teardown-staging.sh
set -uo pipefail
source "$(dirname "$0")/common.sh"
need SUB_ID STATE_SA
az account set --subscription "$SUB_ID" || fail "az account set"
RGS="rg-viadere-stg-app rg-viadere-stg-data rg-viadere-stg-ops rg-viadere-stg-sec"

step "locks and log settings"
for rg in $RGS rg-viadere-stg-net; do
  [ "$(az group exists -n "$rg")" = "true" ] || continue
  for l in $(az lock list -g "$rg" --query "[].id" -o tsv); do az lock delete --ids "$l" || fail "lock $l"; done
  for id in $(az resource list -g "$rg" --query "[].id" -o tsv); do
    az monitor diagnostic-settings delete --name diag-to-log --resource "$id" 2>/dev/null && echo "removed log setting on ${id##*/}"
  done
done

step "log workspace (permanent delete frees the name for another region)"
az monitor log-analytics workspace delete -g rg-viadere-stg-ops -n log-viadere-stg --force true --yes 2>/dev/null || echo "(none)"

step "resource groups"
for rg in $RGS; do [ "$(az group exists -n "$rg")" = "true" ] && az group delete -n "$rg" --yes --no-wait; done
for rg in $RGS; do az group wait -n "$rg" --deleted --timeout 1800 2>/dev/null; echo "$rg gone"; done
if [ "$(az group exists -n rg-viadere-stg-net)" = "true" ]; then az group delete -n rg-viadere-stg-net --yes || fail "delete net"; fi
echo "rg-viadere-stg-net gone"

step "OpenTofu state"
az storage blob delete --account-name "$STATE_SA" -c tfstate -n viadere/azure/staging.tfstate --auth-mode login -o none 2>/dev/null \
  && echo "state cleared" || echo "(no state blob)"
echo "TEARDOWN DONE"
