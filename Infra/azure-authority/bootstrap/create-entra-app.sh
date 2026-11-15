#!/usr/bin/env bash
# Owner-run (Azure Cloud Shell or a terminal with `az login` as an Entra application administrator). NOT run by CI: CI holds no Microsoft
# Graph write right (ADR-0019 section "Consequences", ADR-0028). Creates the Entra application `viadere-authority-<env>` with the two app
# roles of ADR-0028 section 9 and assigns them: Authority.Evidence.Submit -> id-viadere-api ONLY, Authority.Revocations -> id-viadere-worker.
# Then prints the verification (the worker must NOT hold Evidence.Submit: policy rule AUTH-REVOCATIONS-ROLE).
#
#   ENV=staging API_PRINCIPAL_ID=<oid of id-viadere-api> WORKER_PRINCIPAL_ID=<oid of id-viadere-worker> bash create-entra-app.sh
#
# UNTESTED against a live tenant (written 2026-11-02): run it once, read every line it prints, and keep the output summary in
# docs/reviews/IMPLEMENTATION_LEDGER.md.
set -uo pipefail
fail() { echo "FAILED: $*" >&2; exit 1; }
: "${ENV:?set ENV=staging|production}" "${API_PRINCIPAL_ID:?}" "${WORKER_PRINCIPAL_ID:?}"
case "$ENV" in staging|production) ;; *) fail "ENV must be staging or production" ;; esac
NAME="viadere-authority-${ENV}"
URI="api://${NAME}"

SUBMIT_ID="$(python3 -I -c 'import uuid; print(uuid.uuid4())')"
REVOKE_ID="$(python3 -I -c 'import uuid; print(uuid.uuid4())')"
ROLES="$(mktemp)"
cat > "$ROLES" <<JSON
[
  {"allowedMemberTypes": ["Application"], "description": "Submit evidence to the authority (api only)", "displayName": "Authority.Evidence.Submit",
   "id": "${SUBMIT_ID}", "isEnabled": true, "value": "Authority.Evidence.Submit"},
  {"allowedMemberTypes": ["Application"], "description": "Post revocations (worker; reaches POST revocations only)", "displayName": "Authority.Revocations",
   "id": "${REVOKE_ID}", "isEnabled": true, "value": "Authority.Revocations"}
]
JSON

APP_ID="$(az ad app list --display-name "$NAME" --query "[0].appId" -o tsv)"
if [ -z "$APP_ID" ]; then
  APP_ID="$(az ad app create --display-name "$NAME" --sign-in-audience AzureADMyOrg --identifier-uris "$URI" --app-roles @"$ROLES" --query appId -o tsv)" || fail "create app"
  az ad sp create --id "$APP_ID" > /dev/null || fail "create service principal"
else
  echo "application exists ($APP_ID): app roles are NOT changed by this script"
fi
SP_ID="$(az ad sp show --id "$APP_ID" --query id -o tsv)" || fail "service principal"
SUBMIT_ID="$(az ad app show --id "$APP_ID" --query "appRoles[?value=='Authority.Evidence.Submit'].id | [0]" -o tsv)"
REVOKE_ID="$(az ad app show --id "$APP_ID" --query "appRoles[?value=='Authority.Revocations'].id | [0]" -o tsv)"
[ -n "$SUBMIT_ID" ] && [ -n "$REVOKE_ID" ] || fail "app roles missing"

assign() { # principal, role id
  az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo" \
    --body "{\"principalId\":\"$1\",\"resourceId\":\"${SP_ID}\",\"appRoleId\":\"$2\"}" > /dev/null 2>&1 || echo "assignment exists or failed for $1 (check below)"
}
assign "$API_PRINCIPAL_ID" "$SUBMIT_ID"
assign "$WORKER_PRINCIPAL_ID" "$REVOKE_ID"

echo "--- verification (read-only) ---"
az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo" \
  --query "value[].{principal:principalId, role:appRoleId}" -o table
echo "Evidence.Submit id: $SUBMIT_ID   Revocations id: $REVOKE_ID"
bad="$(az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignedTo" \
  --query "value[?principalId=='${WORKER_PRINCIPAL_ID}' && appRoleId=='${SUBMIT_ID}'] | length(@)" -o tsv)"
[ "$bad" = "0" ] || fail "the worker holds Authority.Evidence.Submit (AUTH-REVOCATIONS-ROLE)"
echo "audience (authority_entra_audience): $URI"
echo "api oid:    $API_PRINCIPAL_ID"
echo "worker oid: $WORKER_PRINCIPAL_ID   (put both in authority_caller_object_ids)"
rm -f "$ROLES"
