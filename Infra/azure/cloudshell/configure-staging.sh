#!/bin/bash
# After apply-staging.sh: stores the secrets (AZURE-SETUP.md section 7), creates the database roles (section 8), stores the Cloudflare
# Tunnel token (section 9) and runs the first migration and api start (section 10). Run from the checkout:
#   SUB_ID=... STATE_SA=... bash Infra/azure/cloudshell/configure-staging.sh
# Before running: upload the APNs key (AuthKey_<KEYID>.p8) to your Cloud Shell home directory (Manage files > Upload).
# Prompts (input hidden, Enter skips): the GHCR read:packages token and the Cloudflare Tunnel token.
# Service keys are generated fresh, and only while job-viadere-migrate has never succeeded: once the database may hold data encrypted
# under them, a rerun keeps them (rotation is a separate, deliberate procedure). Values never appear on screen except EDGE_TOKEN, which
# you paste into Cloudflare.
set -uo pipefail
source "$(dirname "$0")/common.sh"
need SUB_ID STATE_SA
cd "$(dirname "$0")/.." || fail "cd Infra/azure"
WORK="$(mktemp -d)" && chmod 700 "$WORK" || fail "mktemp"
# The one-off admin job carries your Entra token as a secret: never leave it behind, even when a step fails.
trap 'rm -rf "$WORK"; az containerapp job delete -n job-viadere-dbadmin -g "$RG_APP" --yes -o none 2>/dev/null' EXIT

step "1/6 subscription and OpenTofu outputs"
az account set --subscription "$SUB_ID" || fail "az account set"
tofu_ready
KV_ID="$(tofu output -json key_vault | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')" || fail "key_vault output"
CAE_ID="$(tofu output -json container_apps_environment | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')" || fail "environment output"
PG_FQDN="$(tofu output -json postgres | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["fqdn"])')" || fail "postgres output"
tofu output -json key_vault_secret_map > "$WORK/map.json" || fail "secret map output"
tofu output -json workload_identities > "$WORK/ids.json" || fail "identities output"
LOCATION="$(az group show -n "$RG_APP" --query location -o tsv)" || fail "location"
echo "vault ${KV_ID##*/}, database $PG_FQDN, region $LOCATION"
P8="$(find ~ -maxdepth 1 -name "AuthKey_*.p8" -type f | head -1)"
FIRST_RUN=1; migrate_has_run && FIRST_RUN=0
[ "$FIRST_RUN" = 0 ] || [ -n "$P8" ] || fail "upload AuthKey_<KEYID>.p8 to your Cloud Shell home directory first (Manage files > Upload)"

step "2/6 secrets"
if [ "$FIRST_RUN" = 1 ]; then
  python3 -I ../fly/generate_secrets.py --no-log-key --env-file "$WORK/s.env" >/dev/null || fail "generate secrets"
  # MailerSend is not connected yet: random placeholders keep the server's required values filled (no mail or SMS is sent with them).
  python3 -I -c 'import secrets
for n in ("EMAIL_API_KEY","MAILERSEND_SMS_API_TOKEN","MAILERSEND_SMS_INBOUND_SECRET","MAILERSEND_SMS_WEBHOOK_SECRET"):
    print(f"{n}=placeholder-{secrets.token_urlsafe(24)}")' >> "$WORK/s.env" || fail "placeholders"
  python3 -I ../fly/generate_secrets.py --check "$WORK/s.env" || fail "secret check"
  python3 -I kv_tool.py put-env --vault-id "$KV_ID" --map "$WORK/map.json" --env-file "$WORK/s.env" || fail "store secrets"
  EDGE_TOKEN_VALUE="$(grep '^EDGE_TOKEN=' "$WORK/s.env" | cut -d= -f2-)"
else
  echo "job-viadere-migrate has already succeeded: keeping the stored service keys and edge token"
fi
if [ -n "$P8" ]; then python3 -I kv_tool.py put --vault-id "$KV_ID" --name apns-p8 < "$P8" || fail "store apns-p8"; fi

echo
echo "GitHub token for pulling the server image (classic token, read:packages only). Enter skips (package is public or token already stored):"
read -rs GHCR_TOKEN; echo
if [ -n "$GHCR_TOKEN" ]; then printf '%s' "$GHCR_TOKEN" | python3 -I kv_tool.py put --vault-id "$KV_ID" --name ghcr-pull-token || fail "store ghcr-pull-token"; fi
unset GHCR_TOKEN
echo "Cloudflare Tunnel token (Zero Trust > Networks > Tunnels > viadere-staging-azure; the long value after --token). Enter skips:"
read -rs TUNNEL_TOKEN; echo
if [ -n "$TUNNEL_TOKEN" ]; then printf '%s' "$TUNNEL_TOKEN" | python3 -I kv_tool.py put --vault-id "$KV_ID" --name cloudflared-tunnel-token || fail "store tunnel token"; fi
HAVE_TUNNEL="${TUNNEL_TOKEN:+1}"; unset TUNNEL_TOKEN

step "3/6 database roles (one-off job as grp-viadere-db-admins)"
python3 -I - "$WORK/ids.json" > "$WORK/db-roles.sql" <<'PY' || fail "role SQL"
import json, re, sys
ids = json.load(open(sys.argv[1]))
roles = {"viadere_migrator": "migrator", "viadere_app": "api", "viadere_worker": "worker"}
print("-- runs in database postgres as the Entra admin group; safe to rerun")
for role, identity in roles.items():
    oid = ids[identity]["principal_id"]
    assert re.fullmatch(r"[0-9a-f-]{36}", oid)
    print(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN "
          f"PERFORM pgaadauth_create_principal_with_oid('{role}', '{oid}', 'service', false, false); END IF; END $$;")
print("ALTER DATABASE viadere OWNER TO viadere_migrator;")
print("GRANT CONNECT ON DATABASE viadere TO viadere_app, viadere_worker;")
print("\\connect viadere")
print("ALTER SCHEMA public OWNER TO viadere_migrator;")
print("REVOKE CREATE ON SCHEMA public FROM PUBLIC;")
PY
python3 -I kv_tool.py psql-job --environment-id "$CAE_ID" --location "$LOCATION" --host "$PG_FQDN" --sql "$WORK/db-roles.sql" \
  --out "$WORK/dbadmin-job.json" >/dev/null || fail "job spec (are you a member of grp-viadere-db-admins?)"
az containerapp job delete -n job-viadere-dbadmin -g "$RG_APP" --yes -o none 2>/dev/null
az containerapp job create -n job-viadere-dbadmin -g "$RG_APP" --yaml "$WORK/dbadmin-job.json" -o none || fail "create dbadmin job"
rm -f "$WORK/dbadmin-job.json"
run_job job-viadere-dbadmin

step "4/6 migrations"
run_job job-viadere-migrate

step "5/6 api and tunnel"
az containerapp update -n ca-viadere-api -g "$RG_APP" --min-replicas 1 -o none || fail "start api"
if [ -n "$HAVE_TUNNEL" ]; then
  REV="$(az containerapp show -n ca-cloudflared -g "$RG_APP" --query properties.latestRevisionName -o tsv)"
  az containerapp revision restart -n ca-cloudflared -g "$RG_APP" --revision "$REV" -o none || fail "restart cloudflared"
fi
for _ in $(seq 1 40); do
  STATE="$(az containerapp show -n ca-viadere-api -g "$RG_APP" --query properties.runningStatus -o tsv 2>/dev/null)"
  HEALTH="$(az containerapp revision list -n ca-viadere-api -g "$RG_APP" --query "[?properties.active] | [0].properties.healthState" -o tsv 2>/dev/null)"
  echo "api: ${STATE:-?} / revision ${HEALTH:-?}"
  [ "$HEALTH" = "Healthy" ] && break
  [ "$HEALTH" = "Unhealthy" ] && fail "api revision unhealthy (logs: az containerapp logs show -n ca-viadere-api -g $RG_APP --tail 50)"
  sleep 15
done

step "6/6 Cloudflare"
if [ -n "${EDGE_TOKEN_VALUE:-}" ]; then
  echo "Edge token: in Cloudflare, Rules > Transform Rules > Modify Request Header, create a rule for hostname viadere-api-az.cksites.dev"
  echo "that SETS header X-Viadere-Edge-Token to this value (shown once, not stored anywhere else):"
  echo; echo "    $EDGE_TOKEN_VALUE"; echo
fi
echo "Then: curl -fsS https://viadere-api-az.cksites.dev/healthz"
echo "DONE"
