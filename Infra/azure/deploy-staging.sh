#!/bin/bash
# Deploy a published release tag to Azure staging from any terminal with the Azure CLI (macOS bash 3.2 compatible).
#
#   bash Infra/azure/deploy-staging.sh v0.1.0-staging.15
#
# 1. Resolves the tag's image digest from GHCR and refuses anything that is not a container image (e.g. a signature or attestation
#    manifest), then checks the image's revision label matches the commit the tag points to.
# 2. Points job-viadere-migrate at the image and runs it; stops if the migration does not succeed.
# 3. Updates ca-viadere-api to the image (same digest), waits, prints the revisions and readyz.
# Needs: az (logged in), curl, python3, git (run inside the repository so the tag can be checked).
set -u
TAG="${1:-}"
SUB_ID="${SUB_ID:-a5901912-4e66-4a96-8457-430cec423acf}"
RG="rg-viadere-stg-app"
REPO="gitbub0816/viadere/viadere-server"
fail() { echo "FAILED: $*"; exit 1; }
case "$TAG" in v*-staging.*) ;; *) fail "usage: bash Infra/azure/deploy-staging.sh v0.1.0-staging.N" ;; esac

echo "== 1/4 image for $TAG"
TOKEN=$(curl -fsS "https://ghcr.io/token?scope=repository:$REPO:pull" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])') || fail "GHCR token"
ACCEPT="Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
DIGEST=$(curl -fsSI -H "Authorization: Bearer $TOKEN" -H "$ACCEPT" "https://ghcr.io/v2/$REPO/manifests/$TAG" \
  | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}' | tr -d '\r') || fail "manifest for $TAG (is the Release workflow finished?)"
case "$DIGEST" in sha256:*) ;; *) fail "no digest for $TAG (is the Release workflow finished?)" ;; esac
MANIFEST=$(curl -fsS -H "Authorization: Bearer $TOKEN" -H "$ACCEPT" "https://ghcr.io/v2/$REPO/manifests/$DIGEST") || fail "manifest $DIGEST"
CONFIG=$(echo "$MANIFEST" | python3 -c '
import sys, json
m = json.load(sys.stdin)
if m.get("artifactType") or (m.get("config") or {}).get("mediaType") not in ("application/vnd.docker.container.image.v1+json", "application/vnd.oci.image.config.v1+json"):
    sys.exit("not a container image (artifact/attestation manifest)")
print(m["config"]["digest"])') || fail "$DIGEST is not a container image"
REVISION=$(curl -fsSL -H "Authorization: Bearer $TOKEN" "https://ghcr.io/v2/$REPO/blobs/$CONFIG" \
  | python3 -c 'import sys,json;print(((json.load(sys.stdin).get("config") or {}).get("Labels") or {}).get("org.opencontainers.image.revision",""))') || fail "image config"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1 || git fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null; then
  EXPECTED=$(git rev-parse "$TAG^{commit}")
  [ "$REVISION" = "$EXPECTED" ] || fail "image revision $REVISION does not match $TAG ($EXPECTED)"
fi
IMG="ghcr.io/$REPO@$DIGEST"
echo "image $IMG"
echo "built from ${REVISION:-unknown}"

echo "== 2/4 Azure"
az account set --subscription "$SUB_ID" || fail "az account set (run az login first)"

echo "== 3/4 migrate"
az containerapp job update -n job-viadere-migrate -g "$RG" --image "$IMG" -o none || fail "migrate job image"
EXEC=$(az containerapp job start -n job-viadere-migrate -g "$RG" --query name -o tsv) || fail "start migrate"
echo "execution $EXEC"
STATUS=""
for _ in $(seq 1 60); do
  STATUS=$(az containerapp job execution show -n job-viadere-migrate -g "$RG" --job-execution-name "$EXEC" --query properties.status -o tsv 2>/dev/null)
  echo "  $STATUS"
  [ "$STATUS" = "Succeeded" ] && break
  [ "$STATUS" = "Failed" ] && fail "migration failed: the api was NOT updated (logs: SUB_ID=$SUB_ID bash Infra/azure/cloudshell/job-logs.sh job-viadere-migrate 1)"
  sleep 15
done
[ "$STATUS" = "Succeeded" ] || fail "migration did not finish in 15 minutes: the api was NOT updated"

echo "== 4/4 api"
az containerapp update -n ca-viadere-api -g "$RG" --image "$IMG" -o none || fail "api update"
echo "api updated; waiting 150 s for the new revision"
sleep 150
az containerapp revision list -n ca-viadere-api -g "$RG" \
  --query "[].{name:name,traffic:properties.trafficWeight,health:properties.healthState,state:properties.runningState}" -o table
curl -fsS https://viadere-api.cksites.dev/readyz; echo
echo "DONE: $TAG ($REVISION) is on staging"
