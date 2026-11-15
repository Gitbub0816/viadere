# Launch and deploy: the command sequence (staging)

The short path from a merged `main` to a running staging environment. Each step points at the guide that explains it; run them in order.
Production uses the same steps with `production` and the `standard` profile (`AZURE-SETUP.md` section 12), and is not for now.

Placeholders: `<owner>` = the GitHub owner, `$SUB_ID`, `$RG_APP`, `$KV_ID` as printed by the earlier steps.

## 0. Local run (optional, any machine with Docker)

```bash
cd Server
cp .env.example .env            # fill in the secrets (comments in .env.example); POSTGRES_PASSWORD=$(openssl rand -hex 24)
docker compose up --build
docker compose run --rm server seed --env development
```

Or without Docker: `cd Server && swift run ViadereServer seed && swift run ViadereServer serve --hostname 127.0.0.1 --port 8080` (SQLite).

## 1. Merge and release

1. Merge the pull request into `main` (GitHub offers the workflows below only once they are on `main`).
2. Tag a release; `release.yml` builds, scans, signs and attests both images (`viadere-server`, `viadere-authority`):

```bash
git checkout main && git pull
git tag -s v0.1.0 -m "Viadere 0.1.0"
git push origin v0.1.0
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
gh api "/users/<owner>/packages/container/viadere%2Fviadere-server/versions" --jq '.[0].name'      # server digest sha256:...
gh api "/users/<owner>/packages/container/viadere%2Fviadere-authority/versions" --jq '.[0].name'   # authority digest
```

## 2. Azure, first time only (`AZURE-SETUP.md` sections 2 to 9)

```bash
az login --tenant <tenant-id> && az account set --subscription "$SUB_ID"
```

Then, in order: budget (2.2), resource providers (2.3), Entra groups (2.4), state storage (3), CI identities (4),
GitHub variables (5), first apply (6):

```bash
cd Infra/azure
tofu init -backend-config=backend.staging.hcl
tofu plan -var profile=lean -out tfplan
tofu show -json tfplan > plan.json && python3 -I policy_check.py plan.json && rm plan.json
tofu apply tfplan && rm tfplan
tofu output -json key_vault_secret_map > map.json
tofu output -json github_deploy
```

Secrets (7):

```bash
cd "$(git rev-parse --show-toplevel)"
python3 -I Infra/azure/generate_secrets.py --env-file "$WORK/s.env"     # then append the MailerSend values
python3 -I Infra/azure/generate_secrets.py --check "$WORK/s.env"
python3 -I Infra/azure/kv_tool.py put-env --vault-id "$KV_ID" --map Infra/azure/map.json --env-file "$WORK/s.env"
python3 -I Infra/azure/kv_tool.py put --vault-id "$KV_ID" --name apns-p8 < AuthKey_<KEYID>.p8
```

Database roles (8), Cloudflare Tunnel (9). From then on, infrastructure changes go through
Actions > Azure > Run workflow (`apply = true`).

## 3. Deploy the server

```bash
gh workflow run azure.yml -f environment=staging -f deploy_digest=sha256:<server digest>
gh run watch "$(gh run list --workflow azure.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
curl -fsS https://viadere-api-az.cksites.dev/healthz && curl -fsS https://viadere-api-az.cksites.dev/readyz
```

The workflow verifies the signature, runs the migrate job, then rolls the api to the same digest. Verification checklist:
`AZURE-SETUP.md` section 10.

## 4. The private authority (`AUTHORITY-OWNER-CHECKLIST.md`, steps A to E)

Repository variables first (C4), including `APPLE_TEAM_ID` and, when needed, `AUTHORITY_ENV_JSON`:

```bash
gh variable set AZURE_AUTH_IAC_ENABLED --body true
gh variable set AUTHORITY_ENABLED_IAC --body true
gh variable set AUTHORITY_ENTRA_AUDIENCE --body api://viadere-authority-staging
gh variable set APPLE_TEAM_ID --body <TEAMID>
gh workflow run authority-infra.yml -f apply=true
gh workflow run authority-deploy.yml -f digest=sha256:<authority digest>
```

Then the database bootstrap (E5), secrets (E6), keys and pins (E7, E10, `KEY-ROTATION.md` sections 8 and 9), monitoring (E8), and the
gates of E9 before any authority flag. Publishing discovery and JWKS:

```bash
gh workflow run authority-admin.yml -f command=key-inventory-record -f change_file=Infra/azure-authority/changes/<name>.json
gh workflow run authority-admin.yml -f command=key-inventory-check -f change_file=Infra/azure-authority/changes/<name>.json
gh workflow run authority-admin.yml -f command=key-version-pin -f change_file=Infra/azure-authority/changes/<pin>.json   # once per key
gh workflow run authority-publish.yml -f inventory_run_id=<admin run id> -f issuer=https://id.<staging domain>
```

## 5. Website (`STAGING-SETUP.md` section 13)

```bash
gh workflow run site.yml -f target=staging
```

## 6. iOS app (Mac with the current Xcode; `STAGING-SETUP.md` sections 11 and 12)

```bash
cd App
cp Configs/Local.xcconfig.example Configs/Local.xcconfig      # DEVELOPMENT_TEAM = <TEAMID>
python3 -I Scripts/compute-spki-pins.py viadere-api.cksites.dev  # put two CA pins into Configs/Staging.xcconfig
xcodegen
open Viadere.xcodeproj                                           # scheme Staging, a real iPhone, Run
```

TestFlight: Product > Archive with both the app and the server switched to production APNs and App Attest (section 12).

## 7. Features that stay off until their owner step

| Switch | Needs |
|---|---|
| `LOOPS_CONNECTED_ENABLED` | nothing external; turn on after review of §2.115 |
| `AUTHORITY_ENABLED`, `OIDC_PROVIDER_ENABLED`, `AUTH_LINK_SERVICE_ENABLED` | authority E9 gates |
| `CKEY_SAFE_ACTION_ISSUER` (in `AUTHORITY_ENV_JSON`) | the pinned `ckey-safe-action-signing` key and `VIADERE_CKEY_SAFE_ACTION_KEYS` in the app build |
| Email OTP fallback | L-8 (provider storage terms) |
| `WALLET_STATUS_LIST_HOSTS` | the issuers' status-list hosts |
| `FCM_ENABLED`, `PLAY_INTEGRITY_ENABLED`, `ANDROID_*` | Android (not now) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | an OTLP endpoint |
