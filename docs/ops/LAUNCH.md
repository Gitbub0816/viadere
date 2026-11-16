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

### 1b. Without GitHub-hosted Actions (local release from the Mac, staging only)

When Actions cannot run (for example the account is locked over billing), build, scan, push and sign on the Mac, then deploy:

```bash
brew install cosign syft trivy
gh auth refresh -s write:packages
bash Infra/release-local.sh v0.1.0-staging.1
az login && bash Infra/azure/deploy-staging.sh v0.1.0-staging.1
```

The signature is keyless with your own Sigstore identity, so `azure.yml`'s signature check (release workflow identity) refuses these
images by design; `deploy-staging.sh` is the deploy path for them. Production stays CI-only (it also needs the SLSA provenance).

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
curl -fsS https://api-staging.viadere.io/healthz && curl -fsS https://api-staging.viadere.io/readyz
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
gh workflow run authority-publish.yml -f inventory_run_id=<admin run id> -f issuer=https://id-staging.viadere.io
```

## 5. Website (`STAGING-SETUP.md` section 13)

```bash
gh workflow run site.yml -f target=staging
```

## 6. iOS app (Mac with the current Xcode; `STAGING-SETUP.md` sections 11 and 12)

```bash
cd App
cp Configs/Local.xcconfig.example Configs/Local.xcconfig      # DEVELOPMENT_TEAM = <TEAMID>
python3 -I Scripts/compute-spki-pins.py api-staging.viadere.io  # put two CA pins into Configs/Staging.xcconfig
xcodegen
open Viadere.xcodeproj                                           # scheme Staging, a real iPhone, Run
```

TestFlight: Product > Archive with both the app and the server switched to production APNs and App Attest (section 12).

## 6a. Move staging to viadere.io (owner decision 2026-11-16, once)

Staging leaves `cksites.dev` for `staging.viadere.io` (web, links, passkey RP), `api-staging.viadere.io` (API),
`assets-staging.viadere.io` (Brand Kit assets) and `site-staging.viadere.io` (marketing site). Why it is safe and what stays shared:
`SECURITY.md` §2.116. In order:

- [ ] **Cloudflare.** With a short-lived API token (Zone: Read, DNS: Edit, Transform Rules: Edit, Cache Rules: Edit on `viadere.io`;
      optionally Zone: Read and Transform Rules: Read on `cksites.dev` to copy the old edge token; Account > Cloudflare Tunnel: Edit):
      `python3 -I Infra/cloudflare/point_staging_to_azure.py`, then `python3 -I Infra/cloudflare/add_asset_host.py`. Both print the plan
      and ask; the token is read without echo; nothing is written to disk; neither touches `viadere.io`, `www.viadere.io` or
      `api.viadere.io`. Add `_dmarc.staging.viadere.io` (`Infra/cloudflare/viadere-staging-dns.txt`). Delete the token afterwards.
- [ ] **MailerSend.** Add and verify the sender domain `staging.viadere.io` (`STAGING-SETUP.md` step 6); the inbound and status webhook
      URLs become `https://api-staging.viadere.io/v1/providers/sms/...` (step 9.6).
- [ ] **Site.** Workers > `viadere-site-staging` > Domains & Routes: add the custom domain `site-staging.viadere.io` (and its Access
      application), remove the old one.
- [ ] **Azure `app_env`.** In your real `Infra/azure/terraform.tfvars` (not the example) set `PUBLIC_BASE_URL = "https://api-staging.viadere.io"`,
      `RP_ID = "staging.viadere.io"`, `RP_ORIGIN = "https://staging.viadere.io"`, `LINK_DOMAIN = "staging.viadere.io"`,
      `ASSET_DOMAIN = "assets-staging.viadere.io"`, `EMAIL_FROM_ADDRESS = "Viadere Staging <no-reply@staging.viadere.io>"` (and
      `OIDC_ISSUER = "https://id-staging.viadere.io"` if the provider is on), and the GitHub `staging` environment variable
      `AZURE_SMOKE_HOST = api-staging.viadere.io`. GitHub Actions is billing-locked, so apply from Cloud Shell:
      `bash Infra/azure/cloudshell/apply-staging.sh`. A staging server now refuses to start with a production name in these settings.
- [ ] **Redeploy** the api (`bash Infra/azure/deploy-staging.sh`, or section 3 when Actions works) and check
      `curl -fsS https://api-staging.viadere.io/readyz` and
      `curl -fsS https://staging.viadere.io/.well-known/apple-app-site-association` (200, JSON, no redirect, lists `TEAMID.com.viadere.app`).
- [ ] **Pins.** `python3 -I App/Scripts/compute-spki-pins.py api-staging.viadere.io` and compare with `App/Configs/Staging.xcconfig`
      (the committed CA pins came from the old host's Cloudflare chain; change them only if the CAs differ).
- [ ] **App.** `cd App && xcodegen`, build the Staging scheme, and **delete the app before installing** the new build: staging passkeys were
      bound to the old RP ID (`viadere.cksites.dev`) and stop working, so testers create a new account or passkey.
- [ ] **Apple.** No portal change for development builds: the associated domains (`applinks:`, `webcredentials:`, `appclips:`) come from the
      build setting `VIADERE_WEB_DOMAIN`. The AASA must be served on `staging.viadere.io` (previous step); Apple's CDN may take hours to fetch it.
- [ ] **Retire `cksites.dev`.** After staging works on the new names, delete the old staging records (`viadere`, `viadere-api`, `viadere-api-az`,
      `viadere-assets`, their `_acme-challenge` and `_dmarc` records) and the old edge-token, asset-header and cache rules in the `cksites.dev` zone.
- [ ] **Before `Infra/cloudflare` is ever applied to `viadere.io` for production:** carry the staging rules into it or move staging to its own
      zone (`SECURITY.md` §2.116, residual risk 2).

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
