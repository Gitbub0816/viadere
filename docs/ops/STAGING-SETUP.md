# Staging setup from zero (macOS)

An ordered, copy-paste checklist for the first staging deployment of Viadere: Fly.io (server), Neon (PostgreSQL 18), Cloudflare (DNS, TLS, origin lock), Apple Developer (identifiers, APNs key), MailerSend (SMS and email), and the iOS app's `Staging` build configuration.

Staging uses **production rules** (`ENVIRONMENT=staging`, `Server/Sources/ViadereServerKit/Config/ServerConfig.swift`): every secret is mandatory, https only, the origin lock (`EDGE_TOKEN`) is enforced, `seed` is refused. It shares no secret with production. Non-secret configuration is `Infra/fly/fly.staging.toml`; secret names are `Infra/fly/secrets.txt`; the reference for the Fly side is `Infra/fly/README.md`.

Everything below is run from the repository root (`cd viadere`) unless a step says otherwise.

## 0. Decisions to know about before you start

| Topic | What this guide does | Why / trade-off |
|---|---|---|
| Bundle ID | Staging keeps `com.viadere.app` (and the extensions' IDs). | The server's `APNS_TOPIC`, App Attest app ID (`TEAMID.com.viadere.app`) and the AASA file (`ServerConfig.appBundleID`) are fixed to that ID, so no server change is needed and one App ID in the portal serves both. Cost: a staging build **replaces** a production install on the same phone (same ID), and you cannot have both side by side. A separate `com.viadere.app.staging` would need a server change (the bundle IDs are constants in `ServerConfig.swift`), another App ID, another provisioning set and a second APNs topic, which is not worth it for one product owner. The staging build is labelled "Viadere Staging" on the home screen. |
| Domains | API `viadere-api.cksites.dev` (`PUBLIC_BASE_URL`); web/RP origin `viadere.cksites.dev` (`RP_ID`, `RP_ORIGIN`). | Passkeys, the dashboard (`/dashboard`), the operator console and `/.well-known/apple-app-site-association` must all be served from the RP origin, so `viadere.cksites.dev` must route to the same Fly app as the API host (step 7). |
| Push and App Attest environment | Defaults: APNs `sandbox`, App Attest `development` (matches `fly.staging.toml`). Works for builds you run **from Xcode onto a phone**. | **TestFlight builds are production-signed**: their push tokens belong to the production APNs gateway. For a TestFlight round switch both app and server to production (section 12, step 2). The server drops a token registered for the other environment (`APNSwiftSender`). |
| Links in SMS and QR codes | Known gap: `ViadereCore.domain` is the constant `viadere.com`, and the server builds handoff/account-link URLs and QR enrollment links from it (`APIRoutes.swift`, `ApprovalEnrollmentCode.swift`). | Staging-generated universal links point at `https://viadere.com/...`, not at staging. Passkeys, push, sign-in approvals, the dashboard and API calls are unaffected. Testing SMS handoff links and QR enrollment end to end needs a Core change (make the link host configurable); until then open those flows by hand on the phone. |
| Optional, left disabled | Verify (`VERIFY_ENABLED=false`), Approve v2 (`APPROVE_V2_ENABLED=false`), RCS, Wallet passes, Apple Messages for Business, the audit-head export. | Each has an external gate or provider; the toml already sets them off. The generator still produces `KEY_DIRECTORY_LOG_KEY` so Approve v2 can be switched on later. |

## 1. Install the tools

```bash
# Homebrew: https://brew.sh   (skip if installed)
brew install flyctl xcodegen python@3
xcode-select --install || true
openssl version            # LibreSSL ships with macOS; fine for the pin script
python3 --version          # any current Python 3; only the standard library is used
fly auth login             # you already did this
fly auth whoami
```

You also need Xcode 27.1 (latest stable, `App/project.yml` `xcodeVersion: "2710"`) from the Mac App Store or developer.apple.com.

Not needed: Docker (the image is built on Fly's remote builder), Node.js or PHP (banned by `CLAUDE.md`).

## 2. Apple Developer

1. Enrol at <https://developer.apple.com/programs/> (paid, individual or organisation). Note the **Team ID** (Membership details, 10 characters). Call it `TEAMID`.
2. Certificates, Identifiers & Profiles > **Identifiers** > App Groups > `+` > `group.com.viadere.shared`.
3. Identifiers > App IDs > `+` > App > explicit Bundle ID **`com.viadere.app`**. Capabilities to tick:
   * Push Notifications
   * App Attest
   * Associated Domains
   * App Groups (select `group.com.viadere.shared`)
   * Keychain Sharing (nothing to configure; Xcode manages the groups)
   * AutoFill Credential Provider
   * Time Sensitive Notifications
4. Register the extension and companion IDs the same way (explicit IDs; App Groups on those that use it): `com.viadere.app.NotificationService` (App Groups, Keychain Sharing), `com.viadere.app.NotificationContent`, `com.viadere.app.CredentialProvider` (AutoFill Credential Provider, App Groups, Keychain Sharing), `com.viadere.app.Widgets`, `com.viadere.app.Clip` (App Clip; Associated Domains, App Attest), `com.viadere.app.watchkitapp`. With **Automatically manage signing** (set in step 11) Xcode creates these for you on first build, so you can skip this item unless signing complains.
5. Keys > `+` > name `Viadere APNs` > tick **Apple Push Notifications service (APNs)** > Continue > Register > **Download** `AuthKey_XXXXXXXXXX.p8` (one download only). The 10 characters in the file name are the **Key ID**. Store the file outside the repository (for example `~/secrets/AuthKey_XXXXXXXXXX.p8`); `**/*.p8` is in `Server/Dockerfile.dockerignore`, but do not rely on that.
6. Verify with Wallet (`com.apple.developer.in-app-identity-presentment`) is **not** needed for staging (`App/project.yml` explains why it is absent).

You now have: `TEAMID`, `KEYID`, the `.p8` file.

## 3. Cloudflare account and zone

Staging runs under **`cksites.dev`** until `viadere.com` is registered: the web origin is `viadere.cksites.dev` and the API `viadere-api.cksites.dev`. Both are one level below `cksites.dev`, so the free Universal SSL certificate covers them (a name like `api.viadere.cksites.dev` would need a paid certificate).

1. `cksites.dev` must be an **Active** zone in your Cloudflare account. (If you later move to `viadere.com`, add that zone the same way and swap the names in `fly.staging.toml`, `App/Configs/Staging.xcconfig` and this guide.)
2. The zone holds your other sites too. Everything below uses the `viadere` / `viadere-api` names only, so it cannot touch other records. (`Infra/terraform/cloudflare.tf` is for the managed setup; this guide does the staging pieces by hand in the dashboard.)

## 4. Neon (PostgreSQL 18)

1. Sign up at <https://console.neon.tech>. **Create project**: name `viadere-staging`, **Postgres version 18**, **region AWS US East 1 (N. Virginia)** (`us-east-1`, next to Fly `iad`), database name `viadere`.
2. Open the project's SQL Editor (connected as the default owner role) and create the two logins. Choose two long random passwords (for example `python3 -c "import secrets;print(secrets.token_urlsafe(32))"`), use letters, digits, `-` and `_` only so the URLs need no escaping:

   ```sql
   CREATE ROLE viadere_migrator LOGIN PASSWORD '<migrator password>';
   CREATE ROLE viadere_app      LOGIN PASSWORD '<app password>';
   ALTER DATABASE viadere OWNER TO viadere_migrator;
   GRANT CONNECT ON DATABASE viadere TO viadere_app;
   GRANT ALL ON SCHEMA public TO viadere_migrator;
   ```

   Roles made with SQL get no special Neon group; do not add `viadere_app` to any group. The first deploy's `migrate` (release command) creates the tables as `viadere_migrator` and then grants `viadere_app` DML only, sets default privileges and revokes `CREATE` on `public` (`docs/ops/RUNBOOKS.md`, "Database role bootstrap"). `DATABASE_APP_ROLE = "viadere_app"` is already in `fly.staging.toml`.
3. **Connection details** > Branch `main`, Database `viadere`, switch off **Connection pooling** (you want the **direct** host: no `-pooler` in the hostname; the server uses prepared statements and a release-command role). Build two URLs from the host `ep-xxxxx.us-east-1.aws.neon.tech`:

   ```text
   DATABASE_MIGRATION_URL = postgres://viadere_migrator:<migrator password>@ep-xxxxx.us-east-1.aws.neon.tech/viadere?sslmode=verify-full
   DATABASE_URL           = postgres://viadere_app:<app password>@ep-xxxxx.us-east-1.aws.neon.tech/viadere?sslmode=verify-full
   ```

   `DATABASE_MIGRATION_URL` must start with `postgres://` or `postgresql://` (`OperationsConfig.swift`). Keep both in a password manager.

## 5. MailerSend (SMS)

Staging uses MailerSend for both SMS and email (`SMS_PROVIDER = "mailersend"`, `EMAIL_API_FORMAT = "mailersend"` in `fly.staging.toml`). Twilio stays supported (`SMS_PROVIDER = "twilio"` and the `TWILIO_*` secrets) if you switch back.

1. Sign up at <https://www.mailersend.com>. SMS needs a plan that includes it, and it sends to **US and Canadian numbers only**.
2. **SMS > Phone numbers**: get a number. US toll-free numbers must pass **toll-free verification** before carriers deliver traffic (MailerSend walks you through it; it can take days). Put the number in E.164 (`+1...`) in `fly.staging.toml` as `MAILERSEND_SMS_FROM_NUMBER` (replacing `REPLACE_WITH_MAILERSEND_NUMBER`).
3. **Integrations > API tokens**: create a token for SMS (`MAILERSEND_SMS_API_TOKEN`). Give it SMS access only.
4. Configure the webhooks later, after the first deploy (step 9.6): both secrets come from there.

MailerSend keeps its own STOP list (a recipient who texts STOP is suppressed there too); the server's own opt-out record stays the source of truth.

## 6. MailerSend (email)

1. **Domains > Add domain** > `viadere.cksites.dev`. MailerSend shows DNS records (SPF, DKIM, a return-path CNAME). Add each in Cloudflare DNS > Records exactly as shown, **proxy status DNS only**, then **Verify** until it is green. Do not create a record at the bare name `viadere` other than the CNAME in step 7.
2. **Integrations > API tokens**: create a token with **Email: full access** limited to that domain (`EMAIL_API_KEY`). Use a different token from the SMS one, so either can be revoked alone.
3. `fly.staging.toml` already has `EMAIL_API_URL = "https://api.mailersend.com/v1/email"`, `EMAIL_API_FORMAT = "mailersend"` and `EMAIL_FROM_ADDRESS = "Viadere Staging <no-reply@viadere.cksites.dev>"`. The server needs all three of URL, key and sender, or none (`PlatformConfig.swift`).

The dashboard sign-up emails a 6-digit code through this provider, so email must work before you can create a business (step 10).

## 7. Cloudflare DNS, TLS and the origin lock

Steps 7.1 to 7.3 can be done now. Step 7.4 needs the Fly app from step 8.2, and step 7.5 needs the `EDGE_TOKEN` from step 9.1; come back here at those points.

1. **Certificates at the edge:** both staging hostnames (`viadere-api.cksites.dev`, `viadere.cksites.dev`) are one level below `cksites.dev`, so Cloudflare's free Universal SSL certificate covers them; no paid certificate is needed.
2. **SSL/TLS > Overview > Full (strict)**. Never Flexible or Full.
3. **DNS records** (Cloudflare > DNS > Records), all **Proxied** (orange cloud):

   | Type | Name | Target |
   |---|---|---|
   | CNAME | `viadere-api` | `viadere-server-staging.fly.dev` |
   | CNAME | `viadere` | `viadere-server-staging.fly.dev` |

   Why two: the API host serves the app's REST calls; the **`viadere` host serves the passkey origin, the dashboard and `/.well-known/apple-app-site-association`** (`RP_ORIGIN`, `Web/WebRoutes.swift`). Apple's CDN fetches the AASA file from `https://viadere.cksites.dev/.well-known/apple-app-site-association` and requires a direct `200` with no redirect, so a redirect or a Worker that rewrites it will break associated domains. (Alternative: a Worker or Redirect Rule is allowed only if it proxies the request, still answers `200` on that exact path and keeps the origin token header; the plain proxied CNAME is simpler and what this guide uses.)
4. **Fly certificates** (so Cloudflare's Full (strict) validates the origin). Allocate addresses once, then add both names:

   ```bash
   fly ips allocate-v4 --shared --app viadere-server-staging
   fly ips allocate-v6 --app viadere-server-staging
   fly certs add viadere-api.cksites.dev --app viadere-server-staging
   fly certs add viadere.cksites.dev     --app viadere-server-staging
   fly certs show viadere-api.cksites.dev --app viadere-server-staging
   fly certs show viadere.cksites.dev     --app viadere-server-staging
   ```

   Each `show` prints an `_acme-challenge` CNAME target. Add them in Cloudflare as **DNS only** (grey cloud): `_acme-challenge.viadere-api` and `_acme-challenge.viadere` pointing at the printed `...flydns.net` targets. Repeat `fly certs show` until each says **Ready** (`Infra/fly/README.md` steps 3 to 5 describe the same flow for production).
5. **Edge token header** (the origin lock, `Operations/EdgeLock.swift`): Cloudflare > Rules > **Transform Rules** > **Modify Request Header** > Create rule:
   * Name `viadere staging edge token`
   * Custom filter expression: `(http.host eq "viadere-api.cksites.dev") or (http.host eq "viadere.cksites.dev")`
   * Modify header > **Set static** > Header name `X-Viadere-Edge-Token` > Value = the `EDGE_TOKEN` printed by the generator in step 9.1 (exactly the same text).

   Do this **after** generating the secrets. Without this rule every request through Cloudflare is refused by the server with `421`.
6. Keep WAF **Bot Fight Mode / Super Bot Fight Mode** off or add a skip rule for `/.well-known/apple-app-site-association`: a challenge page is not a `200` AASA file and Apple's fetcher cannot solve it.
7. Optional hardening (production has it through Terraform): minimum TLS 1.2 (SSL/TLS > Edge Certificates > Minimum TLS Version), Always Use HTTPS.

## 8. Fly.io app

1. Fill the placeholders in `Infra/fly/fly.staging.toml` (three lines):

   | Line | Key | Replace with |
   |---|---|---|
   | `APPLE_TEAM_ID = "REPLACE_WITH_TEAM_ID"` | `APPLE_TEAM_ID` | your `TEAMID` (also in the AASA file) |
   | `APNS_KEY_ID = "REPLACE_WITH_KEY_ID"` | `APNS_KEY_ID` | the `.p8` Key ID from step 2.5 |
   | `APNS_TEAM_ID = "REPLACE_WITH_TEAM_ID"` | `APNS_TEAM_ID` | your `TEAMID` |

   ```bash
   grep -n "REPLACE_WITH" Infra/fly/fly.staging.toml     # must print nothing afterwards
   ```

   Everything else in the toml already matches staging (`PUBLIC_BASE_URL`, `RP_ID`, `RP_ORIGIN`, `APP_ATTEST_MODE = "report"`, `APNS_ENVIRONMENT = "sandbox"`, `TRUSTED_PROXY_COUNT = "2"`, ...).
2. Create the app (the name must match `app = "viadere-server-staging"`):

   ```bash
   fly apps create viadere-server-staging
   ```

   (Add `--org <your-org>` if you have more than one organisation: `fly orgs list`.)

## 9. Secrets and the first deploy

### 9.1 Generate the server-owned secrets

```bash
python3 -I Infra/fly/generate_secrets.py --check           # self-check of the generator (prints OK)
python3 -I Infra/fly/generate_secrets.py --env-file ~/viadere-staging-secrets.env
```

The script (`Infra/fly/generate_secrets.py`, standard library only) writes a mode-600 file with `CONNECT_LINK_SIGNING_KEY`, `SERVER_PEPPER`, `DATA_ENCRYPTION_KEY`, `AUDIT_CHAIN_KEY`, `SUBJECT_REF_KEY` (base64url, 32 bytes, all different), `KEY_DIRECTORY_LOG_KEY` (a valid P-256 scalar), `EDGE_TOKEN` and `METRICS_TOKEN` (64 URL-safe characters, 32 to 256 required). Without `--env-file` it prints a ready-made `fly secrets set` command instead. `--check FILE` validates an existing file.

Back up the file's contents in a password manager **before** deleting it: losing `DATA_ENCRYPTION_KEY`, `SERVER_PEPPER` or `AUDIT_CHAIN_KEY` makes staging data unreadable (rebuild the database and regenerate, which is acceptable for staging).

Copy the `EDGE_TOKEN` value into the Cloudflare rule of step 7.5:

```bash
grep '^EDGE_TOKEN=' ~/viadere-staging-secrets.env
```

### 9.2 Set them on Fly

`--stage` stores secrets without restarting machines (there are none yet):

```bash
fly secrets import --app viadere-server-staging --stage < ~/viadere-staging-secrets.env
rm -P ~/viadere-staging-secrets.env            # after the password-manager copy
```

### 9.3 Set the third-party secrets

```bash
fly secrets set --app viadere-server-staging --stage \
  DATABASE_URL='postgres://viadere_app:...@ep-xxxxx.us-east-1.aws.neon.tech/viadere?sslmode=verify-full' \
  DATABASE_MIGRATION_URL='postgres://viadere_migrator:...@ep-xxxxx.us-east-1.aws.neon.tech/viadere?sslmode=verify-full' \
  EMAIL_API_KEY='<MailerSend email token>' \
  MAILERSEND_SMS_API_TOKEN='<MailerSend SMS token>'
fly secrets set --app viadere-server-staging --stage APNS_KEY_P8="$(cat ~/secrets/AuthKey_XXXXXXXXXX.p8)"
fly secrets list --app viadere-server-staging     # names and digests only
```

The set the server requires in staging: `DATABASE_URL`, `CONNECT_LINK_SIGNING_KEY`, `SERVER_PEPPER`, `DATA_ENCRYPTION_KEY`, `AUDIT_CHAIN_KEY`, `SUBJECT_REF_KEY`, `EDGE_TOKEN`, `APNS_KEY_P8` (+ `APNS_KEY_ID`/`APNS_TEAM_ID` from the toml), the SMS provider's values (MailerSend: `MAILERSEND_SMS_API_TOKEN`, `MAILERSEND_SMS_INBOUND_SECRET`, `MAILERSEND_SMS_WEBHOOK_SECRET` + `MAILERSEND_SMS_FROM_NUMBER` from the toml; Twilio: `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN` + `TWILIO_FROM_NUMBER`), and `EMAIL_API_URL` + `EMAIL_API_KEY` + `EMAIL_FROM_ADDRESS`. `DATABASE_MIGRATION_URL` is needed by the release command; `METRICS_TOKEN` and `KEY_DIRECTORY_LOG_KEY` are optional here.

Leave unset: `RCS_*`, `PASS_*`, `DIDIT_*`, `WALLET_*`, the audit-export values, every `*_PREVIOUS` (rotation only, `docs/ops/KEY-ROTATION.md`).

### 9.4 First deploy from the laptop (staging only)

Production deploys come from CI only (`.github/workflows/release.yml`, signed image by digest); this one-off laptop deploy is for staging. flyctl builds the image on Fly's **remote builder** (no Docker needed):

```bash
fly deploy --config Infra/fly/fly.staging.toml --dockerfile Server/Dockerfile --remote-only
```

Flags checked against <https://docs.fly.io/flyctl/deploy> (`-c/--config`, `--dockerfile`, `--remote-only`; `--app` is optional because the toml names the app). Run it from the repository root: `Server/Dockerfile` copies `Packages/ViadereCore` and `Server/...`, so the build context must be the root. The first build takes 10 to 20 minutes (Swift release build). The release command `migrate --yes --env production` runs on a temporary machine first; if it fails the deploy aborts (read its log in the output).

If flyctl reports `COPY Packages/ViadereCore: not found`, the context was the wrong directory; run from the root with a temporary root-level copy of the config instead, and delete it afterwards:

```bash
cp Infra/fly/fly.staging.toml fly.toml
fly deploy --dockerfile Server/Dockerfile --remote-only
rm fly.toml
```

Afterwards:

```bash
fly status --app viadere-server-staging
fly logs   --app viadere-server-staging        # JSON, secrets redacted
```

### 9.5 Verify

```bash
curl -i  https://viadere-api.cksites.dev/healthz          # 200 {"status":"ok"}
curl -i  https://viadere-api.cksites.dev/readyz           # 200 (database answers); 503 = database problem
curl -si https://viadere.cksites.dev/.well-known/apple-app-site-association | head -20   # 200, application/json, no redirect, body lists TEAMID.com.viadere.app
curl -si -o /dev/null -w '%{http_code}\n' https://viadere-server-staging.fly.dev/v1/directory/search?q=a   # 421: origin lock works
```

Expected: `healthz`/`readyz` 200 through Cloudflare (the Transform Rule adds the token). The direct `*.fly.dev` call must **not** succeed: the server answers **421 (Misdirected Request)** because the token is missing (`Operations/EdgeLock.swift`; not 403). Fly's own health checks are exempt only from Fly's private network. If the Cloudflare call returns 421, the rule or the `EDGE_TOKEN` value is wrong (step 7.5).

Client IP check (`TRUSTED_PROXY_COUNT = "2"`): see `Infra/fly/README.md` step 8.

### 9.6 MailerSend SMS webhooks (required: both secrets are mandatory)

The server refuses to start without the two secrets, so do this right after creating the app's certificates (the URLs only need to exist when MailerSend first sends to them):

1. **SMS > Inbound routing > Add route**: your number, forward URL `https://viadere-api.cksites.dev/v1/providers/sms/inbound`, no filter, enabled. Copy the route's **secret** into `MAILERSEND_SMS_INBOUND_SECRET`.
2. **SMS > Webhooks > Add webhook**: URL `https://viadere-api.cksites.dev/v1/providers/sms/status`, events `sms.sent`, `sms.delivered`, `sms.failed`. Copy its **signing secret** into `MAILERSEND_SMS_WEBHOOK_SECRET`.
3. ```bash
   fly secrets set --app viadere-server-staging --stage MAILERSEND_SMS_INBOUND_SECRET='...' MAILERSEND_SMS_WEBHOOK_SECRET='...'
   ```

Every request is checked against its own route's secret (`Signature` = hex HMAC-SHA256 of the raw body), and unsigned requests are refused. MailerSend's "send test" button signs with a public test secret, so a test call is **expected** to get `403`. MailerSend does not document the inbound forward's payload or signing in detail: if real replies are refused, `fly logs` shows `gateway.webhook_rejected`. Tell the developer then; do not loosen the check.

## 10. Create test data (no `seed` in staging)

`ViadereServer seed` is refused when `ENVIRONMENT=staging` (it is a production-rule environment: `fly ssh console -C "/app/ViadereServer seed"` fails). There is deliberately no staging bypass. Use the real flow, which needs working email:

1. **Operator** (you, once). The machine holds the secrets; run:

   ```bash
   fly ssh console --app viadere-server-staging -C "/app/ViadereServer create-operator --email you@example.com --name 'Your Name' --env production"
   ```

   It prints a one-time link (1 hour) such as `https://viadere-api.cksites.dev/operator/enroll/<token>`. **Replace the host with `https://viadere.cksites.dev`** before opening it: the passkey is bound to `RP_ORIGIN` (`https://viadere.cksites.dev`), and the server checks that origin (`DashboardSessions.swift`). Create the passkey (Touch ID / iCloud Keychain).
2. **Business sign-up.** Open `https://viadere.cksites.dev/dashboard/signup`, register with an email you control and a passkey, enter the 6-digit code that arrives by email, then sign in at `/dashboard/login`. This creates a pending organisation and application.
3. **Verify the business.** Open `https://viadere.cksites.dev/operator/login`, sign in, open the application under `/operator`, and verify it (this issues the handle and permanent code).
4. **API key.** In the dashboard create an API key (a `vdk_test_...` sandbox key if offered) and a webhook endpoint if needed (webhook ownership verification is `required`: the endpoint must answer the challenge with the HMAC proof, see BUSINESS-INTEGRATION 3a; `ALLOW_INSECURE_WEBHOOKS=false`, so https only).
5. Connect the phone app to the business with its code or `/c/<code>` page, then send an interaction from the dashboard or with `POST /v1/business/interactions` (`Server/README.md`).

If the emailed code never arrives: MailerSend > Activity, then `fly logs`.

## 11. The iOS app (Staging configuration)

Hardware matters: App Attest, the Secure Enclave and passkeys need a **real iPhone** (iOS 17 or later). The simulator cannot enrol a Release-grade build (`AppAttestError.unsupported`).

1. Generate the project:

   ```bash
   cd App
   cp Configs/Local.xcconfig.example Configs/Local.xcconfig     # git-ignored
   # edit Configs/Local.xcconfig: DEVELOPMENT_TEAM = TEAMID
   xcodegen
   open Viadere.xcodeproj
   ```

2. **Pins.** Configs/Staging.xcconfig holds placeholders and the build **fails** until they are real (`App/Scripts/check-release-pins.sh` runs for the `Staging` configuration of the app and the clip, and the app would fail closed at runtime anyway). Compute them once Cloudflare serves the host (step 7 done):

   ```bash
   python3 -I App/Scripts/compute-spki-pins.py viadere-api.cksites.dev
   ```

   It prints the SPKI SHA-256 (base64) of every certificate in the chain, using exactly the pipeline `openssl s_client ... | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`. Cloudflare renews its edge certificate regularly and can switch CA, so pin the **issuing CA (intermediate)**, not the leaf: choose a CA entry (`[1]`) as `VIADERE_PIN_PRIMARY`, and a different key as `VIADERE_PIN_BACKUP`: the other CA Cloudflare may use (for example run the script on another Cloudflare-fronted host, which may be served by a different CA, and take its CA pin), or the root, or the next intermediate. The app accepts any certificate in the (system-validated) chain that matches any pin (`PinEvaluator`). Edit both lines in `App/Configs/Staging.xcconfig` and commit them (pins are public). If a pin contains two consecutive slashes, write one as `$()`.

   Why the leaf is risky: if a rotation puts a new leaf key in front of testers who are on an older build, the app cannot connect.
3. Select the **Staging** scheme (Product > Scheme), target `Viadere`, your iPhone. Signing & Capabilities: choose your Team; Xcode registers the missing IDs and profiles. Run. The app is named "Viadere Staging", uses `https://viadere-api.cksites.dev`, relying party `viadere.cksites.dev`, associated domains `applinks:`, `webcredentials:`, `appclips:viadere.cksites.dev`, APNs sandbox, App Attest `development` (all from `Configs/Staging.xcconfig` and `project.yml`).
4. Associated domains for development-signed builds: iOS fetches the AASA file through Apple's CDN, which caches it (hours). If passkey creation fails with an "application is not associated with domain" error right after the first deploy, wait, or check the file with the `curl` of step 9.5 and reinstall the app once it is correct. (On a development-signed build, Settings > Developer > Associated Domains Development makes the phone fetch the file directly, together with the `?mode=developer` suffix on the entitlement entries.)
5. First run: create an account (passkey), enrol the device. In `APP_ATTEST_MODE=report`, a failed attestation is recorded as `unattested` but allowed; flip the server to `require` once enrolments show `attested` (`Infra/fly/README.md`, round 4).

## 12. TestFlight

1. App Store Connect > Apps > `+` > New App: platform iOS, name Viadere, bundle ID `com.viadere.app`, SKU `viadere`. Complete Users and Access (add testers) and the TestFlight Test Information fields. App Clip experiences are optional for staging.
2. **Switch the environment pair** (section 0): TestFlight tokens are production tokens. In `App/Configs/Local.xcconfig` add:

   ```text
   VIADERE_STAGING_APNS_ENVIRONMENT = production
   VIADERE_STAGING_APS_ENVIRONMENT = production
   VIADERE_STAGING_APP_ATTEST_ENVIRONMENT = production
   ```

   and on the server set `APNS_ENVIRONMENT = "production"` and `APP_ATTEST_ENVIRONMENT = "production"` in `Infra/fly/fly.staging.toml`, then `fly deploy` again (step 9.4). The same `.p8` key works for both gateways. From then on Xcode-run builds on a phone will not receive pushes (they are sandbox); switch back for local debugging. Keep `APP_ATTEST_MODE = "report"` while you confirm TestFlight attestations validate.
3. Build number: raise `CURRENT_PROJECT_VERSION` in `App/Configs/Shared.xcconfig` for every upload.
4. `xcodegen`, open the project, scheme **Staging**, destination **Any iOS Device (arm64)**, Product > **Archive**. The pin check runs here and stops the archive if the pins are placeholders.
5. Organizer > Distribute App > App Store Connect > Upload. Wait for processing (email), answer the export-compliance question (the app declares `ITSAppUsesNonExemptEncryption = false`), add the build to an internal testing group.
6. Install through the TestFlight app on the phone.

## 13. Deploy the website to a throwaway Cloudflare Worker behind Access

The marketing site (`Site/`, ADR-04) deploys to Workers Static Assets. For a first test use a throwaway Worker name so nothing touches the real one, and protect it with Cloudflare Access.

1. Build:

   ```bash
   cd Site && swift build && swift run viadere-site          # writes Site/dist
   swift run viadere-site lint --dist dist
   cd ..
   ```

2. API token: Cloudflare > My Profile > API Tokens > Create Token > Custom > permission **Account > Workers Scripts > Edit** (nothing else). Account ID: dashboard right column.
3. Deploy (the script never prints the token):

   ```bash
   export CLOUDFLARE_API_TOKEN=...
   export CLOUDFLARE_ACCOUNT_ID=...
   python3 -I Site/deploy/upload.py --dist Site/dist --script viadere-site-staging-test --dry-run
   python3 -I Site/deploy/upload.py --dist Site/dist --script viadere-site-staging-test
   ```

   `Site/deploy/upload.py` is unverified against a live account (its docstring says so): run `--dry-run` first and expect to read its error output if Cloudflare rejects a request.
4. Workers & Pages > `viadere-site-staging-test` > Settings > Domains & Routes: enable the **workers.dev** route (do not attach a custom domain). Then in the same card, **Enable Cloudflare Access** for the workers.dev URL, or create an Access application (Zero Trust > Access > Applications > Add > Self-hosted) for `viadere-site-staging-test.<subdomain>.workers.dev` with a policy **Allow** > Emails > your address. Open the URL in a private window to confirm the login wall appears before any page.
5. Delete the Worker when done (Settings > Delete).

## 14. Optional features left disabled

| Feature | Switch (already off in `fly.staging.toml`) | Enable only with |
|---|---|---|
| Verify (ID/age checks) | `VERIFY_ENABLED = "false"` | Phase 3 legal and privacy gate, Didit credentials, `WALLET_*`, `docs/ops/KILL-SWITCHES.md` |
| Approve v2 | `APPROVE_V2_ENABLED = "false"` | independent assessment; `KEY_DIRECTORY_LOG_KEY` (generated) and `VIADERE_KEY_DIRECTORY_LOG_KEYS` in the app build (`ViadereServer key-directory-log-key` prints the public key) |
| RCS | `RCS_PROVIDER_BASE_URL = ""` | all four of `RCS_PROVIDER_BASE_URL`, `RCS_AGENT_ID`, `RCS_PROVIDER_TOKEN`, `RCS_WEBHOOK_SECRET` or none |
| Wallet passes | `PASS_TYPE_IDENTIFIER = ""` | the three `PASS_*_PEM` secrets with the identifier |
| Audit-head export | `AUDIT_HEAD_EXPORT = ""` | `Infra/terraform/audit_bucket.tf`; not needed for staging |
| Metrics scrape | `METRICS_TOKEN` set, no scraper | `Infra/fly/README.md` 1b |

## 15. Troubleshooting: startup errors

The server prints `Startup failed: <error>` and exits (`Server/Sources/ViadereServer/main.swift`); read it with `fly logs --app viadere-server-staging`. Messages come from `Server/Sources/ViadereServerKit/Config/*.swift` and never contain values.

| Message | Cause and fix |
|---|---|
| `Missing required configuration: ENVIRONMENT (...)` / `Invalid configuration: ENVIRONMENT (...)` | `[env] ENVIRONMENT` is absent or misspelled; it must be `staging` in `fly.staging.toml`. |
| `Missing required configuration: DATABASE_URL` | Secret not set (step 9.3). |
| `Missing required configuration: CONNECT_LINK_SIGNING_KEY` / `SERVER_PEPPER` / `DATA_ENCRYPTION_KEY` / `AUDIT_CHAIN_KEY` / `SUBJECT_REF_KEY` | Secret not set. Run step 9.1 and 9.2. |
| `Invalid configuration: X (base64url, at least 32 bytes)` | Value is not base64url or is too short, typically truncated while pasting. Regenerate it, or `python3 -I Infra/fly/generate_secrets.py --check file.env`. |
| `Invalid configuration: A and B must be different values` | Two of the five keys are equal. Regenerate one. |
| `Missing required configuration: EDGE_TOKEN` | Secret not set. `Invalid configuration: EDGE_TOKEN (at least 32 printable characters, no spaces)`: re-copy; no spaces or quotes. |
| `Missing required configuration: APNS_KEY_P8 or APNS_KEY_PATH` | `.p8` secret missing (step 9.3). |
| `Missing required configuration: APNS_KEY_ID / APNS_TEAM_ID` | A `REPLACE_WITH_*` placeholder was removed or the keys are empty in the toml (step 8.1). |
| `Missing required configuration: APPLE_TEAM_ID` | Empty `APPLE_TEAM_ID` in the toml. |
| `Missing required configuration: MAILERSEND_SMS_...` | That MailerSend secret is not set (step 9.3 or 9.6). `Invalid configuration: MAILERSEND_SMS_FROM_NUMBER (E.164)`: the toml still has the placeholder. `... (at least 16 characters, different values)`: a secret was pasted wrong. |
| `Missing required configuration: TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN (or SMS_PROVIDER=mailersend)` | `SMS_PROVIDER` is missing from the toml (it defaults to Twilio). |
| `Missing required configuration: EMAIL_API_URL / EMAIL_API_KEY / EMAIL_FROM_ADDRESS` | None of the three set. `... (all three or none)`: one is missing (usually `EMAIL_API_KEY`). `Invalid configuration: EMAIL_API_URL (https required)`. |
| `Invalid configuration: RP_ORIGIN (must be an https origin of RP_ID outside development)` | `RP_ORIGIN` host must equal or be a subdomain of `RP_ID`. Staging: `https://viadere.cksites.dev` and `viadere.cksites.dev`. |
| `Invalid configuration: PUBLIC_BASE_URL (must be https in production)` | Fix the toml value. |
| `Invalid configuration: DATABASE_MIGRATION_URL (postgres URL)` | URL must start with `postgres://`. |
| Refuses to start because the runtime role can change the schema / owns tables | `DATABASE_URL` is not `viadere_app`, or `viadere_app` has too many rights (step 4.2). `docs/ops/RUNBOOKS.md`, "Database role bootstrap". |
| `Invalid configuration: APP_ATTEST_MODE (off, report or require)` / `APP_ATTEST_ENVIRONMENT (development or production)` | Typo in the toml. |
| `Missing required configuration: KEY_DIRECTORY_LOG_KEY (...)` | Only when `APPROVE_V2_ENABLED=true`. Set the generated value. `Invalid ... (base64url, 32-byte P-256 private scalar)`: regenerate with the script. |
| Release command fails (`migrate`) | Open the release log in the `fly deploy` output. Usual causes: wrong migrator password, `sslmode` host mismatch (use the direct host), Neon compute asleep for a moment (retry). |
| Machine healthy but `https://viadere-api.cksites.dev` returns 421 | Cloudflare rule missing or the token differs from `EDGE_TOKEN` (step 7.5). |
| `525` / `526` from Cloudflare | Fly certificate not **Ready** (step 7.4), or SSL mode is not Full (strict). |
| Browser shows a certificate error for `viadere-api.cksites.dev` | Universal SSL isn't active yet for the zone (it can take up to 24 h after the nameserver switch), or the record isn't proxied (orange cloud). |
| App: "can't connect" / TLS error immediately | Pins wrong or placeholders (`tls.pin.mismatch` in the device log). Recompute (step 11.2). |
| Pushes never arrive | Sandbox/production mismatch between the build (TestFlight vs Xcode) and `APNS_ENVIRONMENT` (section 0), wrong `APNS_KEY_ID`, or the phone's token was registered before the toml was fixed. |
| Passkey: "not associated with domain" | AASA not served by `viadere.cksites.dev` (step 9.5), Apple CDN cache, or the app's team ID differs from `APPLE_TEAM_ID`. |

## Files this guide touches

`Infra/fly/fly.staging.toml` (three placeholders), `Infra/fly/generate_secrets.py`, `App/Configs/Staging.xcconfig` (pins), `App/Configs/Local.xcconfig` (team ID; TestFlight overrides), `App/Scripts/compute-spki-pins.py`, `App/Scripts/check-release-pins.sh`, `App/project.yml`, `Site/deploy/upload.py`.
