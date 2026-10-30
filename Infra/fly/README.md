# Fly.io deployment (ADR-01)

The Vapor server runs on Fly.io machines, always on, behind Cloudflare. Cloudflare owns DNS, TLS policy, the WAF and rate limits
([`../terraform`](../terraform)); Fly owns the machines, the release command and the origin certificate. The database is Neon
(ADR-02), service keys are in Google Cloud KMS (ADR-03).

| File | Purpose |
|---|---|
| `fly.production.toml` | app `viadere-server`: 2+ machines, auto-stop off, `/healthz` + `/readyz` checks, release command `migrate --yes` |
| `fly.staging.toml` | app `viadere-server-staging`: same shape, production rules (`ENVIRONMENT=staging`), 1 machine, sandbox providers |
| `secrets.txt` | the names that must be set with `fly secrets set` |
| `generate_secrets.py` | generates the server-owned secrets in the exact formats the server checks (`python3 -I Infra/fly/generate_secrets.py --check`); staging walk-through: [`docs/ops/STAGING-SETUP.md`](../../docs/ops/STAGING-SETUP.md) |
| `check_env_coverage.py` | CI/dev check: every variable in `Server/.env.example` is a `[env]` key, a secret, or an exempt alias |

## Design notes

* **Always on.** `auto_stop_machines = "off"`, `min_machines_running = 2` in production (two machines in one region at minimum so a
  host failure or a rolling deploy never leaves zero; add a second region later, Neon is the single-region dependency, see
  `docs/ops/RESILIENCE.md`). `max_unavailable = 1` keeps one machine serving during a rolling deploy.
* **Health.** `/healthz` is liveness (process answers; no dependency state). `/readyz` runs one database query and answers `503`
  when it fails, so Fly stops routing to a machine that lost the database. Both answer only `{"status":"ok"}`.
* **Migrations.** `release_command = "migrate --yes --env production"` runs in a temporary machine before the new version starts;
  a non-zero exit aborts the deploy and the old version keeps serving. `AUTO_MIGRATE=false` at runtime so machines never race.
  Write migrations additively (expand, deploy, contract) because old machines run against the new schema during a rolling deploy.
  Caveat: the release machine boots the whole app, so the in-process job loop also starts for the few seconds it lives. The jobs are
  compare-and-swap safe (`Server/README.md`, "Operations notes"), so this is harmless but not ideal.
* **Concurrency.** `type = "requests"`, soft 200 / hard 400 per machine in production (100/200 staging). Past the hard limit the
  Fly proxy stops sending new requests to that machine and queues/503s; tune against load tests.
* **Graceful stop.** `SIGTERM`, 30 s.
* **Deploys come from CI only** (`.github/workflows/release.yml`): the image is built, SBOM'd, signed with cosign, attested, pushed
  to GHCR and deployed **by digest**. Staging deploys first and production requires the `production` environment approval.

## One-time setup

**First staging deployment from a laptop, from zero (accounts, Neon, Cloudflare, secrets, app build): follow [`docs/ops/STAGING-SETUP.md`](../../docs/ops/STAGING-SETUP.md).** The laptop deploy (`fly deploy --config Infra/fly/fly.staging.toml --dockerfile Server/Dockerfile --remote-only`) is for staging only; production deploys go through CI.

```bash
# Install flyctl (a Go binary, no Node): https://fly.io/docs/flyctl/install/   (CI uses a checksum-pinned release)
fly auth login
fly apps create viadere-server-staging --org viadere
fly apps create viadere-server         --org viadere
```

### 1. Secrets

Generate each key independently (`openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`); production values are **distinct** from
staging and from each other (the server refuses duplicates). Never reuse a secret across environments. Store the production
`DATA_ENCRYPTION_KEY`, `SERVER_PEPPER` and `AUDIT_CHAIN_KEY` in the offline escrow described in `docs/ops/RESILIENCE.md`
(losing them makes encrypted columns and OTP/phone hashes unrecoverable).

```bash
fly secrets set --app viadere-server-staging --stage \
  DATABASE_URL='postgres://viadere_app:...@ep-....neon.tech/viadere?sslmode=verify-full' \
  CONNECT_LINK_SIGNING_KEY=... SERVER_PEPPER=... DATA_ENCRYPTION_KEY=... AUDIT_CHAIN_KEY=... \
  EMAIL_API_KEY=... APNS_KEY_P8="$(cat AuthKey_XXXX.p8)" \
  TWILIO_ACCOUNT_SID=... TWILIO_AUTH_TOKEN=... TWILIO_MESSAGING_SERVICE_SID=...
# optional groups (all or none): RCS_PROVIDER_TOKEN + RCS_WEBHOOK_SECRET (with RCS_PROVIDER_BASE_URL/RCS_AGENT_ID in fly.toml);
# PASS_CERTIFICATE_PEM + PASS_PRIVATE_KEY_PEM + PASS_WWDR_CERTIFICATE_PEM (with PASS_TYPE_IDENTIFIER in fly.toml)
fly secrets list --app viadere-server-staging      # names and digests only
```

`--stage` defers the restart to the next deploy. Do not put secrets on a shell history line on a shared machine; use `fly secrets import`
from a file on `tmpfs` and delete it. The full list of names is `secrets.txt`; `python3 -I Infra/fly/check_env_coverage.py` proves
every variable in `Server/.env.example` is covered.

### 1a. Database roles (the release command and the runtime use different logins)

`neon.tf` creates `viadere_migrator` (owns the schema) and `viadere_app` (runtime). Two secrets, two connection strings: `DATABASE_MIGRATION_URL` = the migrator's, read **only** by
`ViadereServer migrate` (the release command); `DATABASE_URL` = `viadere_app`'s, used by every serving machine; `DATABASE_APP_ROLE = "viadere_app"` is a plain `[env]` value. The `migrate` run grants
`viadere_app` SELECT/INSERT/UPDATE/DELETE on all tables and sequence usage, sets default privileges for tables later migrations create, revokes `CREATE` on schema `public` and `UPDATE` on `audit_events`.
In staging and production the split is **mandatory** (platform gate C1): `ViadereServer migrate` refuses to run without `DATABASE_MIGRATION_URL` (it never falls back to the runtime login), and every serving
process checks at startup that its own login cannot change the schema (`CREATE` on `public`, or owning tables) and refuses to start if it can, whether or not it holds the migration URL.

**Keep the migrator's secret off the serving machines.** Fly secrets are app-wide, and a `release_command` runs with the serving app's secrets, so the single-app layout leaves `DATABASE_MIGRATION_URL` in every
serving machine's environment (the server reads it only in `migrate`, but a code-execution compromise of a serving machine could read it). The hardened layout, which staging and production should move to:

1. Create a second app per environment that never serves traffic (`viadere-migrate-staging`, `viadere-migrate`; no `[http_service]`, no public IP). It holds `DATABASE_MIGRATION_URL` plus the configuration the server needs to
   start in strict mode (`migrate` loads the full configuration; import the same secrets and use the same `[env]` values as the serving app). Only the release workflow's deploy token can run machines in it.
2. The release workflow pushes the same image digest to that app's registry and runs the migration there before it deploys the serving app: `fly machine run registry.fly.io/<release app>@<digest> migrate --yes --env production --app <release app> --rm`
   (wait for exit code 0; a non-zero exit stops the release and the old version keeps serving).
3. On the serving app: delete `release_command` from the toml and run `fly secrets unset DATABASE_MIGRATION_URL --app <serving app>`. The serving app now holds `DATABASE_URL` (the `viadere_app` login) only.

Until step 3 is done for an app, the migration URL is present in its serving machines and the residual risk in docs/SECURITY.md (2.80 item 4) stands. Rotate the migrator's password (Neon) after any suspected host compromise. Recovery from a mistaken single-role deployment: set both URLs,
run the release; the startup check names the variable that is wrong.

### 1b. Metrics, audit export

`METRICS_TOKEN` protects `GET /metrics` (counters and gauges, no personal data; add the header `Authorization: Bearer <token>` in the scraper; the edge token is required as for everything else, so scrape through
Cloudflare or set `METRICS_PORT` and scrape the machine's private 6PN address: the internal listener binds to `FLY_PRIVATE_IP` when Fly sets it, else to loopback, never to `0.0.0.0`, and it requires the same bearer token; the server refuses to start with `METRICS_PORT` and no `METRICS_TOKEN`). **Production refuses to start without `AUDIT_HEAD_EXPORT` and `AUDIT_HEAD_KMS_KEY`** (platform gate C2; staging may omit them). `AUDIT_HEAD_EXPORT=gcs` with `AUDIT_HEAD_EXPORT_TARGET=$(tofu output -raw audit_head_bucket)`, `AUDIT_HEAD_KMS_KEY=<audit_head_kms_key output>/cryptoKeyVersions/1`
and the three `GCP_*` workload-identity values writes a signed head every `AUDIT_HEAD_EXPORT_INTERVAL_HOURS` to the locked bucket (`Infra/terraform/audit_bucket.tf`); `AUDIT_HEAD_EXPORT=r2` is the Cloudflare
alternative (bucket with Object Lock, `AUDIT_HEAD_EXPORT_ENDPOINT=https://<account>.r2.cloudflarestorage.com`, an access key limited to PutObject on that bucket). Alert when `viadere_audit_head_export_age_seconds` exceeds twice the interval.

### 2. First deploy (staging, then production)

```bash
flyctl deploy --app viadere-server-staging --config Infra/fly/fly.staging.toml --image ghcr.io/<org>/viadere-server@sha256:<digest>
fly status --app viadere-server-staging
curl -fsS https://viadere-server-staging.fly.dev/readyz     # while the Fly hostname is still open (see step 6)
```

## Cloudflare in front of Fly (exact steps)

Terraform creates the Cloudflare side (`Infra/terraform/cloudflare.tf`); the numbered steps below are the Fly side plus the
verification. Hostnames: `api.viadere.com` is the origin hostname served by Fly (staging: `api-staging.viadere.com`).

3. **Allocate addresses and a certificate on Fly** (Fly issues a Let's Encrypt certificate and validates by DNS-01, which works while
   the record is proxied):
   ```bash
   fly ips allocate-v4 --shared --app viadere-server      # or a dedicated v4 if you need a stable address
   fly ips allocate-v6 --app viadere-server
   fly certs add api.viadere.com --app viadere-server
   fly certs show api.viadere.com --app viadere-server     # prints the _acme-challenge CNAME target
   ```
4. **DNS.** Terraform's `cloudflare_dns_record.api` is a **proxied** `CNAME api -> viadere-server.fly.dev`
   (variable `fly_origin_hostname`); add the `_acme-challenge.api` CNAME printed by `fly certs show` as an **unproxied** record
   (variable `fly_acme_challenge_cname`). Re-run `fly certs show` until it says *Ready*.
5. **SSL/TLS mode = Full (strict)** (Terraform: `cloudflare_zone_setting.ssl = strict`). Cloudflare then verifies Fly's certificate
   for `api.viadere.com`; never use Flexible or Full (non-strict).
6. **Lock the origin to Cloudflare.** The Fly app is reachable at `*.fly.dev` and by IP, so the proxy being in front proves nothing
   unless the origin refuses everyone else. Layered controls, strongest last:
   1. *Shared header (set at Cloudflare, **enforced by the server**, gap G-10 closed).* A Cloudflare Transform Rule sets
      `X-Viadere-Edge-Token: <random>` on every request to the API hostnames (`cloudflare_ruleset.origin_edge_token`, value from the
      sensitive variable `edge_token`). The server answers `421` to any request that lacks it or whose value is not equal, in constant
      time, to Fly secret `EDGE_TOKEN` (or `EDGE_TOKEN_PREVIOUS`), **before routing, authentication or any database access**, and
      refuses to boot in staging or production without `EDGE_TOKEN`. *Health-check rule:* `GET`/`HEAD` of `/healthz` and `/readyz`
      are exempt **only** when the TCP peer is on Fly's private network (`fdaa::/16`, `172.16.0.0/12`, `10.0.0.0/8`, loopback) **and**
      the request carries no proxy header (`X-Forwarded-For`, `Forwarded`, `Fly-Client-IP`, `CF-*`, `X-Real-IP`, `True-Client-IP`, `Via`);
      Fly's checker adds none of them (the `[[http_service.checks]]` block sends only `X-Forwarded-Proto`), Cloudflare and Fly's proxy
      always add some, so a public request can never use the exemption. Do not add a proxy header to the checks.
      *Rotation:* set the new value as `EDGE_TOKEN` and the old one as `EDGE_TOKEN_PREVIOUS` (`fly secrets set` restarts machines
      one at a time), apply the new `edge_token` in Terraform, then remove `EDGE_TOKEN_PREVIOUS`. *Verify after deploy:*
      `curl -s -o /dev/null -w '%{http_code}\n' https://viadere-server.fly.dev/v1/directory/search?q=a` must print `421` (the Fly hostname
      reaches the origin without the token), and the same call through `https://api.viadere.com` must print `200`.
   2. *Authenticated Origin Pulls (mTLS Cloudflare -> origin).* Terraform enables zone-level AOP
      (`cloudflare_authenticated_origin_pulls_settings`) so Cloudflare presents a client certificate to the origin. **The Fly
      proxy does not verify client certificates** (its `http_service` supports only ALPN/TLS-version options), so to enforce it
      the origin must terminate TLS itself: expose a raw TCP service (`[[services]]` with `handlers = []` on port 443, no `tls`
      handler), serve the Let's Encrypt/Cloudflare Origin CA certificate from the server and configure NIO-SSL with
      `certificateVerification = .noHostnameVerification` and Cloudflare's origin-pull CA as the only trust root. That needs a
      Server change (gap G-11, still open: it needs a platform decision) and gives up Fly's HTTP-layer features (checks stay TCP/`/healthz` over the app's own TLS).
      The alternative that needs no server change is **Cloudflare Tunnel**: run `cloudflared` (Go) as a second process group,
      remove the public `[http_service]` and let Cloudflare reach the app over Fly's private network. Pick one in the next
      architecture review; this repo ships the Terraform for AOP and the header, and the fly.toml for the Fly-proxied variant.
   3. *Stop using the public Fly hostname for traffic.* After the certificate is *Ready*, nothing should call
      `viadere-server.fly.dev`; alert on requests whose `Host` is not `api.viadere.com` (log line, once the middleware exists).
7. **Authenticated Origin Pulls certificate.** Zone-level AOP uses Cloudflare's shared certificate (anyone using Cloudflare can
   present it, so it only proves "some Cloudflare tenant"; the shared header is what ties the request to *our* zone). For a
   per-zone certificate upload your own client certificate with `cloudflare_authenticated_origin_pulls_certificate`
   (variables `aop_client_certificate`, `aop_client_private_key`; commented example in `cloudflare.tf`).
8. **Client IP.** Traffic is client -> Cloudflare -> Fly proxy -> app, so `X-Forwarded-For` ends with `<client>, <cloudflare edge>`
   and `TRUSTED_PROXY_COUNT = "2"` selects the client. Verify on staging before production (a wrong value makes every client share
   one rate-limit bucket, or lets a client choose its own IP):
   ```bash
   curl -s https://api-staging.viadere.com/v1/<any rate-limited route> -H 'X-Forwarded-For: 203.0.113.9' -i   # spoofed hop
   fly logs --app viadere-server-staging | grep -m1 'ip='    # the resolved address must be YOUR address, not 203.0.113.9 and not a Cloudflare range
   ```
9. **Cache and compression.** The API is dynamic: Terraform adds a cache-bypass rule for `api.viadere.com` (`cloudflare_ruleset.api_cache_bypass`);
   only `/connect-button/v1/*` and `/.well-known/*` may be cached (they are immutable/public).
10. **Smoke tests** after any change: `curl -sI https://api.viadere.com/healthz` (200, `strict-transport-security`, `cf-ray`),
    `curl -sI http://api.viadere.com/` (301 to https), `openssl s_client -tls1_1 ...` (handshake refused),
    `curl --tlsv1.2 --tls-max 1.2 https://api.viadere.com/healthz` (works only while the 1.2 compatibility policy is on).

## Routine operations

```bash
fly status --app viadere-server                # machines and check state
fly logs --app viadere-server                  # JSON logs, tokens/secrets/phones are redacted by the server
fly scale count 3 --region iad --app viadere-server
fly ssh console --app viadere-server -C "/app/ViadereServer audit-head"    # see docs/ops/RUNBOOKS.md for command use
fly releases --app viadere-server              # roll back with: flyctl deploy --image <previous digest> (migrations are forward-only)
fly secrets set --app viadere-server NAME=...  # restarts machines one by one
```

## Environment variable coverage

`python3 -I Infra/fly/check_env_coverage.py` is authoritative. Summary of the mapping:

* **Secrets (`fly secrets`)**: `DATABASE_URL`, `CONNECT_LINK_SIGNING_KEY`, `SERVER_PEPPER`, `DATA_ENCRYPTION_KEY`, `AUDIT_CHAIN_KEY`,
  `SUBJECT_REF_KEY`, `KEY_DIRECTORY_LOG_KEY` (Approve v2 transparency-log signing key), `LINK_DESCRIPTOR_SIGNING_KEY` (link-session descriptor and result signing key, WP-C1; `KEY_DIRECTORY_LOG_ID` and `APPROVE_V2_ENABLED` are plain `[env]`),
  `EMAIL_API_KEY`, `APNS_KEY_P8`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` / `TWILIO_MESSAGING_SERVICE_SID`,
  `RCS_PROVIDER_TOKEN`, `RCS_WEBHOOK_SECRET`, `PASS_CERTIFICATE_PEM`, `PASS_PRIVATE_KEY_PEM`, `PASS_WWDR_CERTIFICATE_PEM`,
  `EMAIL_API_AUTH_*` (only for providers that need them), `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` (upgrade only).
  WP6: `EDGE_TOKEN`, `EDGE_TOKEN_PREVIOUS`, `METRICS_TOKEN`, `DATABASE_MIGRATION_URL`, the rotation lists `DATA_ENCRYPTION_KEYS_PREVIOUS`, `SERVER_PEPPERS_PREVIOUS`, `AUDIT_CHAIN_KEYS_PREVIOUS`, `CONNECT_LINK_SIGNING_KEYS_PREVIOUS` (only during a rotation, `docs/ops/KEY-ROTATION.md`) and `AUDIT_HEAD_EXPORT_ACCESS_KEY_ID` / `AUDIT_HEAD_EXPORT_SECRET_ACCESS_KEY` (only for the R2 export). Their plain companions (`DATA_ENCRYPTION_KEY_ID`, `SERVER_PEPPER_ID`, `AUDIT_CHAIN_KEY_EPOCH`, `CONNECT_LINK_SIGNING_KEY_ID`, `DATABASE_APP_ROLE`, `AUDIT_HEAD_EXPORT*`, `GCP_*`, `WEBHOOK_OWNERSHIP_VERIFICATION`, ...) are `[env]` values.
* **Plain `[env]`**: everything else in `.env.example` (URLs, RP identifiers, Apple identifiers, App Attest, APNs ids/topic,
  retention, abuse, billing, limits, rate-limit store, proxy count, dashboard timeouts).
* **Exempt**: `POSTGRES_PASSWORD` (docker-compose only) and the `*_PATH` aliases (`APNS_KEY_PATH`, `PASS_*_PATH`): Fly has no mounted
  secret files, so use the inline `APNS_KEY_P8` and `PASS_*_PEM` secrets.
* `RATE_LIMIT_STORE=database` and `AUTO_MIGRATE=false` are set explicitly; `ENVIRONMENT` is set per app (`production` / `staging`).
* `EDGE_TOKEN` (origin shared header) is **required** in staging and production (gap G-10 closed); `EDGE_TOKEN_PREVIOUS` only during a rotation.
* The placeholders `REPLACE_WITH_*` in `fly.*.toml` (`APPLE_TEAM_ID`, `APNS_KEY_ID`, `APNS_TEAM_ID`) must be replaced before the
  first deploy; they are identifiers, not secrets.
