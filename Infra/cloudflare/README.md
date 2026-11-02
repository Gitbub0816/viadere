# Cloudflare as code (ADR-0009, ADR-0029)

OpenTofu root for the Cloudflare edge. It was split out of the retired `Infra/terraform` root (which also held Neon, Google Cloud KMS
and the Fly origin; ADR-0029) and starts with a **fresh state** in the Azure state account (`backend.tf`, key
`viadere/cloudflare/<env>.tfstate`, Entra authentication). Existing Cloudflare resources are **imported**, never recreated.

| File | Manages |
|---|---|
| `cloudflare.tf` | zone TLS settings, HSTS, DNSSEC, CAA, DNS (apex, www, api, status), WAF managed rules, edge rate limits, Authenticated Origin Pulls, the origin headers (edge token, verified client-certificate headers), the Tier E mTLS hostname (`enable_mtls`), site hostnames |
| `cloudflare_tunnel.tf` | the remotely managed Cloudflare Tunnel to `ca-viadere-api` (the only origin) |
| `versions.tf`, `backend.tf` | provider pin (`cloudflare/cloudflare` 5.28.1), Azure Storage backend |

`add_asset_host.py` and `point_staging_to_azure.py` are the owner-run helpers that were used for the staging cutover; they stay as a
record and do not need Terraform.

## The authority has no Cloudflare route

The private authority (`Infra/azure-authority`, ADR-0019) has no tunnel route, no hostname and no DNS record here. `policy_check.py
--source` fails when any file in this directory names it (rule `AUTH-NO-PUBLIC-INGRESS`). The `id.` host's static JWKS and discovery
files are deployed by `authority-publish.yml` with its own Cloudflare token (ADR-0024 section 7); the token of this root carries no
scope for them.

## Use

```bash
cd Infra/cloudflare
cp terraform.tfvars.example terraform.tfvars          # fill in ids; gitignored
export CLOUDFLARE_API_TOKEN=...                        # CI: from a protected environment
export TF_VAR_edge_token="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
cp backend.example.hcl backend.staging.hcl            # fill in; gitignored
tofu init -backend-config=backend.staging.hcl
tofu plan -out plan.tfplan                            # read-only first: a human reviews it, nothing is applied before the imports
```

Import before the first apply: `tofu import` each existing resource the plan wants to create (zone settings, DNS records, the tunnel,
the rulesets). Run `tofu plan` again until it shows no creation of something that already exists. The edge token value in the existing
Transform Rule is read from Cloudflare by `point_staging_to_azure.py` and never printed; set `TF_VAR_edge_token` to the same value (or
rotate it with the `EDGE_TOKEN` / `EDGE_TOKEN_PREVIOUS` overlap, `docs/ops/KEY-ROTATION.md`).

Staging and production are separate states with their own tfvars, their own zone or child zone and their own tunnel.

## Notes

* **Zones are created out of band** (registrar delegation is a manual, reviewed step); the module takes `cloudflare_zone_id`.
* **TLS (SEC-TR-001).** `tls_1_3 = on`, `min_tls_version = 1.2` under the compatibility policy in
  `docs/ops/TLS-COMPATIBILITY-POLICY.md`, TLS 1.2 limited to six ECDHE + AEAD suites, SSL 3/TLS 1.0/1.1 refused, HSTS with
  `includeSubDomains` (preload off until reviewed), Always Use HTTPS, SSL mode Full (strict).
* **Rate limits.** Six edge rules as a coarse first layer. Cloudflare rate-limit features depend on the plan; if `tofu apply` rejects a rule
  on a lower plan, upgrade the plan rather than dropping the rule. Precise limits stay in the server (`docs/SECURITY.md` section 2.23).
* **WAF.** Managed ruleset ids are variables (plan dependent).
* **Site.** Workers Static Assets scripts are uploaded by `Site/deploy/upload.py` (ADR-0004), so the script is not a resource here. This
  root only binds the apex and `www` hostnames (`manage_site_custom_domain = true`) after the script exists.
* **Origin headers.** `cloudflare_ruleset.origin_edge_token` sets `X-Viadere-Edge-Token` and overwrites the verified client-certificate
  headers on every API host, which is what makes the server's trust in them sound. The tunnel token is never read into state: the owner
  stores it in Key Vault (`docs/ops/AZURE-SETUP.md` section 9). The API token needs Account, Cloudflare Tunnel: Edit.
* **Tier E mTLS (`enable_mtls`).** Creates `api-mtls.<apex>` and a WAF rule that blocks any request to it without a verified client
  certificate. Uploading a tenant CA is a per-tenant operational step (`docs/ops/RUNBOOKS.md`, "Enterprise mTLS onboarding").
* **Secrets.** None in code. State can contain the edge token: protect the backend. `edge_token` is a sensitive variable.

## Validation

`tofu fmt -check`, `tofu init -backend=false` and `tofu validate` pass (OpenTofu 1.13.2; CI job `infrastructure`). `tofu plan` needs real
credentials and ids.
