# Trust boundaries (Stage 1)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §4.3, §5, §9, §18, §22, §27 |
| Decisions | 5 (authority in staging), 11 (Azure only), 12 (key placement); `docs/product/AUTH-OWNER-DECISIONS.md` |
| Companion | `docs/architecture/THREAT_MODEL.md`; ADR-0019 (layout), ADR-0023 (evidence), ADR-0028 (keys and CI) |
| Date | 2026-11-02 |
| Status | Proposed target for staging, **revision 3** after the A2 and A3 re-reviews (`docs/reviews/STAGE1_RESPONSE.md` "Revision 3"): recovery codes and recovery keys sealed to `recovery-seal` (ADR-0034), passkey assertions limited to `oidc_login` and `recovery_cancel`, device-add comparison code, standby keys as separate objects, new §4.3a rows, DF-5 and DF-6 rewritten. **Revision 2** after the Stage 1 reviews (`docs/reviews/STAGE1_RESPONSE.md`): field-level trust table (§4.3a), authority-minted accounts and authority-verified recovery (ADR-0032), authority-built displays and device statements (ADR-0033), tenant destination keys (ADR-0031), JWKS publication path (ADR-0024 §7). Section 1 is today (verified against `Infra/azure/locals.tf`, `identity.tf`, `containerapps.tf`, `network.tf`); sections 2 onward are the target. |

## 1. Today (baseline, for contrast)

One Container Apps environment `cae-viadere-<env>` on `snet-cae` (`10.40.0.0/23` in staging). `ca-viadere-api` (internal ingress, plain HTTP inside the environment), `ca-cloudflared`, optional `ca-viadere-worker`, `job-viadere-migrate`. `id-viadere-api` holds Crypto User on `kek-data`, `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest` and Secrets User on every service secret (`locals.tf` `key_grants`). One deploy identity `id-gh-deploy-<env>` holds Container Apps Contributor on the app resource group and Managed Identity Operator on all four workload identities (`identity.tf` lines 45-57). No grant, MFA, signer or recovery identity exists (CURRENT_STATE §3.1). Findings F-01, F-02, F-13.

## 2. Components and trust classes (target)

| Component | Runtime | Trust class | Ingress | Identity |
|---|---|---|---|---|
| Cloudflare edge | SaaS | edge (control plane class AS-7) | Internet | Cloudflare account; API tokens per workflow |
| Static publication: `id.<domain>` discovery and JWKS | Cloudflare Workers Static Assets (ADR-0004) | **authority publication** (as protected as the signing keys, ADR-0024 §7) | Internet (read-only) | `authority-publish.yml` in environment `authority-publish-<env>` (reviewers), own Cloudflare token scoped to `id.` only; admits only thumbprints from the attested authority key inventory |
| Static publication: developer site | Cloudflare Workers Static Assets | publication | Internet (read-only) | site workflow Cloudflare token (no `id.` scope) |
| JWKS monitor | read-only GitHub scheduled workflow | monitor | none | no Azure or Cloudflare write credential |
| `ca-cloudflared` | Container App, `cae-viadere-<env>` | ordinary | none | `id-viadere-cloudflared` |
| `ca-viadere-api` (`ROLE=api`) | Container App, `cae-viadere-<env>` | **ordinary, public-facing** | environment-internal, via tunnel | `id-viadere-api` |
| `ca-viadere-worker` (`ROLE=worker`) | Container App, `cae-viadere-<env>` | ordinary | none | `id-viadere-worker` |
| `job-viadere-migrate` | Container Apps job | ordinary (schema owner) | none | `id-viadere-migrator` |
| `ca-viadere-authority` (`ViadereAuthority` executable) | Container App, **separate** environment `cae-viadere-<env>-auth` on `snet-auth` | **authority** | VNet-internal only (internal environment, ILB), 443 from `snet-cae` | `id-viadere-authority` |
| `job-viadere-authority-admin` | Container Apps job in `cae-viadere-<env>-auth` | authority-admin | none (manual start) | `id-viadere-authority-admin` |
| `job-viadere-authority-migrate` | Container Apps job in `cae-viadere-<env>-auth` | authority (schema owner of `viadere_authority`) | none | `id-viadere-authority-migrator` |
| PostgreSQL Flexible Server | PaaS on `snet-pg` | data | 5432 from `snet-cae` and `snet-auth` | Entra roles |
| `kv-vdr-<env>` (existing) | Key Vault | ordinary keys | firewall: `snet-cae` (+ admin IPs, `AzureServices`) | RBAC |
| `kv-vdr-auth-<env>` (new) | Key Vault | authority keys | firewall: `snet-auth` only (+ `AzureServices` for ARM key creation, no admin IPs) | RBAC |
| Service Bus | PaaS | ordinary | public endpoint, Entra only (existing exception) | RBAC |
| Devices (iOS app, NSE, watch; Android later) | consumer hardware | device | n/a | device keys (Secure Enclave / Keystore) |
| Business backend | partner | tenant | n/a | API key + request-signing key or Tier E cert |
| Business browser / RP | partner | tenant / user agent | n/a | none (PKCE verifier, cookies) |
| APNs, FCM (later), MailerSend email, SMS providers | partner | provider (AS-6) | n/a | provider credentials (api secrets) |
| GitHub Actions | CI | control plane class | n/a | OIDC federated identities (section 6) |

The authority is the **only** component outside the "ordinary" class in the request path. Everything in the ordinary class is assumed compromisable together (AS-1, AS-2).

## 3. Boundaries

| Id | Boundary | Crossing | Authentication | Authorization |
|---|---|---|---|---|
| B1 | Internet → edge | HTTPS (TLS 1.2+ ECDHE/AEAD, 1.3 preferred) | none / business credentials / device signatures (below) | WAF, rate rules |
| B2 | Edge → api | Cloudflare Tunnel → `ca-cloudflared` → api (environment-internal HTTP) | `X-Viadere-Edge-Token` (existing shared header; F-13) | not authorization; second layer only |
| B3 | Business → api | `/v1/business/*` | API key (`vdk_…`, SHA-256 at rest) **plus** RFC 9421 signature with a registered key (live) or Tier E mTLS (ADR-0020 §3) | tenant = key's business; scopes; capability ceiling; destination policy |
| B4 | Device → api | `/v1/*` consumer routes | bearer + `VIADERE-SIG-V1` device signature (SECURITY §2.3) | device belongs to the consumer; device trust tier |
| B5 | api/worker → authority | HTTPS to the authority's internal FQDN (`ca-viadere-authority.internal.<env-domain>`) | Entra access token, `aud = api://viadere-authority-<env>`; app role `Authority.Evidence.Submit` (api only) or `Authority.Revocations` (worker, `revocations` only); `oid` allow-list; validated against Entra JWKS | **device/passkey evidence** verified against the authority key log; challenge, nonce, audience, expiry, single use; policy (ADR-0023 §6); every field per §4.3a |
| B6 | authority → Key Vault (`kv-vdr-auth`) | HTTPS (service endpoint in lean, private endpoint in standard) | managed identity token `https://vault.azure.net` | Crypto User per key; Secrets User per secret |
| B7 | authority → PostgreSQL | TLS verify-full | Entra token as `viadere_authority` | DML on its own database only |
| B8 | api/worker → providers | HTTPS | provider credentials | provider-side |
| B9 | Business backend ← api (webhooks) | HTTPS to registered endpoint | webhook signature v2 (ADR-0025) | receiver verifies; payload ids only |
| B10 | RP / business ← static publication | HTTPS GET JWKS, discovery | Cloudflare TLS | changes only through `authority-publish.yml` (reviewers, CODEOWNERS, attested key inventory); independent monitor alerts on unknown `kid` (ADR-0024 §7) |
| B11 | Device ← authority (relayed by api) | signed device statements: key-log heads, challenges with authority-built displays, tenant destination-key records, pinned-key revocation lists (ADR-0033, ADR-0031) | signature with a pinned `device-statement-signing` key (active or standby), `typ` per statement | freshness ≤ 15 min for heads and tenant records; head must list the device's own keys and `seq` must not decrease |
| B11b | Device ← business (relayed by api) | `viadere-destination+jws` for business-mode links | signature with a tenant key from the authority-signed record | URL digest, host in authority `allowed_hosts`, `brq`, `purpose`, `exp`, `jti` (ADR-0031 §4) |
| B12 | CI → Azure | OIDC federation | federated subject = environment + `job_workflow_ref` | resource-group-scoped roles (section 6) |
| B13 | Human operator → authority admin | GitHub workflow `authority-admin.yml` in environment `authority-admin-<env>` (required reviewers, Prevent self-review; staging: single owner approval, R-21) → starts `job-viadere-authority-admin` | GitHub identity + reviewers; agents use a GitHub identity distinct from the owner's | the job's command allow-list (ADR-0019 §5); change file on protected `main` under CODEOWNERS |

Rule (spec §4.3, §18): B2 and the network part of B5 are access restrictions. Neither is ever sufficient: B5 always requires the evidence check, and the authority treats the api as untrusted.

## 4. Key and permission matrix (who may hold what)

### 4.1 Keys and secrets

| Key / secret | Type | Purpose (`typ` / use) | Store | Holder (only) | Who must NOT hold it |
|---|---|---|---|---|---|
| `grant-signing` | EC P-256, ES256, non-exportable | `viadere-grant+jwt` (link-service results) | `kv-vdr-auth` | `id-viadere-authority` (Crypto User, key scope) | api, worker, every deploy identity |
| `oidc-signing-rs256` | RSA 3072, RS256 | id_token default alg (OIDC Discovery requires RS256 support); RFC 9068 access tokens | `kv-vdr-auth` | `id-viadere-authority` | same |
| `oidc-signing-es256` | EC P-256, ES256 | id_tokens for clients registered with `id_token_signed_response_alg = ES256` | `kv-vdr-auth` | `id-viadere-authority` | same |
| `device-statement-signing` (was `keylog-signing`) | EC P-256, ES256 | `viadere-keylog-head+jws`, `viadere-challenge+jws`, `viadere-tenant-keys+jws`, seal-family revocation lists (ADR-0033); pinned in the app as the active key | `kv-vdr-auth` | `id-viadere-authority` | same |
| `device-statement-signing-standby` (separate key object) | EC P-256, ES256, created disabled | statement-family revocation lists and statements after rollover (ADR-0033 §3); pinned in the app as the standby | `kv-vdr-auth` | **nobody** until rollover (role granted by `id-gh-infra-auth-apply`, reviewer-gated), then `id-viadere-authority` | everyone before rollover (`AUTH-STANDBY-ROLE`) |
| `recovery-seal` active + standby | HPKE KEM key pairs, P-256 (suite of ADR-0034) | open sealed recovery sets and starts | private halves only wrapped in `authority_seal_keys`; active one in authority memory after unwrap | `id-viadere-authority` (active only) | api, worker, every deploy identity |
| `recovery-seal-kek`, `recovery-seal-kek-standby` | RSA 3072, RSA-OAEP-256, `wrapKey`/`unwrapKey` only | wrap the seal private keys | `kv-vdr-auth` | authority: custom "Unwrapper" role on `recovery-seal-kek` only; standby KEK: nobody until rollover | api, worker |
| `OIDC_PAIRWISE_KEY` | 32-byte secret | HMAC for pairwise OIDC `sub` only | `kv-vdr-auth` secret | `id-viadere-authority` (Secrets User, secret scope) | api |
| `ACCOUNT_REF_KEY` | 32-byte secret | HMAC for `account_ref` (ADR-0032 §4) | `kv-vdr-auth` secret | `id-viadere-authority` | api |
| `RECOVERY_VERIFIER_KEY` | 32-byte secret | HMAC for authority recovery-code verifiers (ADR-0032 §3, ADR-0034 §4); the codes it verifies are a separate set the api never sees or hashes | `kv-vdr-auth` secret | `id-viadere-authority` | api |
| `SUBJECT_REF_KEY` (authority copy) | 32-byte secret | compute `sub` of grants = the tenant's existing `subject_ref` (SECURITY §2.30) | `kv-vdr-auth` secret (copy; rotation coordinated, ADR-0028 §3) | authority (also api, by design: knowing it does not let the api choose the account, **because** the authority checks the account id against the signing key's `account_ref` first, ADR-0032 §2) | n/a |
| Tenant destination public keys | P-256 public | verify `viadere-destination+jws` | `authority_tenant_keys` (admin job only, after a registration PoP and the key's thumbprint in DNS or well-known evidence fetched by the reviewer-gated workflow; `not_after` ≤ 13 months; ADR-0031 §1) | authority (relayed to devices in a signed record) | private halves: the business only |
| `kd-log-signing` | EC P-256 | key-directory log heads | `kv-vdr` | api (**decision 12 exception**) | authority (unneeded) |
| `link-descriptor` | EC P-256 | link-session descriptors | `kv-vdr` | api (exception) | |
| `loop-publication` | EC P-256 | Loop manifests | `kv-vdr` | api (exception) | |
| `brand-manifest` | EC P-256 | Brand manifests | `kv-vdr` | api (exception) | |
| `kek-data` | RSA 3072 wrap | `kms1:` wrapped secrets | `kv-vdr` | api, worker (exception: required to operate) | authority |
| `audit-head-signing` | EC P-256 | exported audit heads | `kv-vdr` | worker | api |
| `AUTH_SECRET_KEY` (new) | 32-byte AES-256-GCM key, `kms1:`-wrappable | encrypt P-class fields (`auth_delivery_secrets`) | `kv-vdr` secret | api, worker | authority (unneeded) |
| Webhook secrets `whsec_…` | per subscription | webhook v1/v2 MAC | api DB (sealed) | api, worker | authority |
| Device keys (`request`, `approvalUserPresence`, `approvalBiometric`), pairwise approval keys, passkeys | P-256 private | device evidence | Secure Enclave / Keystore / platform authenticator | the device | every server |
| Business request-signing keys | P-256 or Ed25519 private | RFC 9421 signatures | business | the business | Viadere (public key only) |

New authority keys never exist in `kv-vdr` and are never granted to an ordinary identity (decision 12; policy-check rule `AUTH-KEY-SCOPE`, ADR-0028 §5).

**What "non-exportable" means (S1-A3-11).** Lean (Key Vault Standard): software-protected keys; no API export and no Secure Key Release, but a backup blob is possible for any holder of `keys/backup/action` and restorable within the same subscription and geography, so backup is restricted by role (`AUTH-KEY-BACKUP`): only the PIM-activated crypto-officer group holds it, and `id-viadere-authority` has a custom sign-only role. Standard: HSM-protected keys. The authority signs only with explicitly pinned key versions (ADR-0028 §2).

### 4.2 Identities and roles

| Identity | Roles (scope) | Must not have |
|---|---|---|
| `id-viadere-api` | Crypto User on the five exception keys (`kv-vdr`, key scope); Secrets User on api secrets; Service Bus sender/receiver; Monitoring Metrics Publisher; DB role `viadere_app` (DML on `viadere`); app role `Authority.Evidence.Submit` on the authority's Entra application | any role on `kv-vdr-auth`; CONNECT on `viadere_authority`; any role on `rg-viadere-<env>-auth` |
| `id-viadere-worker` | as today (`kek-data`, `audit-head-signing`, secrets, Service Bus); app role `Authority.Revocations` only (reaches `POST revocations` and nothing else; S1-A2-8) | same as api; `Authority.Evidence.Submit` |
| `id-viadere-authority` | custom role "Viadere Authority Signer" (`keys/read`, `keys/sign/action`) on the active authority signing keys, key scope, pinned versions; custom role "Viadere Authority Unwrapper" (`keys/read`, `keys/unwrapKey/action`) on `recovery-seal-kek` only; no role on standby keys before rollover; Secrets User on `OIDC_PAIRWISE_KEY`, `ACCOUNT_REF_KEY`, `RECOVERY_VERIFIER_KEY` and the `SUBJECT_REF_KEY` copy; DB role `viadere_authority`; Monitoring Metrics Publisher on its own App Insights; AcrPull on the authority registry | any role on `kv-vdr`; Key Vault Crypto User (includes backup/update); any Service Bus role; any provider credential; any role on `rg-viadere-<env>-app` |
| `id-viadere-authority-admin` | DB role `viadere_authority_admin` (INSERT on `authority_policy_versions`, `authority_oidc_clients`, `authority_link_clients`, `authority_tenant_keys`, `authority_keylog_imports`; UPDATE of `grant_capable` only through the audited restore command); no Key Vault role | Key Vault roles; network ingress |
| `id-viadere-authority-migrator` | owner of `viadere_authority` schema | runtime roles, Key Vault |
| `id-gh-deploy-<env>` (existing, reduced) | Container Apps Contributor on `rg-viadere-<env>-app`; Managed Identity Operator on api, worker, migrator, cloudflared | any role on `rg-viadere-<env>-auth` or on any authority identity |
| `id-gh-deploy-auth-<env>` (new) | Container Apps Contributor on `rg-viadere-<env>-auth`; Managed Identity Operator on `id-viadere-authority`, `-authority-admin`, `-authority-migrator`; AcrPush on the authority registry (lean) | any role on `rg-viadere-<env>-app` |
| `id-gh-authority-admin-<env>` (new) | custom role "Container Apps Job Starter" on `job-viadere-authority-admin` only; Log Analytics Reader on the authority workspace, limited to the admin job's execution-log table (to attest the printed key inventory, ADR-0024 §7.3) | deploy rights, Key Vault |
| `authority-publish.yml` (GitHub environment `authority-publish-<env>`) | Cloudflare token scoped to `id.` static assets only; no Azure identity | any other Cloudflare scope; any Azure role |
| `id-gh-infra-apply-<env>` (existing, re-scoped) | Contributor + constrained RBAC Administrator on the four existing resource groups only (F-03) | any role on `rg-viadere-<env>-auth` |
| `id-gh-infra-auth-apply-<env>` (new) | Contributor + constrained RBAC Administrator on `rg-viadere-<env>-auth` | roles elsewhere |
| Crypto officers group (authority) `grp-viadere-<env>-auth-crypto-officers` | Key Vault Crypto Officer on `kv-vdr-auth` via PIM, time-bound | membership overlap with `grp-viadere-<env>-kv-crypto-officers` is a policy-check warning |
| Subscription Owner / Entra admins | everything | AS-7 class, alerts only (R-11) |

### 4.3 Authority API (what the api may ask for)

All under `https://<authority internal FQDN>/internal/v1/`, JSON, strict decoding, ≤ 32 KiB bodies.

| Route | Effect | Monotone? | Evidence required |
|---|---|---|---|
| `POST challenges` | create an authority challenge `ach_…` from references only (purpose, client id, requested return URL or redirect URI checked byte for byte against the registration, delivery id, key-log entry); the authority builds the display and returns a signed `viadere-challenge+jws`; expiry ≤ 600 s | neutral (creates nothing usable without evidence) | none |
| `POST evidence` | verify a `viadere-factor+jws` or WebAuthn assertion for a challenge; on success mint the purpose's artifact (link-code registration, OIDC authorization code) | increases (only with evidence) | device or passkey evidence over the challenge nonce, display and (link) return URL |
| `POST link-codes/redeem` | business redemption → `viadere-grant+jwt` | increases (only with a code whose hash is in verified evidence + PKCE verifier) | prior evidence |
| `POST oidc/token` | code + PKCE + client auth → id_token, access token | increases (only with a prior code) | prior evidence |
| `POST keylog/entries` | append to an account's key log; `genesis` mints the account id (no caller-chosen id) | increases (only with a factor JWS by a logged grant-capable device key, never a passkey assertion; PoP + App Attest for genesis; a device-add comparison code; or a sealed, authority-verified recovery code bound to the new keys) | proof (ADR-0023 §3a, §4; ADR-0032; ADR-0033 §4.1; ADR-0034) |
| `GET keylog/{account_ref}/head` | signed head (plus the latest pinned-key revocation list) for relay to the app | neutral | none |
| `GET tenant-keys/{tenant_id}` | signed tenant destination-key record (plus the revocation list) for relay to the app (ADR-0031) | neutral | none |
| `GET oidc/clients/{client_id}/check` | `{valid, display_name}` for an exact redirect URI; no signing (ADR-0024 §4) | neutral | none |
| `POST policy/raise` | raise a tenant/client assurance floor | **reduce-only** (tightens) | none |
| `POST revocations` | revoke a key, a challenge family, a grant family, a client (suspension) | **reduce-only** | none |
| `GET health` | liveness | neutral | none |

Not exposed to any ordinary identity: policy lowering, OIDC client, link client or tenant destination key registration/change, key import, key creation, restoring grant capability, any raw `sign`. These exist only as commands of `ViadereAuthority admin …` in `job-viadere-authority-admin` (ADR-0019 §5). No authority route returns another tenant's link clients, consents, grants or audit to an api token; only the two signed records above are readable (ST-AUTH-19).

### 4.3a Field-level trust (S1-A2-8)

Every value the authority uses that arrives through the api. Rule: a field that ends up in a signed artifact is either authority-derived or covered by device, passkey or business evidence; otherwise it is refused.

| Route | Field | Source | Authority trusts it? | Check applied | If AS-1 lies |
|---|---|---|---|---|---|
| `challenges` | purpose | api | as a request only | must match the client type; bound into the signed challenge and the factor JWS | evidence for another purpose is refused |
| `challenges` | `link_client_id` / `oidc_client_id` | api | as a reference only | must exist, be active; tenant, `display_name`, `aud`, `tid` come from the record | the device shows the real client of that id; grant `aud`/`tid` are that client's |
| `challenges` | `return_url` / `redirect_uri` | api | no | byte-for-byte equality with the registration; signed into the challenge; `return_url` echoed in the factor JWS | refused |
| `challenges` | display text | — | **not accepted** | authority builds it (ADR-0033 §1) | no effect |
| `challenges` | `code_challenge` (link service) | business via api | as data | stored; redemption requires the matching verifier | link service: a wrong value only makes redemption fail for the real business; OIDC: R-17 |
| `challenges` | OIDC `code_challenge`, `state`, `nonce` | RP via api | as data | stored with the code; PKCE at token | R-17 (session swap of a genuine login), named exception |
| `challenges` | `login_hint` | RP via api | as a lookup only | resolves an account for a push; evidence must come from that account's key | at most a prompt to the wrong person, which counts against fatigue budgets |
| `challenges` | delivery id | api | as a reference only | must name a delivery of the same tenant as the client record; bound into the signed challenge | at most a challenge for another delivery of the same tenant, which the device displays from authority data |
| `challenges` (OIDC) | creation itself | api, on a user action | neutral | created only after a method is chosen; edge limits per IP and client; per-tenant signing bulkhead (ADR-0024 §4, ADR-0033 §2) | that tenant's OIDC challenges degrade; nothing else does |
| `evidence` | factor JWS | device via api | yes, after verification | ADR-0023 §3 | refused |
| `evidence` | WebAuthn assertion | browser or app via api | **only** for `oidc_login` and `recovery_cancel` | `clientDataJSON.origin` on the per-purpose allow-list, UV, grant-capable passkey (ADR-0023 §3a) | refused for every key-adding purpose; for `oidc_login`, R-17 (single session only) |
| `evidence` (`keylog_device_added`) | `match` (comparison code) | person types it on the approving device | after verification | equals the code the authority computes from the entry's `kids` and the challenge nonce (ADR-0033 §4.1) | substituted keys give a different code; refused |
| `evidence`, `link-codes/redeem`, `oidc/token` | `accountId` | api | no | constant-time check against the signing key's `account_ref` (ADR-0032 §2) | refused, alerted |
| `link-codes/redeem` | tenant | api | equality only | must equal the link-client record's tenant; never a source | refused |
| `link-codes/redeem` | `code`, `code_verifier` | business via api | as data | hash in authority store; PKCE; single use; 120 s | refused |
| `keylog/entries` | account id | — | **not accepted** at genesis | minted by the authority | no effect |
| `keylog/entries` | keys, proofs, App Attest | device via api | after verification | PoP by every new key, proof by a logged key, attestation | refused |
| `keylog/entries` (`device_added`) | new-device name | new device via api | **as reported text only** | bounded, NFC, no control/bidi characters; marked `reported_name` and rendered "Name chosen on the new device" (ADR-0033 §1) | a misleading name; the comparison code, not the name, decides |
| `keylog/entries` (`enrollment_confirmed`) | `head_hash`, `seq` | device via api | after verification | equal to the current head; every key of the entry must confirm the same head (ADR-0032 §1.4) | refused |
| `keylog/entries` (`recovery_codes_set`) | recovery codes | device | **never seen by the api** | HPKE envelope to the pinned `recovery-seal` key; `envelope_digest` in the factor JWS by a D1-equivalent `approvalBiometric` key (ADR-0034) | api sees ciphertext only; a swapped envelope breaks the factor JWS |
| `keylog/entries` (`recovery_started`) | recovery code, new passkey and app keys (`new_kids`) | recovering device | code: never seen by the api; keys: after verification | code and `new_kids` sealed together; every new key's PoP commits to `envelope_digest`; activation adds exactly `new_kids` (ADR-0032 §3.2-§3.3) | a substituted key does not match `new_kids`; refused. Without a sealed code: `recovery_started_legacy`, never grant-capable, refused when an authority set exists |
| `keylog/entries` | recovery id | api | as a reference only | names the recovery the sealed start answers; inside the sealed plaintext | a wrong id fails the sealed comparison |
| `tenant-keys/{tenant_id}` | path parameter | api | as a reference only | selects which signed record to return; the device checks `tenant_id` and `seq` in the signed record against the delivery | the device refuses a record for another tenant or an older `seq` |
| `oidc/token` | client assertion | RP via api | after verification | `private_key_jwt`, `aud` = issuer, registered JWK | `invalid_client` |
| `revocations`, `policy/raise` | any | api/worker | yes | reduce-only by construction | DoS only (R-14, R-19) |

## 5. The monotone api rule

An ordinary workload may cause only changes that **reduce** the ability to authenticate: revoke, freeze, cancel, deny, raise a floor, suspend. Every change that **increases** it (a key added to an account, an account created, a lower floor, a new redirect URI or return URL, a new client, a new tenant destination key or host, a grant-capable recovery, a signature) requires either fresh device/passkey evidence verified by the authority, or the reviewer-gated admin path (single owner approval in staging, R-21). The rule applies per field, not only per route (§4.3a). Reviewers check every route in section 4.3 against this rule; Stage 7 tests ST-AUTH-02, -06, -07, -15, -16, -17, -19 enforce it.

## 6. Data flows

Notation: `→` request, `⇢` push or asynchronous, `[x]` = boundary id.

### DF-1 Business-supplied magic link (delivery only; authority not involved)

```
Business ─[B3]→ api POST /v1/business/auth-deliveries {method: magic_link, destination: {url, signature = viadere-destination+jws}}
api: tenant from credential; signature; idempotency; destination policy; store row + P-class ciphertext + outbox (one txn)
worker/api ⇢ APNs (ids only: adl id, category viadere.auth.link) [B8]
Device NSE ─[B4]→ api GET /v1/auth-deliveries/{id} (display: business, purpose, host, destination statement; no URL)  → status delivered
Device ─[B4]→ api GET tenant destination-key record (authority-signed) [B11]; verifies statement [B11b]; shows name and host from them
User taps Continue ─[B4]→ api POST /v1/auth-deliveries/{id}/open → URL once; ciphertext deleted; status opened
Device: SHA-256(URL) == url_sha256, host == statement host, validator → opens URL via system API
  integrity failure → deny {reason: destination_unverified} (alert, not counted toward the pause); stale/absent record or clock skew → no server call, item stays open, retry (ADR-0031 §4)
Business verifies its own token; ─[B3]→ api POST /v1/business/auth-deliveries/{id}/complete → completed
api ⇢ webhook v2 auth.delivery.* (ids only) [B9]
```

### DF-2 Push MFA / payment step-up (business-verified; authority not involved)

```
Business ─[B3]→ api POST /v1/business/auth-approvals (Approve v2 request + number_match) 
api ⇢ APNs generic "Action needed" (req id)
Device ─[B4]→ api GET request (E2EE envelope or server-visible), user types number, biometric, signs ApprovalResult v2 JWS (pairwise key)
Device ─[B4]→ api POST /v1/approve/requests/{id}/result
api ⇢ webhook approve.request.decided {result_ref}
Business ─[B3]→ api GET result → verifies JWS with ITS enrolled key, its challenge, its txn_digest, its match code
```

### DF-3 Viadere link service (Viadere-asserted; authority mints)

```
Business ─[B3]→ api POST /v1/business/auth-deliveries {method: magic_link, link_mode: viadere, link_client_id, return_url, code_challenge}
api ─[B5]→ authority POST challenges {purpose: link_open, link_client_id, return_url, code_challenge, delivery id} → signed viadere-challenge+jws (authority-built display, exact return_url)
api ⇢ APNs (ids only)
Device ─[B4]→ api GET delivery (+ challenge statement); verifies it [B11]; renders its display; user chooses "On this device" (or "On another device" → enters number)
Device: link_code = 32 random bytes; signs viadere-factor+jws {aud: authority, ach, nonce, display_digest, return_url, code_hash = SHA-256(link_code), uv, decision}
Device ─[B4]→ api POST /v1/auth-deliveries/{id}/approve ─[B5]→ authority POST evidence → verified (incl. return_url byte equality, account binding), link code hash registered
Device opens the signed return_url#vdr_code=<link_code> in the browser
Business ─[B3]→ api POST /v1/business/auth-links/redeem {code, code_verifier} ─[B5]→ authority POST link-codes/redeem
authority → viadere-grant+jwt {iss, aud = link client from record, tid from record, sub = subject_ref computed by authority after binding check, ...}  → business verifies with grant JWKS [B10]
```

### DF-4 OIDC (staging; Viadere-asserted; authority mints)

```
RP browser → api GET /oidc/authorize (code, PKCE S256, nonce, state, redirect_uri) → api ─[B5]→ authority GET oidc/clients/{id}/check (no challenge, no signing)
person chooses a method (POST, CSRF; edge limits per IP and client)
api ─[B5]→ authority POST challenges {purpose: oidc_login, client_id, redirect_uri, code_challenge, nonce, state} (authority checks client + exact redirect URI, builds and signs the display) — R-17: the api controls this front end
User: passkey (WebAuthn, rpId = RP_ID, origin https://id.<domain> on the oidc_login allow-list; this assertion can only ever yield this one login, ADR-0023 §3a) or app approval (login_hint or QR) with number matching
api ─[B5]→ authority POST evidence → authorization code (authority-held, 60 s)
api → 302 redirect_uri?code&state
RP backend → api POST /oidc/token ─[B5]→ authority POST oidc/token (PKCE, client auth) → id_token (RS256 or ES256)
RP verifies with JWKS from static publication [B10]
```

### DF-5 Key-log append (new device)

```
New account:  device ─[B4]→ api ─[B5]→ authority POST keylog/entries {genesis, keys, PoP over authority nonce, App Attest} → authority mints account_id, returns it + signed head
              api creates the consumer row with that account_id; device verifies head lists exactly its keys → enrollment_confirmed (factor JWS) → keys grant-capable
              enrollment_confirmed carries head_hash + seq and a PoP by every key of the entry; keys grant-capable only when all confirmed the same head
New device B: enrolls at api (existing D1 confirmation, App Attest); submits device_added entry {new keys, PoP by each}
api ─[B5]→ authority POST challenges {keylog_device_added, entry} → signed challenge {account_ref, kids, nonce, display: reported_name, kids, match_digits 6}
B verifies the challenge: kids == exactly its own keys (else S-DEV-05, stop) → shows code = decimal6(SHA-256("VIADERE-DEVICE-ADD-V1\n" ‖ env ‖ nonce ‖ sorted kids))   [never shown on A]
A (grant-capable approvalBiometric, cool-down over) verifies the challenge, account_ref == its own → person types B's code → factor JWS {match: code}
api ─[B5]→ authority POST keylog/entries {device_added, factor JWS} → expected code from the stored entry, constant-time compare, approving key in the entry's account, PoPs
authority records usable_from = now + 24 h (cool-down) → signs new head; B verifies the head lists exactly its keys → enrollment_confirmed
No passkey assertion is accepted for device_added or passkey_added (ADR-0023 §3a); a passkey-only person adds a device through an existing device or through recovery (DF-6)
```

### DF-6 Recovery (sealed codes, ADR-0032 §3, ADR-0034)

```
Register:  trusted device generates 10 codes → authority challenge {recovery_codes_set} → HPKE seal {account_ref, set_id, nonce, codes} to pinned recovery-seal (info VIADERE-RECOVERY-SET-V1\n{env}, aad ach\nnonce)
           ─[B4]→ api (ciphertext only) ─[B5]→ authority {envelope, factor JWS by D1-equivalent approvalBiometric key with envelope_digest} → verifiers stored, old authority set invalidated
           app → api: invalidate the api's legacy set (the api never held the new codes)
Start:     recovering device ─[B4]→ api POST /v1/recovery/begin {recoveryId} ─[B5]→ authority challenge {recovery_started}
           device creates passkey + app keys → seals {recovery_id, nonce, code, new_kids} → PoP by each new key over (…\n{nonce}\n{envelope_digest})
           ─[B4]→ api ─[B5]→ authority: open, verify code (limits), PoP keys == new_kids → recovery_started {kids}; head pending_recoveries[].kids
           recovering device verifies the head lists exactly its new_kids
Hold:      72 h; any logged key (factor JWS) or logged passkey (assertion, allowed origin) cancels; S-REC-02 on existing devices from the head
Activate:  adds exactly kids, revokes earlier keys; grant-capable only for a sealed, authority-verified start
```

## 7. Mapping to spec §4.3 invariants

| Invariant (§4.3) | Where it holds |
|---|---|
| One compromised ordinary workload must not issue arbitrary valid grants | §4.1 (no key), §4.3 (no raw sign; evidence needed), §5 (monotone rule), ADR-0023 §4 (key log), §5 (authority computes `sub`) |
| Public gateway cannot export grant/token keys or self-authorize signatures | §4.1, §4.2 (no Key Vault role), non-exportable keys, ADR-0028 |
| Grant decisions require independently authenticated, audience-bound, short-lived evidence; policy controls assurance | ADR-0023 §3 (factor JWS: `aud`, `ach`, nonce, `exp − iat ≤ 120`), §6 (policy evaluation in the authority) |
| Tenant isolation at data, key, authorization, message-routing layers | data: per-query tenant filter + authority DB separation; key: pairwise approval keys, per-tenant link/OIDC clients; authorization: tenant from credential (ADR-0020 §4); routing: pairwise `subject_ref`, webhook v2 binds tenant (ADR-0025) |
| Recovery and enrollment cannot bypass effective assurance without explicit controlled downgrade | ADR-0032 (authority-minted accounts, authority-verified recovery codes; legacy-code recovery never grant-capable), ADR-0034 (codes sealed end to end, separate from the api's, bound to the new keys), ADR-0033 §4.1 (device-add comparison code), ADR-0023 §3a (no passkey assertion adds a key), ADR-0023 §4 (key-log proofs, recovery hold), ADR-0027 (phone link is never a factor), SECURITY §2.26 |
| Any failure to validate nonce, audience, origin, signature, state, time, policy version or replay state results in denial | ADR-0023 §6 verification order, fail-closed defaults; ST-AUTH-09, ST-GR-* |
| A tunnel or mTLS handshake is never itself sufficient authorization | §3 rule; B5 requires evidence |

## 8. Mapping to spec §27 stop-ship rules

| Stop-ship rule | Boundary / control |
|---|---|
| Single ordinary public service can issue a successful grant | §4, §5, ADR-0022 §7 (legacy path frozen) |
| Link token in push payloads or logs | DF-1 (ids-only push, P-class ciphertext), ADR-0020 §6 |
| Verified business domain bypass | ADR-0021 §2-§3 (api validator), ADR-0031 (business-signed destinations verified on the device against authority tenant records; fail closed), ADR-0021 §5.2 and ADR-0033 (authority-registered, signed return URLs); residual R-07' only |
| Cross-tenant access | §7 tenant row |
| Critical keys exportable to application processes | §4.1 non-exportable, held only by the authority |
| Recovery bypasses assurance | §7 recovery row; DF-6 |

## 9. Network specifics (staging, lean)

| Item | Value | Note |
|---|---|---|
| `snet-auth` | `cidrsubnet(vnet_cidr, 11, 32)` = `10.40.4.0/27` (staging), `10.50.4.0/27` (production plan) | does not overlap `snet-cae` /23, `snet-pg` /28, `snet-pe` /27; delegated to `Microsoft.App/environments`; /27 is the documented minimum for workload-profile environments (A5 re-checks in Stage 6) |
| `cae-viadere-<env>-auth` | workload-profile environment, `Consumption` profile, `internal = true` | private DNS zone for its default domain linked to the VNet so `snet-cae` resolves it |
| NSG `nsg-viadere-<env>-auth` inbound | allow 443 from `snet-cae`; allow `AzureLoadBalancer`; deny all | api and cloudflared share `snet-cae`, so the NSG cannot tell them apart; the Entra token check does (B5) |
| NSG outbound | allow 5432 to `snet-pg`; allow 443 to service tags `AzureActiveDirectory`, `AzureKeyVault.<region>`, `AzureMonitor`, `AzureContainerRegistry.<region>`, `MicrosoftContainerRegistry`, `Storage.<region>` (registry data); deny `Internet` | the list is validated by A5 in Stage 6 against Microsoft's documented outbound requirements before enabling the deny; any extra tag is recorded |
| Image source | authority image pulled from a registry reachable by service tag (ACR Basic in lean, ACR with private endpoint in standard), not from GHCR | GHCR needs general internet egress; F-18 PAT issue does not apply to the authority |
| App-level outbound guard | authority's `OutboundDestinationGuard` in allow-list mode: Key Vault host, Entra login host, App Insights ingestion host, PostgreSQL host; anything else refused and logged | defense in depth for the NSG |
| Database | separate database `viadere_authority` on the existing Flexible Server (lean); role `viadere_authority`; `REVOKE CONNECT ... FROM PUBLIC`; `viadere_app`/`viadere_worker` get no CONNECT | standard profile decides between a separate server or subscription (ADR-0019 §4.5) |
