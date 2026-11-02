# Trust boundaries (Stage 1)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §4.3, §5, §9, §18, §22, §27 |
| Decisions | 5 (authority in staging), 11 (Azure only), 12 (key placement); `docs/product/AUTH-OWNER-DECISIONS.md` |
| Companion | `docs/architecture/THREAT_MODEL.md`; ADR-0019 (layout), ADR-0023 (evidence), ADR-0028 (keys and CI) |
| Date | 2026-11-02 |
| Status | Proposed target for staging. Section 1 is today (verified against `Infra/azure/locals.tf`, `identity.tf`, `containerapps.tf`, `network.tf`); sections 2 onward are the target. |

## 1. Today (baseline, for contrast)

One Container Apps environment `cae-viadere-<env>` on `snet-cae` (`10.40.0.0/23` in staging). `ca-viadere-api` (internal ingress, plain HTTP inside the environment), `ca-cloudflared`, optional `ca-viadere-worker`, `job-viadere-migrate`. `id-viadere-api` holds Crypto User on `kek-data`, `kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest` and Secrets User on every service secret (`locals.tf` `key_grants`). One deploy identity `id-gh-deploy-<env>` holds Container Apps Contributor on the app resource group and Managed Identity Operator on all four workload identities (`identity.tf` lines 45-57). No grant, MFA, signer or recovery identity exists (CURRENT_STATE §3.1). Findings F-01, F-02, F-13.

## 2. Components and trust classes (target)

| Component | Runtime | Trust class | Ingress | Identity |
|---|---|---|---|---|
| Cloudflare edge | SaaS | edge (control plane class AS-7) | Internet | Cloudflare account; API tokens per workflow |
| Static publication (`id.<domain>` discovery and JWKS, developer site) | Cloudflare Workers Static Assets (ADR-0004) | publication | Internet (read-only) | site workflow Cloudflare token |
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
| B5 | api → authority | HTTPS to the authority's internal FQDN (`ca-viadere-authority.internal.<env-domain>`) | Entra access token, `aud = api://viadere-authority-<env>`, app role `Authority.Evidence.Submit`, `oid` ∈ {api, worker}, token lifetime as issued by Entra, validated against Entra JWKS | **device/passkey evidence** verified against the authority key log; challenge, nonce, audience, expiry, single use; policy (ADR-0023 §6) |
| B6 | authority → Key Vault (`kv-vdr-auth`) | HTTPS (service endpoint in lean, private endpoint in standard) | managed identity token `https://vault.azure.net` | Crypto User per key; Secrets User per secret |
| B7 | authority → PostgreSQL | TLS verify-full | Entra token as `viadere_authority` | DML on its own database only |
| B8 | api/worker → providers | HTTPS | provider credentials | provider-side |
| B9 | Business backend ← api (webhooks) | HTTPS to registered endpoint | webhook signature v2 (ADR-0025) | receiver verifies; payload ids only |
| B10 | RP / business ← static publication | HTTPS GET JWKS, discovery | Cloudflare TLS | content changes only through reviewed commits |
| B11 | Device ← authority (relayed by api) | signed key-log heads (`viadere-keylog-head+jws`) | signature with pinned `keylog-signing` public key | freshness ≤ 15 min |
| B12 | CI → Azure | OIDC federation | federated subject = environment + `job_workflow_ref` | resource-group-scoped roles (section 6) |
| B13 | Human operator → authority admin | GitHub workflow `authority-admin.yml` in environment `authority-admin-<env>` (2 required reviewers) → starts `job-viadere-authority-admin` | GitHub identity + reviewers | the job's command allow-list (ADR-0019 §5) |

Rule (spec §4.3, §18): B2 and the network part of B5 are access restrictions. Neither is ever sufficient: B5 always requires the evidence check, and the authority treats the api as untrusted.

## 4. Key and permission matrix (who may hold what)

### 4.1 Keys and secrets

| Key / secret | Type | Purpose (`typ` / use) | Store | Holder (only) | Who must NOT hold it |
|---|---|---|---|---|---|
| `grant-signing` | EC P-256, ES256, non-exportable | `viadere-grant+jwt` (link-service results) | `kv-vdr-auth` | `id-viadere-authority` (Crypto User, key scope) | api, worker, every deploy identity |
| `oidc-signing-rs256` | RSA 3072, RS256 | id_token default alg (OIDC Discovery requires RS256 support); RFC 9068 access tokens | `kv-vdr-auth` | `id-viadere-authority` | same |
| `oidc-signing-es256` | EC P-256, ES256 | id_tokens for clients registered with `id_token_signed_response_alg = ES256` | `kv-vdr-auth` | `id-viadere-authority` | same |
| `keylog-signing` | EC P-256, ES256 | `viadere-keylog-head+jws` (account key-log heads, pinned in the app) | `kv-vdr-auth` | `id-viadere-authority` | same |
| `OIDC_PAIRWISE_KEY` | 32-byte secret | HMAC for pairwise OIDC `sub` | `kv-vdr-auth` secret | `id-viadere-authority` (Secrets User, secret scope) | api |
| `SUBJECT_REF_KEY` (authority copy) | 32-byte secret | compute `sub` of grants = the tenant's existing `subject_ref` (SECURITY §2.30) | `kv-vdr-auth` secret (copy; rotation coordinated, ADR-0028 §3) | authority (also api, by design: knowing it does not let the api choose the account) | n/a |
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

### 4.2 Identities and roles

| Identity | Roles (scope) | Must not have |
|---|---|---|
| `id-viadere-api` | Crypto User on the five exception keys (`kv-vdr`, key scope); Secrets User on api secrets; Service Bus sender/receiver; Monitoring Metrics Publisher; DB role `viadere_app` (DML on `viadere`); app role `Authority.Evidence.Submit` on the authority's Entra application | any role on `kv-vdr-auth`; CONNECT on `viadere_authority`; any role on `rg-viadere-<env>-auth` |
| `id-viadere-worker` | as today (`kek-data`, `audit-head-signing`, secrets, Service Bus); `Authority.Evidence.Submit` (expiry sweeps call `revocations` only) | same as api |
| `id-viadere-authority` | Crypto User on the four authority keys (key scope, operations `sign` and `verify` only); Secrets User on `OIDC_PAIRWISE_KEY` and the `SUBJECT_REF_KEY` copy; DB role `viadere_authority`; Monitoring Metrics Publisher on its own App Insights; AcrPull on the authority registry | any role on `kv-vdr`; any Service Bus role; any provider credential; any role on `rg-viadere-<env>-app` |
| `id-viadere-authority-admin` | DB role `viadere_authority_admin` (INSERT on `authority_policy_versions`, `authority_oidc_clients`, `authority_link_clients`, `authority_keylog_imports`); no Key Vault role | Key Vault roles; network ingress |
| `id-viadere-authority-migrator` | owner of `viadere_authority` schema | runtime roles, Key Vault |
| `id-gh-deploy-<env>` (existing, reduced) | Container Apps Contributor on `rg-viadere-<env>-app`; Managed Identity Operator on api, worker, migrator, cloudflared | any role on `rg-viadere-<env>-auth` or on any authority identity |
| `id-gh-deploy-auth-<env>` (new) | Container Apps Contributor on `rg-viadere-<env>-auth`; Managed Identity Operator on `id-viadere-authority`, `-authority-admin`, `-authority-migrator`; AcrPush on the authority registry (lean) | any role on `rg-viadere-<env>-app` |
| `id-gh-authority-admin-<env>` (new) | custom role "Container Apps Job Starter" on `job-viadere-authority-admin` only | deploy rights, Key Vault |
| `id-gh-infra-apply-<env>` (existing, re-scoped) | Contributor + constrained RBAC Administrator on the four existing resource groups only (F-03) | any role on `rg-viadere-<env>-auth` |
| `id-gh-infra-auth-apply-<env>` (new) | Contributor + constrained RBAC Administrator on `rg-viadere-<env>-auth` | roles elsewhere |
| Crypto officers group (authority) `grp-viadere-<env>-auth-crypto-officers` | Key Vault Crypto Officer on `kv-vdr-auth` via PIM, time-bound | membership overlap with `grp-viadere-<env>-kv-crypto-officers` is a policy-check warning |
| Subscription Owner / Entra admins | everything | AS-7 class, alerts only (R-11) |

### 4.3 Authority API (what the api may ask for)

All under `https://<authority internal FQDN>/internal/v1/`, JSON, strict decoding, ≤ 32 KiB bodies.

| Route | Effect | Monotone? | Evidence required |
|---|---|---|---|
| `POST challenges` | create an authority challenge `ach_…` with nonce, purpose, tenant, client, display object, return URL or redirect URI, expiry ≤ 600 s | neutral (creates nothing usable without evidence) | none |
| `POST evidence` | verify a `viadere-factor+jws` or WebAuthn assertion for a challenge; on success mint the purpose's artifact (link-code registration, OIDC authorization code) | increases (only with evidence) | device or passkey evidence over the challenge nonce |
| `POST link-codes/redeem` | business redemption → `viadere-grant+jwt` | increases (only with a code whose hash is in verified evidence + PKCE verifier) | prior evidence |
| `POST oidc/token` | code + PKCE + client auth → id_token, access token | increases (only with a prior code) | prior evidence |
| `POST keylog/entries` | append to an account's key log | increases (only with proof by a logged key, or genesis for a new account, or authority-timed recovery) | proof (ADR-0023 §4) |
| `GET keylog/{account_ref}/head` | signed head for relay to the app | neutral | none |
| `POST policy/raise` | raise a tenant/client assurance floor | **reduce-only** (tightens) | none |
| `POST revocations` | revoke a key, a challenge family, a grant family, a client (suspension) | **reduce-only** | none |
| `GET health` | liveness | neutral | none |

Not exposed to any ordinary identity: policy lowering, OIDC client or link client registration/change, key import, key creation, any raw `sign`. These exist only as commands of `ViadereAuthority admin …` in `job-viadere-authority-admin` (ADR-0019 §5).

## 5. The monotone api rule

An ordinary workload may cause only changes that **reduce** the ability to authenticate: revoke, freeze, cancel, deny, raise a floor, suspend. Every change that **increases** it (a key added to an account, a lower floor, a new redirect URI or return URL, a new client, a signature) requires either fresh device/passkey evidence verified by the authority, or the two-reviewer admin path. Reviewers check every route in section 4.3 against this rule; Stage 7 test ST-AUTH-02, -06, -07 enforce it.

## 6. Data flows

Notation: `→` request, `⇢` push or asynchronous, `[x]` = boundary id.

### DF-1 Business-supplied magic link (delivery only; authority not involved)

```
Business ─[B3]→ api POST /v1/business/auth-deliveries {method: magic_link, destination.url}
api: tenant from credential; signature; idempotency; destination policy; store row + P-class ciphertext + outbox (one txn)
worker/api ⇢ APNs (ids only: adl id, category viadere.auth.link) [B8]
Device NSE ─[B4]→ api GET /v1/auth-deliveries/{id} (display: business, purpose, host; no URL)  → status delivered
User taps Continue ─[B4]→ api POST /v1/auth-deliveries/{id}/open → URL once; ciphertext deleted; status opened
Device opens URL via system API (universal link to business app, or browser)
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
api ─[B5]→ authority POST challenges {purpose: link_open, tenant, link_client_id, return_url, display, code_challenge} → ach, nonce
api ⇢ APNs (ids only)
Device ─[B4]→ api GET display (+ ach, nonce); user chooses "On this device" (or "On another device" → enters number)
Device: link_code = 32 random bytes; signs viadere-factor+jws {aud: authority, ach, nonce, display_digest, code_hash = SHA-256(link_code), uv, decision}
Device ─[B4]→ api POST /v1/auth-deliveries/{id}/approve ─[B5]→ authority POST evidence → verified, link code hash registered
Device opens return_url?vdr_code=<link_code> in the browser
Business ─[B3]→ api POST /v1/business/auth-links/redeem {code, code_verifier} ─[B5]→ authority POST link-codes/redeem
authority → viadere-grant+jwt {iss, aud = tenant, sub = subject_ref computed by authority, ...}  → business verifies with static grant JWKS [B10]
```

### DF-4 OIDC (staging; Viadere-asserted; authority mints)

```
RP browser → api GET /oidc/authorize (code, PKCE S256, nonce, state, redirect_uri)
api ─[B5]→ authority POST challenges {purpose: oidc_login, client_id, redirect_uri, display} (authority checks client + exact redirect URI)
User: passkey (WebAuthn, rpId = RP_ID, origin https://id.<domain>) or app approval (login_hint or QR) with number matching
api ─[B5]→ authority POST evidence → authorization code (authority-held, 60 s)
api → 302 redirect_uri?code&state
RP backend → api POST /oidc/token ─[B5]→ authority POST oidc/token (PKCE, client auth) → id_token (RS256 or ES256)
RP verifies with JWKS from static publication [B10]
```

### DF-5 Key-log append (new device)

```
New device enrolls at api (existing passkey or D1 confirmation, App Attest)
api ─[B5]→ authority POST keylog/entries {account_ref, entry: device_added, new key, proof: ConfirmationProof by logged D1 key or WebAuthn assertion by logged passkey}
authority verifies proof against its log; records usable_from = now + 24 h (cool-down) → signs new head
```

## 7. Mapping to spec §4.3 invariants

| Invariant (§4.3) | Where it holds |
|---|---|
| One compromised ordinary workload must not issue arbitrary valid grants | §4.1 (no key), §4.3 (no raw sign; evidence needed), §5 (monotone rule), ADR-0023 §4 (key log), §5 (authority computes `sub`) |
| Public gateway cannot export grant/token keys or self-authorize signatures | §4.1, §4.2 (no Key Vault role), non-exportable keys, ADR-0028 |
| Grant decisions require independently authenticated, audience-bound, short-lived evidence; policy controls assurance | ADR-0023 §3 (factor JWS: `aud`, `ach`, nonce, `exp − iat ≤ 120`), §6 (policy evaluation in the authority) |
| Tenant isolation at data, key, authorization, message-routing layers | data: per-query tenant filter + authority DB separation; key: pairwise approval keys, per-tenant link/OIDC clients; authorization: tenant from credential (ADR-0020 §4); routing: pairwise `subject_ref`, webhook v2 binds tenant (ADR-0025) |
| Recovery and enrollment cannot bypass effective assurance without explicit controlled downgrade | ADR-0023 §4 (key-log proofs, recovery hold), ADR-0027 (phone link is never a factor), SECURITY §2.26 |
| Any failure to validate nonce, audience, origin, signature, state, time, policy version or replay state results in denial | ADR-0023 §6 verification order, fail-closed defaults; ST-AUTH-09, ST-GR-* |
| A tunnel or mTLS handshake is never itself sufficient authorization | §3 rule; B5 requires evidence |

## 8. Mapping to spec §27 stop-ship rules

| Stop-ship rule | Boundary / control |
|---|---|
| Single ordinary public service can issue a successful grant | §4, §5, ADR-0022 §7 (legacy path frozen) |
| Link token in push payloads or logs | DF-1 (ids-only push, P-class ciphertext), ADR-0020 §6 |
| Verified business domain bypass | ADR-0021 §2-§3 (api) and §5.2 (authority-registered return URLs); R-07 recorded |
| Cross-tenant access | §7 tenant row |
| Critical keys exportable to application processes | §4.1 non-exportable, held only by the authority |
| Recovery bypasses assurance | §7 recovery row |

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
