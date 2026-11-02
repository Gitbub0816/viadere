# Authentication delivery threat model (Stage 1)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §4, §13, §18, §22, §26, §27 (Part II binding) |
| Owner decisions | `docs/product/AUTH-OWNER-DECISIONS.md` 1-12; post-Stage-0 rulings O-1, O-3, O-6, decision-9 phone proof |
| Inputs | `docs/architecture/CURRENT_STATE.md`, `GAP_ANALYSIS.md` (F-01 to F-27), `docs/SECURITY.md` §1 and §2 |
| Companion | `docs/architecture/TRUST_BOUNDARIES.md` (who holds which key and permission); ADR-0019 to ADR-0030 in `docs/ops/adr/` |
| Date | 2026-11-02 |
| Author roles | A1, A2, A3, A5, A10 (Stage 1 author). Self-approval is forbidden (§15.1); reviewers are listed in `docs/reviews/STAGE1_REVIEW_REQUEST.md`. |
| Status | Proposed, **revision 3** after the A2 re-review (BLOCK, narrow) and the A3 re-review (approve with conditions): sealed recovery (T-REC-8, ADR-0034), passkey assertions never add keys (T-REC-9), device-add comparison code (T-REC-10), pinned-key revocation roles (T-AUTH-17), challenge flood (T-AUTH-16), tenant key registration (T-ML-9), destination failure classes (T-ML-10), grouping instead of supersession (T-MFA-6), R-17 narrowed, R-23 added. **Revision 2** after the four Stage 1 reviews (A2 verdict BLOCK; A3, A6/A7, A9/A10 approve with conditions). Every finding's disposition is in `docs/reviews/STAGE1_RESPONSE.md`. Nothing here is implemented. Where this document says "existing", it cites the file or the `SECURITY.md` section that implements it today. |

## 0. How to read and check this document

- Threat ids are `T-<component>-<n>`. Controls cite an ADR (`ADR-00NN §n`), an existing `SECURITY.md` section, or a Stage 0 finding (`F-NN`). Tests are `ST-<area>-<nn>` and are defined once, in section 6; Stage 7 (A12, A13) runs every one of them.
- "Ordinary workload" means any process that is not the private authority: `ca-viadere-api`, `ca-viadere-worker`, `ca-cloudflared`, migrate and scheduled jobs (TRUST_BOUNDARIES §2).
- Every attacker assumption of spec §4.2 is section 2; every red-team scenario of spec §26 is section 5; every stop-ship rule of §27 is section 7.
- A reviewer checks a row by (1) finding the control in the cited ADR, (2) confirming the test in section 6 would fail if the control were removed. A row whose test would still pass without its control is a defect in this document.

## 1. Scope, assets and design stance

### 1.1 In scope

| Id | Component | What it is in the target design |
|---|---|---|
| GW | Public gateway / api | `ca-viadere-api` behind Cloudflare and the tunnel: business API, consumer API, OIDC front end, consoles (ADR-0019) |
| DO | Delivery orchestrator | Auth-delivery aggregate, outbox, push (APNs; FCM later), in-app inbox, email adapter; **no SMS for authentication** (decisions 1, 9) (ADR-0020) |
| ML | Business-supplied magic links | Business URL on a verified domain, confirm-before-open handoff (ADR-0021 §1-§4) |
| LS | Viadere link service | Optional link generation and redemption; result is an authority-signed grant (ADR-0021 §5) |
| OTP | One-time-code delivery | Business-generated codes delivered in-app or by email; Viadere never verifies them (ADR-0020 §6) |
| TOTP | TOTP | On-device authenticator (seeds never leave the device) and partner-code transport; no server-side TOTP verification (decision 3) |
| MFA | Push MFA | Approve v2 pairwise keys, number matching, transaction binding, fatigue controls, passkey-biased step-up, watch tier (ADR-0022) |
| PAY | Payment step-up | `transaction.approve` with number matching, biometric, D1 (ADR-0022 §4) |
| REC | Recovery and device linking | Existing recovery (SECURITY §2.26), device confirm (§2.17), authority key log (ADR-0023 §4), phone ownership proof (ADR-0027) |
| AUTH | Private grant/policy authority and signer | `ca-viadere-authority`, internal ingress only, own identity, own vault and keys (ADR-0019, ADR-0023, ADR-0028) |
| OIDC | OIDC provider (staging) | Authorization code + PKCE; tokens minted only by AUTH; discovery/JWKS published statically (ADR-0024) |
| CP | Cloud control plane and CI | Azure RBAC, OpenTofu identities, GitHub OIDC deploy identities, Cloudflare (ADR-0028, ADR-0029) |
| CON | Consoles | Business console and operator console (existing, `Dashboard/*`), new auth pages |

Out of scope: SAML (design only, ADR-0024 §9); production (no agent deploys there); the existing messaging, Loops, Brand Kits, profiles and household features except where they touch the flows above (they are baseline, O-6; section 1.4 lists the touch points).

### 1.2 Assets (spec §4.1, mapped to stores)

| Asset | Where it lives (target) | Class (ADR-0026) |
|---|---|---|
| Device private keys | Secure Enclave / Android Keystore; never leave the device | n/a (device) |
| Device and passkey public keys, account binding | api DB (`devices`, `device_keys`, `passkey_credentials`) **and** the authority key log (`authority_keylog_entries`) | E (evidence) |
| Pairwise approval keys | api DB `approve_keys`, the business's own enrollment record | E |
| Business magic-link URL (bearer) | `auth_delivery_secrets` ciphertext, minutes | P (pending secret) |
| OTP / partner TOTP code | `auth_delivery_secrets` ciphertext, minutes | P |
| Link-service code | device-generated, only its hash in the evidence; authority `authority_link_codes` holds the hash | P |
| Number-match code | business or authority; on the device only while the prompt is open | P |
| Grant artifacts, id_tokens | never stored; issuance records only (`authority_grants`: jti, kid, aud, acr, sub hash, iat) | E |
| Authority signing keys | `kv-vdr-auth-<env>` (non-exportable; HSM in standard) | key |
| Existing api keys (`kd-log-signing`, `link-descriptor`, `loop-publication`, `brand-manifest`, `kek-data`) | `kv-vdr-<env>`, api identity (decision 12 exception, ADR-0028) | key |
| Recovery records | api DB (`recovery_codes`, `account_recoveries`); authority keyed recovery verifiers (`authority_recovery_verifiers`, ADR-0032 §3) and key log | E-high |
| Account identity binding | authority `authority_accounts` (minted or imported `account_ref`, grant capability), ADR-0032 | E-high |
| Tenant destination public keys | authority `authority_tenant_keys` (admin job only), ADR-0031 | T |
| API credentials | `api_keys` (SHA-256), business request-signing keys (ADR-0020 §3) | T |
| Tenant configuration, destination policy, grant policy | api DB (destination policy); authority DB (grant policy, link clients, OIDC clients) | T / authority |
| Notification metadata | APNs/FCM payloads (opaque ids only), `auth_delivery_events` | T |
| Audit trail | `audit_events` (keyed chain, SECURITY §2.22), authority audit log | E |

### 1.3 Design stance (what makes the containment claim testable)

1. **Three kinds of result, never confused.** (a) Delivery-only (business magic link, OTP, partner TOTP code, notices): Viadere asserts nothing; `COMPLETED` comes only from the business (ADR-0020 §5). (b) Business-verified device evidence (push MFA, payment step-up): the business verifies the device's pairwise `ApprovalResult` JWS against a key **it** enrolled (SECURITY §2.54); the api's status is never sufficient. (c) Viadere-asserted results (link-service redemption, OIDC tokens): signed only by the private authority after it verifies device or passkey evidence against **its own** key log (ADR-0023).
2. **Monotone api rule.** An ordinary workload may do anything that only *reduces* authority (revoke a key, raise a policy floor, freeze, cancel, deny) and nothing that *increases* it (add a key to an account, lower a policy, register a redirect URI or link client, sign a grant) (TRUST_BOUNDARIES §5).
3. **Network position is never authorization** (§4.3, §18). The authority checks an Entra workload token (access control) and then the device/passkey evidence (authorization). Both must pass.

### 1.4 Baseline touch points (O-6)

| Baseline feature | Touch point | Rule |
|---|---|---|
| Household delegation | Delegates already cannot decide `authenticate`/`authorize` | Auth deliveries and auth approvals go only to the subject's own app devices; a delegate device never receives them, never opens them, never approves them (ST-TEN-06) |
| Customer profiles | none | No profile value in any auth-delivery record, event or webhook (ST-PRIV-01) |
| First-party actions (Live Activities, notification actions, rewards, Wallet, Loop actions) | Live Activities | Auth deliveries and approvals are never Live Activity eligible (existing exclusion for secure flows, `LiveActivityService`); test keeps it (ST-UX-05) |
| SMS gateway (on-ramp) | Phone ownership, secure handoff | No code, link token or approval over SMS or RCS (ADR-0027); the gateway keeps menus, routing, STOP/HELP, "get Viadere" |

## 2. Attacker assumptions (spec §4.2)

Each assumption is applied to every component in section 3. This table states what the attacker gets and what must still hold.

| Id | Assumption (§4.2) | Attacker capability | Must still hold | Residual | Tests |
|---|---|---|---|---|---|
| AS-1 | Internet-facing gateway compromised with arbitrary code execution | Everything `id-viadere-api` can do: read/write the api database as `viadere_app`, read all api secrets, sign with the five api keys (decision 12 exception), send pushes, call the authority with a valid Entra token, render any page on api hosts (including the OIDC authorize page and the WebAuthn origin) | No valid grant, id_token or link-service result for an account whose keys the attacker does not hold; the authority accepts no identity, account id, subject, display, return URL, recovery assertion or destination from the api without independent verification (TRUST_BOUNDARIES §4.3a); no policy lowering; no new redirect URI, link client or tenant destination key; no authority key use outside the authority's own checks; no undetected rewrite of a business link (ADR-0031); no cross-tenant data beyond what the api DB already holds | R-01, R-02, R-03, R-07', R-14, R-17, R-18, R-19 (section 8) | ST-GW-01..08, ST-AUTH-01..19, ST-REC-07..13, ST-LS-07, -08, ST-ML-10..13 |
| AS-2 | One workload identity, API key or DB read credential stolen | (a) api UAMI token: as AS-1 minus code execution; (b) business API key: act as that tenant within its scopes; (c) `viadere_app` DB read: read all api tables | (a) as AS-1; (b) only that tenant's requests, only to that tenant's customers, only to verified destinations, rate-limited; live keys also need a request signature (ADR-0020 §3); (c) no bearer link, code or secret in clear (P class ciphertext, keyed hashes); no grant from DB contents | R-04 | ST-TEN-01..05, ST-GW-09, ST-PRIV-03 |
| AS-3 | Employee support account phished or session token stolen | Console session with that role | No route from any console role to: a grant, a policy lowering, an OIDC client or link client change, an authority key, a key-log append, a recovery override. Operator actions that only reduce (suspend tenant, revoke device, freeze) are allowed and audited | R-05 | ST-CON-01..05 |
| AS-4 | Business integration or tenant admin malicious or compromised | Tenant API keys, console Owner role, webhook endpoint | Cannot reach other tenants (data, routing, revocation, completion); cannot register an unverified destination; cannot alter security copy, Deny prominence or approval semantics; cannot lower assurance below the platform floor; phishing-domain registration is detected and held | R-06 | ST-TEN-*, ST-ML-03..07, ST-UX-01..03 |
| AS-5a | Consumer device stolen while locked | Physical device, no passcode/biometric | Approval keys need user verification (biometric or passcode); nothing secret on the Lock Screen; Deny/Report reachable without unlocking only where it is safe (deny reduces) | R-08 | ST-MFA-08, ST-PRIV-05 |
| AS-5b | Consumer device stolen while unlocked | Unlocked device; biometric may still be required | High-risk approvals need biometric (`approvalBiometric`, `.biometryCurrentSet`); device revocation from another device or recovery works; pending approvals die with the device | R-09 | ST-MFA-09, ST-REC-06 |
| AS-6 | Upstream push, email or SMS provider unavailable or compromised | Drop, delay, duplicate, read or replay notification payloads; a compromised email provider reads email bodies | Push payloads contain no bearer material, code or personal data (opaque ids); outage fails closed with no silent downgrade; email carries a code or link only when the business explicitly chose email fallback for that request (ADR-0020 §7) | R-10 | ST-DLV-03..06, ST-PRIV-02 |
| AS-7 | Cloud control-plane or high-privilege administrator compromise (separate severe class) | Subscription Owner, Key Vault Administrator, Entra admin, GitHub org admin, Cloudflare account admin | Not contained by service isolation (spec §4.4). Detected: key/RBAC/DNS/route change alerts, signed audit heads, Key Vault sign reconciliation, independent JWKS monitor, separate apply identities and approvals; no single CI credential deploys api and authority or publishes JWKS (ADR-0028 §6, ADR-0024 §7) | R-11, R-21 | ST-CI-01..08, ST-OIDC-15, ST-GR-07 |

## 3. STRIDE per component

Columns: threat, control (where specified), test. "S/T/R/I/D/E" = Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.

### 3.1 GW: public gateway / api

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-GW-1 | E | AS-1 attacker mints a link-service grant or id_token directly | api holds no authority key; grant and OIDC keys live only in `kv-vdr-auth` with Crypto User granted only to `id-viadere-authority` (ADR-0028 §2, TRUST_BOUNDARIES §4) | ST-AUTH-01, ST-CI-03 |
| T-GW-2 | E | AS-1 attacker asks the authority to sign arbitrary content | Authority has no "sign this" endpoint; every signature is produced by an authority-internal decision over evidence it verified (ADR-0023 §6) | ST-AUTH-02 |
| T-GW-3 | E | AS-1 attacker inserts its own device key for a victim account in the api DB, or posts a forged `genesis` for a victim's account id, then produces "evidence" | Authority verifies evidence only against its own key log; account ids are **minted by the authority** at genesis (no caller-chosen id), every pre-existing id is imported once (keyless ones never grant-capable), no account is created while genesis fails, and a device's keys are grant-capable only after every key confirmed the head it verified (ADR-0032 §1); appends need proof by a logged key plus PoP by the new key (ADR-0023 §4, ADR-0033 §4). Residual: none for new accounts; imported keys rest on R-16 | ST-AUTH-03, -04, -15, ST-REC-12 |
| T-GW-4 | E | AS-1 attacker substitutes the subject mapping (victim's `subject_ref` or `accountId` paired with the attacker's own valid evidence) | Authority checks any `accountId` against the signing key's `account_ref` in constant time before computing `sub`, and takes the business id, `aud` and `tid` from its client record (ADR-0032 §2) | ST-AUTH-05, ST-AUTH-05a, ST-AUTH-17 |
| T-GW-5 | E | AS-1 attacker lowers grant policy, adds a redirect URI or link client | Authority API exposes only raise-only policy and reduce-only revocation to the api; lowering and client registration exist only in the reviewer-gated admin job (named reviewers, Prevent self-review, CODEOWNERS; a single owner approval in staging, R-21) (ADR-0019 §5, ADR-0024 §3, ADR-0028 §6.6) | ST-AUTH-06, ST-AUTH-07, ST-CI-08 |
| T-GW-6 | T | AS-1 attacker rewrites a business-supplied magic-link URL to a phishing host | Business-signed `viadere-destination+jws` (URL digest, host, `brq`, `jti`) verified on the device against an authority-signed tenant destination-key record before Continue; URL bytes checked against the digest before opening; fail closed without a signature (ADR-0031). Residual R-07' (genuine signed URL for the attacker's own account) | ST-ML-08, ST-ML-10..13, ST-AUTH-16 |
| T-GW-7 | I | Generic errors leak enrollment ("does this person use Viadere?") | Uniform `404`/`409 not_deliverable` for unknown subject, no device, opted out; same timing class (spec §6.1; ADR-0020 §4) | ST-TEN-04 |
| T-GW-8 | S | Forged business request with a stolen API key | Live keys require an RFC 9421 HTTP Message Signature with a registered business key, or Tier E mTLS; test keys may be bearer-only (ADR-0020 §3) | ST-GW-09 |
| T-GW-9 | T | Body tampering, oversized or malformed requests | Strict decoding (unknown members refused, including any `tenant_id`), bounded sizes (create body ≤ 16 KiB), schema validation (ADR-0020 §2) | ST-GW-10 |
| T-GW-10 | D | Floods against public endpoints | Cloudflare WAF and rate rules, per-IP and per-tenant buckets, fail-closed namespaces for all new auth namespaces (ADR-0020 §8) | ST-DLV-07 |
| T-GW-11 | R | A business denies having requested a delivery | Request signature (live), idempotency record with request digest, audit event `auth_delivery.created` with key id (ADR-0020 §3, §9) | ST-GW-11 |
| T-GW-12 | S | Origin bypass inside the Container Apps environment (F-13) | Out of scope for the authority (token checked); api keeps the edge token; Stage 6 evaluates workload-token authentication for the api | ST-GW-12 |
| T-GW-13 | T | AS-1 attacker supplies a misleading display (business name, host, device thumbprints) to an authority-backed prompt | Authority builds every display from its own records and signs the challenge; the device verifies before the person acts; `display_digest` compares against the authority-built object (ADR-0033) | ST-LS-08, ST-REC-10, ST-GW-07 |
| T-GW-14 | E | AS-1 attacker starts a recovery for a dormant victim and suppresses notices for 72 h | `recovery_started` needs a sealed code the authority verifies, from a set the api never saw (ADR-0034); legacy-code recovery never yields grant-capable keys and is refused when an authority set exists; the app shows S-SEC-01 when heads are withheld (ADR-0032 §3) | ST-REC-07, -08, -09, -14, -20, -21 |

### 3.2 DO: delivery orchestrator

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-DO-1 | I | Bearer link, OTP, code, `login_hint` or phone number in a push payload, log, edge log, analytics, crash report, webhook or queue envelope | Push payload is ids only (`adl` id, category); secrets live only in `auth_delivery_secrets` ciphertext; queue envelopes are ids only (SECURITY §2.91); auth, phone-link and OIDC routes log an **allow-list** of fields (no query string, no body), implemented in the logger and telemetry initializer, regex redaction only as a second layer; Cloudflare Logpush excludes query strings on `id.` and link hosts; webhooks are opaque v2 envelopes (ADR-0020 §6, §9, ADR-0026 §3, ADR-0025) | ST-PRIV-01..04 |
| T-DO-2 | T | Duplicate delivery or double state change after a crash | Transactional outbox; `processed_messages` idempotency; every transition is a compare-and-swap on `(id, status, version)` (ADR-0020 §5) | ST-DLV-01, ST-DLV-02 |
| T-DO-3 | S | Provider acknowledgment treated as human receipt | `SENT` = provider accepted; `DELIVERED` = the app fetched the item (device-signed) or an email provider receipt; neither is authentication (spec §6.2; ADR-0020 §5) | ST-DLV-03 |
| T-DO-4 | E | Silent fallback to a weaker channel (email, SMS) | No SMS adapter for auth exists (decision 1); email only when the request names `fallback.email` and tenant policy allows it; the event `auth.delivery.fallback_used` records the downgrade (ADR-0020 §7) | ST-DLV-04, ST-DLV-05 |
| T-DO-5 | D | Push outage blocks sign-in | In-app inbox still lists the delivery when the app is opened; business sees `queued`/`sent` without `delivered`; fail closed, never "success" (spec §12) | ST-DLV-06 |
| T-DO-6 | I | Notification metadata reveals relationships to Apple/Google (F-20) | Opaque per-device thread id; no business id or name in the payload; title and body generic until the NSE fetches content (ADR-0020 §6) | ST-PRIV-02 |
| T-DO-7 | T | Expired or cancelled delivery still opened | Open requires `status ∈ {queued,sent,delivered}` and `now < expires_at` inside the same CAS that deletes the secret (ADR-0020 §5) | ST-DLV-08 |
| T-DO-8 | D | Push bombing through repeated deliveries | Per (tenant, subject) grouping: a new request joins the open group without a new alert, and supersedes an open one only with the same business `session_handle` (revision 3, ADR-0020 §8, ADR-0022 §5.2), so an attacker cannot cancel the person's own request; per-subject budgets limit **alerting** (over budget: silent inbox delivery), only per-tenant aggregate floods get `429` (ADR-0020 §8, ADR-0022 §5) | ST-MFA-05, ST-MFA-10, ST-DLV-09 |

### 3.3 ML: business-supplied magic links

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-ML-1 | S | Tenant registers a look-alike or someone else's domain | Existing domain control (DNS TXT or well-known file) per domain, plus purpose binding `auth_links` and an exact-host allow-list; new destination host triggers a console notice to all Owners and a 24 h hold for tenants younger than 30 days (ADR-0021 §2) | ST-ML-03 |
| T-ML-2 | T | Open redirect on the business host sends the user elsewhere | Query values that look like absolute or scheme-relative URLs must themselves pass the allow-list; businesses attest no open redirect on registered hosts; Viadere never follows redirects (ADR-0021 §3) | ST-ML-04 |
| T-ML-3 | S | Host confusion: userinfo, IDN homographs, IP literals, ports, trailing dot, backslashes, mixed case | Parser rules in ADR-0021 §3.1 (A-labels only, exact host match after lowercase, no userinfo, no port except 443 omitted, no IP literals) | ST-ML-05 |
| T-ML-4 | I | Link prefetch or preview consumes or leaks the token | Viadere never fetches the URL; the app opens it only after an explicit tap on the confirm screen (fixes F-08 pattern); NSE never sees the URL (ADR-0021 §4) | ST-ML-06 |
| T-ML-5 | I | Referrer or analytics leak | App opens via system API (no Viadere page in between, no referrer); business guidance requires `Referrer-Policy: no-referrer` and no third-party assets on redemption pages (spec §6.4; ADR-0021 §4.5) | ST-ML-07 (guidance check in harness) |
| T-ML-6 | E | Wrong-device or wrong-browser completion (attacker-initiated link opened by the victim) | Confirm screen states "Continue on this device"; Viadere does not transfer sessions; business binds its token to the initiating browser and uses number matching for cross-device (ADR-0021 §6) | ST-ML-09 |
| T-ML-7 | T | AS-1 URL rewrite | see T-GW-6 (ADR-0031) | ST-ML-10..13 |
| T-ML-8 | R | Business claims Viadere opened the link | `OPENED` event with device-signed open request reference; business receives `auth.delivery.opened` | ST-DLV-03 |
| T-ML-9 | E | AS-1 (between dashboard and operator) substitutes its own public key in a tenant destination-key registration while the domain evidence stays genuine | Registration needs a PoP JWS by the new key over an admin-job nonce, and the key's RFC 7638 thumbprint must appear in the DNS TXT or well-known evidence, fetched by the reviewer-gated workflow (not the api); `not_after` ≤ 13 months (ADR-0031 §1, S1-A3-R03) | ST-AUTH-16 |
| T-ML-10 | D | Outages or wrong device clocks look like user denials (business fraud signal, pause count, alert flood hiding real tampering) | Two failure classes: integrity → `destination_unverified` deny, high-priority alert, never counted toward the pause; availability (stale or absent record, clock) → no server call, item stays open, retry copy (ADR-0031 §4, S2-A2-10) | ST-ML-15 |

### 3.4 LS: Viadere link service

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-LS-1 | E | AS-1 attacker forges a redemption result | Result is a `viadere-grant+jwt` signed by the authority's `grant-signing` key after it verifies a device `viadere-factor+jws` over its own challenge nonce (ADR-0021 §5, ADR-0023) | ST-LS-01 |
| T-LS-2 | T | Return URL swapped to an attacker host (at challenge creation or at the device) | Return URLs are pre-registered per link client **in the authority** under the admin path; authority refuses a challenge whose `return_url` is not registered exactly, signs it into the challenge, and requires the factor JWS to carry the same URL; the device opens only the URL it signed, after the authority accepted the evidence (ADR-0021 §5, ADR-0033 §4) | ST-LS-02, ST-LS-07 |
| T-LS-3 | S | Code replay or redemption by another tenant | Code is device-generated (256 bits), only `SHA-256` is in the evidence; single use (authority CAS); 120 s TTL; redemption bound to the link client and to the business's PKCE `code_verifier` (ADR-0021 §5.3) | ST-LS-03, ST-LS-04 |
| T-LS-4 | E | Cross-device confusion (attacker-initiated) | Same-device path needs the initiating browser's verifier; cross-device path requires number matching entered on the phone (ADR-0021 §6) | ST-LS-05 |
| T-LS-5 | I | AS-1 observes codes at redemption | Code alone is useless without the verifier bound to the initiating session; the code travels in the URL fragment, not to the business server's logs; attack also needs the victim to approve an attacker-initiated prompt (R-03) | ST-LS-06 |

### 3.5 OTP: one-time-code delivery

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-OTP-1 | I | Code in push, logs or webhook | as T-DO-1; app fetches the code only after the user opens the item; code display is not on the Lock Screen | ST-PRIV-01, ST-OTP-01 |
| T-OTP-2 | E | Viadere mistaken for the verifier | Viadere never verifies business codes; contract states that the business verifies with rate limits, keyed hashes, bounded retries (spec §6.5; ADR-0020 §6) | ST-OTP-02 (contract test: no verify endpoint exists) |
| T-OTP-3 | S | Phishing: user reads the code to an attacker | Copy: "Never share this code. {Business} will never ask for it." Code is labelled with the business and purpose; OTP is documented as not phishing resistant (UX_COPY C-OTP-*) | ST-UX-04 |
| T-OTP-4 | I | DB read exposes codes (AS-2c) | P-class ciphertext with purpose key `AUTH_SECRET_KEY` (AES-256-GCM, AAD `table.column#rowId`), deleted at view, expiry or cancel; sweep every minute (ADR-0026) | ST-PRIV-03 |
| T-OTP-5 | D | Brute force against the business | Out of Viadere's control; SDK verification helper enforces attempt caps and constant-time compare | ST-OTP-03 (SDK unit test) |

### 3.6 TOTP

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-TOTP-1 | I | Seed exfiltration through Viadere servers | Seeds never transit Viadere in plaintext: enrollment is QR scan on device, or (Phase B) an E2EE envelope (ADR-0007) to the device; validation refuses any plaintext `otpauth://` in delivery fields (ADR-0020 §6.3) | ST-TOTP-01 |
| T-TOTP-2 | E | Viadere advertised as TOTP verifier | No server-side TOTP verification (decision 3); partner TOTP codes are transport only, labelled `code_kind: totp` | ST-OTP-02 |
| T-TOTP-3 | I | Vault sync leaks seeds | Existing vault design (SECURITY §2.40, ADR-0008), sync off by default; unchanged | existing vault tests |

### 3.7 MFA: push MFA with number matching

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-MFA-1 | S | MFA fatigue: user approves an attacker-initiated sign-in | Number matching (user types the number shown on the requesting screen; "no number there → Deny"; paste and AutoFill disabled); equal-prominence Deny first; "This wasn't me" → signed report; fatigue warnings and acknowledgement gate; authority counts wrong numbers for authority flows (ADR-0022 §2, §5; ADR-0023 §3 step 6) | ST-MFA-01, ST-MFA-05, ST-AUTH-20 |
| T-MFA-2 | T | Transaction details altered between business and device | E2EE business-signed `ApprovalRequest` (SECURITY §2.54); server-visible mode labelled; `txn_digest` and `match` are in the device-signed JWS and verified by the business against **its** record (ADR-0022 §3) | ST-MFA-02 |
| T-MFA-3 | S | Replay of an approved result | Business consumes `aud‖kid‖challenge` once (existing `ApprovalVerifier`); relay CAS; `exp − iat ≤ 600 s` (devices sign 300 s) | ST-MFA-03 |
| T-MFA-4 | E | AS-1 relay reports "approved" | Business acts only on a verified JWS (existing rule, SECURITY §2.55); legacy unsigned interaction path is closed for the pilot and frozen (ADR-0022 §7) | ST-MFA-04, ST-GW-08 |
| T-MFA-5 | S | Real-time phishing proxy relays the number | Not stopped by number matching (documented, R-12); passkey bias recommends origin-bound WebAuthn for high risk (ADR-0022 §6) | ST-MFA-06 (documents expected pass-through) |
| T-MFA-6 | D | Attacker-controlled lockout through prompts, budgets or supersession | Budgets limit alerting, not availability: over budget the newest request is still created and reachable silently from the inbox; no request supersedes another unless both carry the same business `session_handle`, and the number the person types selects their own request from the group (S2-A2-9, ADR-0022 §5.2); `429` only for per-tenant aggregate floods; pause is per (business, customer), lasts ≤ 1 h, never blocks other businesses, and the customer can lift it in the app with biometric (ADR-0020 §8, ADR-0022 §5). Residual R-20 (business-side trigger rate) | ST-MFA-07, ST-MFA-10, ST-DLV-09 |
| T-MFA-7 | E | Low-assurance approve from Lock Screen or watch | Approve always foregrounds the app (fixes F-14); watch can only view, Deny and Report (ADR-0022 §8) | ST-MFA-08, ST-UX-06 |
| T-MFA-8 | I | Lock Screen shows number, amount or payee; business name shown to bystanders | Notification body is generic; number is never shown on the device (the user types it); amounts only inside the app after unlock; previews-hidden placeholder "You have a security item."; optional "Show business names on the Lock Screen" off switch; Android `VISIBILITY_PRIVATE` with a generic public version; interruption level `active`, never time-sensitive (ADR-0022 §5.5, §9) | ST-PRIV-05 |
| T-MFA-10 | D | Deny requires unlock, or is silently lost offline | Deny/This wasn't me actions have no `.authenticationRequired` and no foreground (iOS) and no `setAuthenticationRequired` (Android); offline Deny is not queued: local "Deny not sent yet. Open Viadere." and the item stays in the inbox (ADR-0022 §5.5-§5.6) | ST-MFA-11, ST-MFA-12 |
| T-MFA-9 | T | Deny visually subordinate to Approve (F-16) | Design-system rule: equal size, weight and contrast; Approve disabled until the number is entered (ADR-0022 §2.5) | ST-UX-02 |

### 3.8 PAY: payment step-up

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-PAY-1 | T | Amount, currency or payee changed | `txn_digest` over the displayed transaction (SECURITY §2.54) verified by the business | ST-PAY-01 |
| T-PAY-2 | E | Approval from a new or untrusted device | D1 required for high/critical; new-device cool-down; biometric key (existing) | ST-PAY-02 |
| T-PAY-3 | S | Fatigue on payments | 3-digit number matching for high/critical (ADR-0022 §4) | ST-PAY-03 |
| T-PAY-4 | T | Display spoofing in server-visible mode | High/critical requests require E2EE business-signed requests in the pilot (ADR-0022 §4.3) | ST-PAY-04 |

### 3.9 REC: recovery, device linking, phone ownership

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-REC-1 | E | Email or SMS recovery replaces a passkey (§26) | No email or SMS recovery route exists; recovery is codes + new passkey + 72 h hold (SECURITY §2.26); test asserts the absence of any such route (ADR-0023 §4) | ST-REC-01 |
| T-REC-2 | E | AS-1 fakes "recovery code accepted" to add a key | `recovery_started` needs a sealed code the authority verifies itself (codes registered only inside HPKE envelopes to the pinned `recovery-seal` key, ADR-0034); a start without one is `recovery_started_legacy`, its keys are never grant-capable, and it is refused for accounts with an authority set; 72 h authority-timed hold; any logged key can cancel; all of this ships before any authority-backed flag is enabled (ADR-0032 §3) | ST-REC-02, ST-REC-07, ST-REC-08, ST-REC-11, ST-REC-20, ST-AUTH-04 |
| T-REC-3 | D | AS-1 suppresses recovery notices or relays another account's or a stale head | App verifies the authority-signed head (pinned `device-statement-signing` keys, active + standby), requires its own key ids in it, refuses a lower `seq` or a head older than 15 min, and shows S-SEC-01 when it cannot get a valid head for over one hour online (ADR-0033 §2, ADR-0032 §3.4) (R-02) | ST-REC-03, ST-REC-09, ST-REC-12 |
| T-REC-4 | E | New device added without the user | D1 confirmation proof, 24 h cool-down, notices; key-log proof by a logged grant-capable `approvalBiometric` key with the device-add comparison code; no passkey assertion (ADR-0023 §3a, §4; ADR-0033 §4.1) | ST-REC-04, ST-REC-17, ST-REC-18 |
| T-REC-8 | E | AS-1 harvests recovery codes at registration, searches them offline from its own database and pepper, or pairs a genuine code with its own key at start (S2-A2-1, S1-A3-R01) | Authority codes are generated on the device and travel only inside HPKE envelopes (`DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`) to the pinned `recovery-seal` key, with purpose `info` and challenge `aad`; the api holds no hash of them and its legacy set is invalidated; the start seals the code with `new_kids` and every new key's PoP commits to the envelope digest; registration needs a D1-equivalent `approvalBiometric` key (ADR-0034, ADR-0032 §3). Residual R-23 | ST-REC-14, -15, -16, -21 |
| T-REC-9 | E | AS-1 relays the nonce of a `keylog_device_added`/`keylog_passkey_added` challenge into any passkey ceremony the victim performs on the api-served origin, adding the attacker's key (S2-A2-2) | WebAuthn assertions are accepted only for `oidc_login` and reduce-only `recovery_cancel`, with a per-purpose origin allow-list; every key-adding purpose needs a factor JWS by a logged grant-capable device key (ADR-0023 §3a) | ST-REC-17 |
| T-REC-10 | E | AS-1 substitutes its own keys in a genuine device add while the person approves on the old device (S2-A2-3) | The new device refuses a challenge whose `kids` are not exactly its own and shows a 6-digit code over the nonce and its `kids`; the person types it on the old device; the authority recomputes it from the stored entry (ADR-0033 §4.1) | ST-REC-10, ST-REC-18 |
| T-REC-11 | E | A key added by a legacy recovery upgrades itself to grant capability (S2-A2-7) | It cannot register a code set; grant capability returns only by an authority-verified recovery against a set registered before, or by an admin-job decision (ADR-0032 §3.3) | ST-REC-20 |
| T-REC-12 | E | An attacker key slipped into a genesis or imported entry confirms itself (S2-A2-4) | `enrollment_confirmed` carries `head_hash` and `seq`; keys become grant-capable only when every key of the entry confirmed the current head (ADR-0032 §1.4) | ST-AUTH-23 |
| T-REC-5 | S | Phone number hijack through MO spoofing or a victim-induced text (decision 9 proof) | MO nonce bound to account, device and keyed number hash; From must equal the claimed number; mandatory aggregator spoof indicator; an existing link is never displaced before cool-down and in-app no-objection; SMS-02 states the effect with UNLINK and STOP; per-number caps; MO-linked numbers get only on-ramp text; never an authenticator (ADR-0027) | ST-PH-01..05, ST-PH-08..11 |
| T-REC-6 | E | Phone link used as a factor or recovery | Phone link carries assurance `phone_control_mo`, which satisfies no `AssurancePolicy` level and is refused by recovery and by the authority (ADR-0027 §2) | ST-PH-06 |
| T-REC-7 | I | Account enumeration through link or recovery errors | Uniform errors (existing recovery `401`); phone begin answers the same for linked/unlinked numbers | ST-PH-07 |

### 3.10 AUTH: private grant/policy authority and signer

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-AUTH-1 | S | Any process in the VNet calls the authority | Internal-only environment; NSG admits 443 from `snet-cae` only; every call needs an Entra token with `aud = api://viadere-authority-<env>`, app role `Authority.Evidence.Submit`, and `oid` on the allow-list (`id-viadere-api`, `id-viadere-worker`) (ADR-0019 §4) | ST-AUTH-08 |
| T-AUTH-2 | S | Token alone treated as authorization | Token only gates access; every state change also needs device/passkey evidence (ADR-0023 §6) | ST-AUTH-02 |
| T-AUTH-3 | T | Evidence replay, cross-audience or reorder | `aud = urn:viadere:authority:<env>`, authority-issued `ach` + 256-bit nonce, `exp − iat ≤ 120 s`, `ach` consumed once (unique row) **after** all checks, `jti` of issued grants unique (ADR-0023 §3) | ST-AUTH-09, ST-GR-01..06 |
| T-AUTH-4 | T | Algorithm confusion, header injection (`jku`, `jwk`, `x5u`, `crit`, `none`) | Header allow-list exactly `alg, kid, typ`; `alg` fixed per `typ`; explicit `typ` per RFC 8725 §3.11 (ADR-0023 §2) | ST-GR-02 |
| T-AUTH-5 | E | Authority used as a signing oracle | No raw sign route; Key Vault `sign` is called only from the grant, token and log-head builders after policy evaluation (ADR-0023 §6) | ST-AUTH-02 |
| T-AUTH-6 | I | Key extraction | Signing keys non-exportable in Key Vault (HSM in standard); the authority process never holds signing key bytes. Exception: the active `recovery-seal` KEM private key is held in authority memory after a Key Vault unwrap (no ECDH in Key Vault; ADR-0034 §5; residual R-23) | ST-AUTH-10 |
| T-AUTH-7 | E | Policy changed by an ordinary workload | `policy/raise` only increases floors; lowering is admin-job only, reviewer-gated (single owner approval in staging, R-21; ADR-0019 §5, ADR-0028 §6.6) | ST-AUTH-06, ST-CI-08 |
| T-AUTH-8 | D | Authority outage | Fail closed: link service and OIDC unavailable; sign-up waits (no account without genesis, ADR-0032 §1.5); business-mode links wait on the device once the cached tenant record is older than 15 minutes (ADR-0031 §4, no denial); business-verified push MFA and delivery-only OTP continue | ST-AUTH-11, ST-ML-15 |
| T-AUTH-9 | E | Exfiltration from a compromised authority | Egress deny except named dependencies (Key Vault, Entra, Monitor, PostgreSQL, image registry), app-level outbound allow-list (ADR-0019 §4.4) | ST-AUTH-12 |
| T-AUTH-10 | R | Grant issuance denied later | `authority_grants` issuance record (jti, kid, aud, acr, sub hash, evidence `ach`) and authority audit chain, class E | ST-AUTH-13 |
| T-AUTH-11 | T | Database tampering by the api role | Separate database `viadere_authority`, role `viadere_authority`; `viadere_app` has no CONNECT; append-only triggers on key log and grants (ADR-0019 §4.5) | ST-AUTH-14 |
| T-AUTH-12 | E | Authority code path (bug, RCE in a dependency) used as a signing oracle via its managed identity | Custom sign-only Key Vault role; KMS `sign` reachable only through builders that take `VerifiedEvidence`; module scan test; Key Vault `AuditEvent` reconciliation against issuance records with alerts (ADR-0023 §6, ADR-0028 §2) | ST-AUTH-21 |
| T-AUTH-13 | D | New key version silently becomes current and is used before publication | Authority signs only with explicitly pinned versions whose thumbprints are in the published inventory; `nbf` on new versions (ADR-0028 §2) | ST-AUTH-22 |
| T-AUTH-14 | E | Worker identity submits evidence | Worker has only `Authority.Revocations` (ADR-0028 §9) | ST-AUTH-18 |
| T-AUTH-15 | I | Recorded seal envelopes opened later | Seal private key only wrapped at rest under a non-exportable KEK; unwrap-only role on the active KEK; standby KEK has no role before rollover; every `unwrapKey` reconciled against replica starts; retired seal keys destroyed (ADR-0034 §5). Residual R-23 (authority process compromise) | ST-AUTH-21, ST-CI-09 |
| T-AUTH-16 | D | Unauthenticated `/oidc/authorize` loads exhaust a tenant's challenge budget or Key Vault sign throughput shared with heads and grants (S2-A2-6) | No challenge on page load; challenge only after a method is chosen, behind per-IP and per-client edge limits; per-tenant challenge-signing bulkhead (ADR-0024 §4, ADR-0033 §2) | ST-OIDC-17, ST-AUTH-24 |
| T-AUTH-17 | T | A compromised active pinned key revokes the standby, or two keys revoke each other (S2-A2-5, S1-A3-R02) | Statement-family revocations only by the standby and only of the active key; seal-family only of the active seal key; sticky; standby as separate key objects with no role before rollover; loss-of-both fails closed (ADR-0033 §3) | ST-REC-13, ST-REC-19 |

### 3.11 OIDC: provider in staging

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-OIDC-1 | E | AS-1 forges an id_token | id_tokens signed only by the authority (`oidc-signing-rs256` / `-es256`) after evidence; api cannot sign (ADR-0024 §6) | ST-OIDC-01 |
| T-OIDC-2 | E | AS-1, a compromised site credential or one merged PR publishes an attacker key in JWKS | Discovery and JWKS are static files deployed only by `authority-publish.yml` in a reviewer-gated environment with its own `id.`-scoped Cloudflare token; CODEOWNERS on `Site/content/id/**`; a JWK is admitted only if its thumbprint is in the attested authority key inventory; independent monitor alerts on unknown `kid` (ADR-0024 §7) | ST-OIDC-02, ST-OIDC-15, ST-GR-07 |
| T-OIDC-3 | S | Code interception or injection | PKCE S256 required, `plain` refused; code single use, 60 s, bound to client, redirect URI, PKCE challenge and nonce; held by the authority (RFC 7636, RFC 9700 §2.1.1) | ST-OIDC-03 |
| T-OIDC-4 | T | Open redirect via `redirect_uri` | Exact string match against authority-held registrations; no wildcards; admin-only changes (RFC 9700 §2.1) | ST-OIDC-04 |
| T-OIDC-5 | S | Implicit or hybrid flow token leakage | `response_type=code` only; `response_mode=query` only (ADR-0024 §2) | ST-OIDC-05 |
| T-OIDC-6 | I | Cross-RP correlation | Pairwise `sub` per sector identifier (OIDC Core §8.1) computed by the authority | ST-OIDC-06 |
| T-OIDC-7 | E | acr/amr overstated | acr values defined per evidence type; push approval never claims phishing resistance (ADR-0024 §5) | ST-OIDC-07 |
| T-OIDC-8 | S | QR login relayed by a phisher | QR/app approval yields only `urn:viadere:acr:app`; clients needing phishing resistance require `urn:viadere:acr:passkey` (WebAuthn, origin-bound) (ADR-0024 §4) | ST-OIDC-08 |
| T-OIDC-9 | T | CSRF on authorize/consent | `state` passthrough required; consent form CSRF token; `__Host-` cookies; `frame-ancestors 'none'` | ST-OIDC-09 |
| T-OIDC-10 | E | Staging flag leaks to production | `OIDC_PROVIDER_ENABLED` refused at boot when `ENVIRONMENT=production` until an ADR change (ADR-0024 §1) | ST-OIDC-10 |
| T-OIDC-11 | S | AS-1 binds a victim's genuine, in-progress login to the attacker's RP session (swapped `code_challenge`/`state`; api serves the authorize page and WebAuthn origin) | Not prevented in staging: recorded as R-17, a named exception to the §13 metric, **limited to that single session**; a lasting key addition through the same origin is excluded (T-REC-9); removal before any production IdP (ADR-0024 §4) | ST-OIDC-16 (documents the residual; counts toward no §26 row) |
| T-OIDC-12 | S | Public-client code redemption with a swapped PKCE challenge; client-assertion audience injection; IdP mix-up | Confidential clients only (`private_key_jwt`); assertion `aud` = issuer string only; RFC 9207 `iss` in every authorization response (ADR-0024 §2, §6) | ST-OIDC-11..13 |
| T-OIDC-13 | D | `login_hint` used to bomb a person with prompts | `login_hint` pushes count against fatigue counters per (client, account) and are alert-limited (ADR-0024 §4) | ST-OIDC-14 |

### 3.12 CP: cloud control plane and CI

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-CP-1 | E | One CI credential deploys both api and authority (F-02, §9.2) | Separate deploy identity `id-gh-deploy-auth-<env>`, own resource group, own GitHub environment with required reviewers, federated subject pinned to environment **and** `job_workflow_ref` (ADR-0028 §6) | ST-CI-01 |
| T-CP-2 | E | api deploy identity runs an app as `id-viadere-authority` | Managed Identity Operator on the authority identity is granted only to the authority deploy identity (ADR-0028 §6) | ST-CI-02 |
| T-CP-3 | E | Infra apply identity is effectively Owner (F-03) | Re-scope the main apply identity to the four existing resource groups; authority resources in a separate OpenTofu root and apply identity (ADR-0028 §7) | ST-CI-04 |
| T-CP-4 | T | Malicious image deployed to the authority | Authority image built by the release workflow, cosign-verified by digest, SLSA provenance tied to a commit on protected `main` shown to the reviewer; branch protection and CODEOWNERS; agents push with an identity distinct from the reviewer's and Prevent self-review is on (ADR-0028 §6.4, §6.6). Staging is a single owner approval (R-21) | ST-CI-05, ST-CI-08 |
| T-CP-5 | T | Legacy Fly paths still deploy (F-10) | Removed (ADR-0029) | ST-CI-06 |
| T-CP-6 | T | DNS or Cloudflare route change points `id.` or JWKS elsewhere | Cloudflare changes through IaC only; alert on DNS/route changes; separate Cloudflare token for the site workflow (ADR-0024 §7, ADR-0028 §8) | ST-CI-07 |
| T-CP-7 | R | Silent RBAC or key-policy change | Activity-log alert rules on role assignments and Key Vault access/key operations in both vaults (Stage 6) | ST-CI-03 |
| T-CP-8 | E | Unreviewed JWKS publication through the site workflow | Site token has no `id.` scope; site workflow refuses `Site/content/id/**`; publication only via `authority-publish` (ADR-0024 §7, ADR-0028 §8) | ST-OIDC-15 |
| T-CP-9 | I | Data or backup pair created outside US regions (decision 13) | Azure Policy allowed locations (US) and `RESIDENCY-US` rule (ADR-0026 §3, ADR-0028 §5) | ST-CI-09 |

### 3.13 CON: consoles

| Id | STRIDE | Threat | Control | Test |
|---|---|---|---|---|
| T-CON-1 | E | Business Owner session stolen: registers phishing destination | Destination add needs a fresh passkey step-up (existing re-auth), notifies all Owners, new tenants get a 24 h hold (ADR-0021 §2.3) | ST-CON-01 |
| T-CON-2 | E | Operator console path to grant policy or clients | No console route exists; authority admin is a job, not a web page (ADR-0019 §5) | ST-CON-02 |
| T-CON-3 | E | Business edits security copy | Template catalog is Viadere-owned; business sets only bounded variables (`action_display`, reference) validated for length, NFC, no control/bidi characters (ADR-0020 §2) | ST-UX-01 |
| T-CON-4 | I | Console shows codes or URLs | Console delivery log shows status and ids only; P-class fields are never readable through the console (ADR-0026) | ST-CON-03 |
| T-CON-5 | E | Operator reads evidence without reason | Evidence access only through `export-dispute`-style audited jobs and the `security_auditor` role with step-up and reason (ADR-0026 §4) | ST-CON-04 |
| T-CON-6 | E | Business lowers its assurance requirement | Console writes go to the api, which can only call `policy/raise`; lowering requires a request reviewed in the admin job (ADR-0019 §5) | ST-CON-05 |

## 4. Attack trees

Leaves marked **[C]** are blocked by a control (id in brackets), **[R]** are accepted residual risks (section 8). An OR node succeeds if any child does; AND needs all.

### AT-1 Log in as an arbitrary customer at a business (goal of §13 formal metric)

```
AT-1 Valid login for customer V at business B without V's authenticator
├─ OR 1 Forge Viadere-asserted result (link service / OIDC)
│   ├─ 1.1 Sign with grant/OIDC key from api ................... [C] T-GW-1 (no key, no role)
│   ├─ 1.2 Ask authority to sign ............................... [C] T-GW-2 (no raw sign)
│   ├─ 1.3 Register attacker key for V, then sign evidence
│   │   ├─ 1.3.1 Write key into api DB ......................... [C] T-GW-3 (authority key log)
│   │   ├─ 1.3.2 Forged genesis / append for V ................. [R → C] open until ADR-0032 §1 ships (authority-minted ids, import of every id); [C] after
│   │   ├─ 1.3.3 Fake, harvested or key-swapped recovery ........ [R → C] stays [R] until ADR-0032 §3 and ADR-0034 ship and ST-REC-14..16, -21 pass (sealed codes the api never sees, bound to the new keys; legacy recovery never grant-capable); [C] after; R-23
│   │   ├─ 1.3.4 Redirect a victim passkey ceremony into a key add  [C] T-REC-9 (no passkey assertion adds a key, ADR-0023 §3a)
│   │   ├─ 1.3.5 Substitute keys in a genuine device add .......... [C] T-REC-10 (comparison code, ADR-0033 §4.1)
│   │   └─ 1.3.6 Attacker key beside victim keys at genesis ....... [C] T-REC-12 (every key confirms the same head)
│   ├─ 1.4 Map V's subject_ref / accountId to attacker evidence .. [C] T-GW-4 (binding check, ADR-0032 §2)
│   ├─ 1.5 Publish attacker JWKS ............................... [C] T-OIDC-2 (reviewer-gated publication, attested inventory, monitor)
│   ├─ 1.6 Add redirect URI / return URL to steal code .......... [C] T-GW-5, T-LS-2 (registration) + ADR-0033 (signed challenge, return_url in factor JWS)
│   ├─ 1.7 Bind V's genuine OIDC login to attacker RP session ... [R] R-17 (named §13 exception, staging only, single session)
│   └─ 1.8 Substitute a tenant destination key at registration .. [C] T-ML-9 (PoP + thumbprint in domain evidence)
├─ OR 2 Forge business-verified device evidence (push MFA)
│   ├─ 2.1 Relay says "approved" ................................ [C] T-MFA-4 (business verifies JWS)
│   ├─ 2.2 Substitute pairwise key at enrollment ................ [C] existing SECURITY §2.53 (business binds key; directory)
│   └─ 2.3 Legacy unsigned interaction path ..................... [C] ADR-0022 §7 (frozen, sunset)
├─ OR 3 Get V to approve (social)
│   ├─ 3.1 Fatigue / bombing ................................... [C] T-MFA-1 (number matching), T-MFA-6
│   ├─ 3.2 Real-time phishing relay of number ................... [R] R-12 (passkey bias recommended)
│   └─ 3.3 AS-1 + V approves attacker-initiated prompt ......... [R] R-03 (cross-device: number matching; same-device link service: code goes only to the signed, registered return URL)
├─ OR 4 Steal a bearer link / code
│   ├─ 4.1 From push payload .................................... [C] T-DO-1 (none present)
│   ├─ 4.2 From DB read ......................................... [C] T-OTP-4 (ciphertext, minutes)
│   ├─ 4.3 From logs/webhooks ................................... [C] T-DO-1
│   └─ 4.4 From AS-1 memory during the minutes window .......... [R] R-01
└─ OR 5 Compromise the authority itself or the control plane ... [R] R-11 (separate class)
```

### AT-2 Abuse a magic link

```
AT-2 Get V's browser or attacker's browser signed in via a link
├─ 2.1 Send link to a phishing host
│   ├─ unverified domain ....................................... [C] T-ML-1
│   ├─ open redirect on verified host .......................... [C] T-ML-2 (query check) + [R] R-06 (server-side redirects)
│   ├─ host confusion .......................................... [C] T-ML-3
│   ├─ AS-1 rewrite ............................................ [C] ADR-0031 (business-signed destination verified on device)
│   └─ AS-1 delivers attacker's own genuine signed link ........ [R] R-07' (login CSRF)
├─ 2.2 Consume or read the token
│   ├─ prefetch/preview ........................................ [C] T-ML-4
│   ├─ referrer/analytics ...................................... [C] T-ML-5
│   └─ push interception ....................................... [C] T-DO-1
└─ 2.3 Wrong device completion ................................. [C] T-ML-6 (confirm + business binding)
```

### AT-3 Cross-tenant action (§13 cross-tenant gate, §26)

```
AT-3 Tenant A acts on tenant B's request or customer
├─ read status of B's delivery by id ........................... [C] ADR-0020 §4 (tenant from credential; 404)
├─ cancel/complete B's delivery ................................ [C] same
├─ send as B ................................................... [C] tenant from API key + signature key ownership
├─ route to B's customer with A's subject_ref guess ............ [C] subject_ref pairwise per tenant (SECURITY §2.30)
├─ receive B's webhooks ........................................ [C] subscriptions per tenant; v2 signature binds tenant (ADR-0025)
└─ redeem B's link code / OIDC code ............................ [C] authority binds code to link client / OIDC client
```

### AT-4 Misuse a signing key

```
AT-4 Get a valid signature from an authority key on attacker content
├─ api identity calls Key Vault sign ........................... [C] no role on kv-vdr-auth
├─ api deploy identity redeploys an app as authority identity .. [C] T-CP-2
├─ CI build poisons authority image ............................ [C] T-CP-4 (reviewed digest deploy) + [R] R-11 (malicious merged code)
├─ authority logic bug signs unverified evidence ............... [C] ST-GR-* forged-proof suite; A2+A3 review
└─ Key Vault admin exports or uses key ......................... [C] non-exportable; [R] R-11 (admin can grant itself sign)
```

### AT-5 Hijack a phone number link (decision 9)

```
AT-5 Link V's number to attacker's account
├─ spoof MO From = V's number with attacker's nonce
│   ├─ nonce bound to claimed number + account ................. needs spoof
│   ├─ aggregator spoof indicator ............................. [C] ADR-0027 §1.3 (hard fail)
│   ├─ spoof succeeds anyway ................................... [R] R-13 (carrier/aggregator spoofing)
│   ├─ displace V's existing link ............................. [C] ADR-0027 §1.3 (cool-down + in-app no-objection)
│   └─ V receives MT notice, replies UNLINK during cool-down ... [C] ADR-0027 §1.5
├─ persuade V to send the nonce text ............................ [R] R-13b (SMS-02 states the effect; caps; never a factor)
├─ port or SIM-swap V's number then link ........................ [R] R-13 (whoever holds the number controls it)
└─ use the link to authenticate ................................. [C] T-REC-6 (never an authenticator)
```

### AT-6 Lock a user out (DoS as an attack)

```
AT-6 Prevent V from signing in at B
├─ prompt flood ................................................ [C] T-MFA-6 (pause ≤ 1 h, per business, user can lift)
├─ exhaust per-subject budgets ................................. [C] T-MFA-6 (budgets limit alerts; inbox still reachable) + [R] R-20
├─ supersede V's genuine prompt with attacker-triggered ones ... [C] T-MFA-6 (session_handle-only supersession; typed number selects) + [R] R-20 (retry on collision)
├─ flood /oidc/authorize to exhaust challenge budgets .......... [C] T-AUTH-16 (no challenge on load; edge limits; bulkhead)
├─ make destination checks fail to count as denials ........... [C] T-ML-10 (availability failures make no server call; none counts toward the pause)
├─ induce an outage at sign-up to limit the account forever .... [C] ADR-0032 §1.5 (no account without genesis; the app retries)
├─ revoke the pinned standby with a stolen active key ......... [C] T-AUTH-17
├─ wrong-number flood .......................................... [C] wrong entries count per request, not per account
├─ recovery begin flood ........................................ [C] existing per-ID budgets (SECURITY §2.26)
├─ authority outage ............................................ [R] availability (T-AUTH-8)
└─ revoke V's keys via AS-1 .................................... [R] R-14 (reduce-only actions are allowed to the api; detectable)
```

## 5. Red-team scenarios (spec §26) mapped to controls and tests

| # | Scenario (§26) | Expected result | Controls | Stage 7 tests |
|---|---|---|---|---|
| RT-1 | Compromise the public delivery gateway: cannot mint MFA success, alter grant policy, retrieve protected signing keys or read other tenants' data | No grant/id_token/link result; no policy lowering; no authority key; tenant isolation holds for **requests through the API** and at the authority boundary. Note: under AS-1 the api DB is readable, so "read other tenants' data" is limited to what the api DB holds; P-class secrets are ciphertext under a key the api holds (R-01) | T-GW-1..5, T-GW-13, -14, T-REC-8..12, T-AUTH-1..7 | ST-GW-01, ST-AUTH-02, ST-AUTH-15, ST-AUTH-23, ST-LS-07, ST-REC-07, ST-REC-14, ST-REC-15, ST-REC-17, ST-REC-18, ST-AUTH-19 |
| RT-2 | Steal a webhook signing secret: cannot create an authentication grant or impersonate Viadere's issuer | Webhooks carry ids only; results are fetched and verified (device JWS or authority grant); a forged webhook can at most cause a fetch that fails verification | ADR-0025 §5, ADR-0023 | ST-WH-04 |
| RT-3 | Replay a previously approved MFA assertion: rejected by challenge id, audience, expiry and single-use state | Business verifier and relay refuse; authority refuses factor JWS replay | T-MFA-3, T-AUTH-3 | ST-MFA-03, ST-AUTH-09 |
| RT-4 | Swap business destination domain or follow open redirects: blocked before handoff | Create refused (`422 destination_not_allowed`); open refused if policy changed since create; under AS-1 the device refuses any URL not matching the business-signed statement | T-ML-1..3, T-GW-6 | ST-ML-03..05, ST-ML-10..13 |
| RT-5 | Intercept a push payload: no bearer credential | Payload has only `aps` generic alert, category, opaque `adl`/`req` id | T-DO-1 | ST-PRIV-02 |
| RT-6 | Compromise one business tenant: cannot send as another tenant or query another's status | `404` on foreign ids; no cross-tenant routing; authority takes tenant from client records | AT-3 | ST-TEN-01..05, ST-AUTH-17 |
| RT-7 | Compromise ordinary admin account: cannot change signing policy or enroll a new privileged issuer without independent authorization | No console path; admin job behind reviewers, CODEOWNERS and Prevent self-review (single owner approval in staging, R-21); new authority key needs crypto-officer group + `authority-publish` with attested inventory | T-CON-2, T-CP-* | ST-CON-02, ST-AUTH-07, ST-CI-08 |
| RT-8 | Email/SMS recovery against a high-assurance account: cannot silently replace a passkey | No email/SMS recovery exists; code recovery needs a sealed, authority-verified code (never seen by the api) bound to the new keys for grant capability, has the 72 h hold and authority-timed log entry | T-REC-1, T-REC-2, T-REC-8 | ST-REC-01, ST-REC-07, ST-REC-08, ST-REC-14, ST-REC-15 |
| RT-9 | Flood a user with MFA prompts: contained without indefinite lockout | Warn from 3/h with acknowledgement gate; over budget: silent inbox delivery (never refusal for the subject); no supersession without a matching `session_handle`, typed number selects the request; pause after 3 denials ≤ 1 h; user can lift; other businesses unaffected; OIDC authorize floods create no challenges | T-MFA-6, T-AUTH-16 | ST-MFA-07, ST-MFA-10, ST-DLV-09, ST-OIDC-17 |
| RT-10 | Crash during delivery or callback: no duplicate authorization, bounded retries | Outbox + CAS; webhook retries bounded (existing schedule, then DLQ); receiver dedup covers the whole retry horizon (≥ 72 h); authority `ach` single use | T-DO-2 | ST-DLV-01, ST-DLV-02, ST-WH-05, ST-WH-06 |

Every row's tests fail if its control is removed (S1-A2-10). ST-MFA-06 and ST-OIDC-16 document residuals and count toward no row.

## 6. Security test catalogue (run in Stage 7)

Location key: **S** = `Server/Tests` (SQLite and PostgreSQL, per CLAUDE.md rule 6), **C** = `Packages/ViadereCore/Tests`, **K** = `Packages/ViadereKit/Tests`, **B** = `Packages/ViadereBusinessSDK/Tests`, **A** = new `Server/Tests/ViadereAuthorityTests`, **TS** = `tests/security/` (new, spec §25: black-box scripts against staging, Python), **D** = real-device check (A6/A7/A13), **I** = IaC policy test (`Infra/azure/tests`, `policy_check.py`), **W** = TypeScript SDK tests, **V** = cross-language vector in `docs/protocol/vectors/`.

| Test | Asserts | Loc |
|---|---|---|
| ST-GW-01 | With the api's full configuration and identity (staging), no code path or credential produces a JWS that verifies under any key in the static grant/OIDC JWKS | TS, I |
| ST-GW-02 | api process has no `AZURE_KEY_VAULT_*` reference to an authority key; boot refuses one | S |
| ST-GW-03 | api DB write of a new device key for account X does not make authority accept evidence from that key | A |
| ST-GW-04 | api-supplied `subject_ref` in a challenge is ignored; grant `sub` derives from the signing key's account | A |
| ST-GW-05 | api cannot call any authority route that lowers policy or adds a client (route absent; `404`) | A |
| ST-GW-06 | Authority refuses a challenge for an unregistered `return_url` | A |
| ST-GW-07 | (rewritten) The api submits `POST challenges` with its own display text and business name; the authority ignores it, builds the display from its records, and evidence whose `display_digest` covers the api text is refused. Fails if the authority accepts api display text | A |
| ST-GW-08 | With auth pilot flags on, any legacy `authenticate`/`authorize` issue for a live tenant without entitlement is `403`; no new legacy entitlement can be granted after pilot start | S |
| ST-GW-09 | Live API key without a valid RFC 9421 signature (or Tier E cert) is refused on auth endpoints; test key without signature accepted only for sandbox subjects | S, V |
| ST-GW-10 | Unknown members (including `tenant_id`), oversized bodies, bad enums refused with `422` | S |
| ST-GW-11 | Idempotency: same key + same body replays; same key + different body `409`; record contains request digest and signing key id | S |
| ST-GW-12 | Request to the api without edge token from inside the environment is refused (existing EdgeLock) | S |
| ST-TEN-01 | Tenant A `GET/cancel/complete` on tenant B's delivery id → `404`, no state change, audit `auth_delivery.cross_tenant_refused` | S |
| ST-TEN-02 | Tenant A cannot create a delivery for B's subject_ref (`404 not_deliverable`, same as unknown) | S |
| ST-TEN-03 | Tenant A webhook subscription never receives B's events | S |
| ST-TEN-04 | Unknown subject, no device, opted-out, frozen: indistinguishable response body and status | S |
| ST-TEN-05 | Tenant A cannot redeem B's link code or exchange B's OIDC code | A |
| ST-TEN-06 | Delegate devices never receive, list, open or decide a principal's auth delivery or approval | S |
| ST-DLV-01 | Kill the worker between outbox write and send: exactly one send after restart; CAS prevents double transition | S |
| ST-DLV-02 | Concurrent `open` calls: one returns the URL, the other `409 already_opened`; secret row deleted once | S |
| ST-DLV-03 | `SENT` and `DELIVERED`/`OPENED` never emit `completed`; only business `complete` or authority redemption does | S |
| ST-DLV-04 | No SMS adapter is selectable for any auth method (contract + config refusal) | S |
| ST-DLV-05 | Email fallback only when request names `fallback.email` and tenant policy allows; emits `auth.delivery.fallback_used` | S |
| ST-DLV-06 | APNs failure: delivery stays retrievable in inbox; status not advanced past `sent`; no success claimed | S |
| ST-DLV-07 | New auth rate-limit namespaces fail closed when the rate-limit DB is unavailable | S |
| ST-DLV-08 | Open after `expires_at` or after cancel → `410`; secret already purged | S |
| ST-DLV-09 | After an attacker exhausts every per-subject budget for a victim, a magic link the victim requests is still created and openable from the inbox (silent delivery) | S |
| ST-ML-03 | Destination on an unverified domain, or verified domain without `auth_links` purpose, or host not in allow-list → `422 destination_not_allowed` | S |
| ST-ML-04 | Query value containing an absolute or scheme-relative URL to a non-allowed host (raw and percent-encoded once) → refused | S, V |
| ST-ML-05 | Host-confusion corpus (userinfo, `@`, backslash, U-label, mixed-script, IP literal, port, trailing dot, `%2e`) refused | C, V |
| ST-ML-06 | NSE and push payload never contain the URL; app does not open without a confirm tap (UI test) | K, D |
| ST-ML-07 | Harness redemption page check: `Referrer-Policy: no-referrer`, no third-party subresources (advisory report for partners) | TS |
| ST-ML-08 | App displays the host parsed from the URL it will open even when the display payload names another host | K |
| ST-ML-09 | "Continue on this device" path never calls any session-transfer endpoint | K |
| ST-ML-10 | AS-1 rewrites any byte of the stored URL after create; the device refuses to open it and sends `destination_unverified` | K, S |
| ST-ML-11 | Device refuses: missing signature; key not in the authority record; key revoked within 15 min; expired statement; `iat` window exceeded; wrong `brq` or `purpose`; replayed `jti`; host not in `allowed_hosts` | K, V |
| ST-ML-12 | Device refuses an api-fabricated `viadere-tenant-keys+jws` signed by any non-pinned key, and a stale (> 15 min) one | K, V |
| ST-ML-13 | Business-mode create without a signature → `422 destination_signature_required` while the flag is on; the pilot release check refuses the flag off | S |
| ST-ML-14 | The `/l/` and `/h/` "no longer used" screen never calls `redeemHandoff`; opening a URL never redeems on handling | K |
| ST-ML-15 | A stale or absent tenant record, or device clock skew, leaves the delivery open, makes no server call and shows S-LINK-11/-12; an integrity failure sends `destination_unverified`, alerts at high priority and never counts toward the pause; a lower-`seq` record is refused | K, S |
| ST-LS-01 | Redemption result verifies only under the grant JWKS; forged/unsigned/other-key results refused by SDK verifiers | B, W, V |
| ST-LS-02 | Unregistered or near-match return URL (trailing slash, case, extra query) refused by authority | A |
| ST-LS-03 | Code reused, expired (> 120 s), or redeemed by another link client → refused | A |
| ST-LS-04 | Redemption without matching PKCE verifier refused | A |
| ST-LS-05 | Cross-device path without correct number → no grant | A, D |
| ST-LS-06 | Code observed at redemption cannot be redeemed with a different verifier | A |
| ST-LS-07 | A substituted `return_url` (at challenge, in transit to the device, or in the factor JWS) → evidence refused and no code registered | A, K |
| ST-LS-08 | An api-modified display (business name, host) → refused by the device (statement signature) and by the authority (digest) | A, K |
| ST-OTP-01 | Code is fetched only via device-signed `GET` after open; not in push, NSE, logs | S, K |
| ST-OTP-02 | No Viadere endpoint verifies a business OTP or TOTP (route catalog test) | C |
| ST-OTP-03 | SDK verification helper enforces attempts and constant-time compare | B, W |
| ST-TOTP-01 | Delivery containing `otpauth://` (any case, any field, percent-encoded) refused | S |
| ST-MFA-01 | Approve disabled until the typed number equals the request's code; wrong entries counted; 3 wrong → signed deny `number_mismatch` | K, D |
| ST-MFA-02 | Business verifier refuses JWS whose `match` or `txn_digest` differs from its record | B, V |
| ST-MFA-03 | Second presentation of the same JWS → `replayed` (verifier) and `replay_detected` (relay) | B, S |
| ST-MFA-04 | Business integration example acts only on verified JWS; relay `status` alone never unlocks (harness) | TS |
| ST-MFA-05 | (rewritten) Fatigue thresholds: warning and acknowledgement gate from 3/h; above 6/h or over any per-subject budget the request is created, collapsed and delivered **silently** (no alert push, no `429`); `429` only for per-tenant aggregate floods; pause after 3 denials/reports; supersession only with a matching `session_handle` | S |
| ST-MFA-06 | Documented: a relayed number defeats number matching (test records pass-through so that copy and policy keep the residual visible). Counts toward no §26 row | TS |
| ST-MFA-10 | After an attacker exhausts every per-subject budget, a push sign-in the victim initiates is still completable from the inbox; and while an attacker creates a request every N seconds at the business's throttle rate (no or a different `session_handle`), the victim's own request is never superseded, the number the victim types selects it, and no attacker request is approved | S, K |
| ST-MFA-11 | iOS category option sets: Deny and This wasn't me have no `.authenticationRequired`/`.foreground`; Review/Open have `.foreground`; Android Deny has no `setAuthenticationRequired`; PendingIntents immutable, receivers/activities not exported | C, K, D |
| ST-MFA-12 | Offline Deny: no queued decision; local "Deny not sent yet" notice; item stays in inbox; business sees `pending` until expiry | K, D |
| ST-MFA-13 | Number field refuses paste and AutoFill, is never prefilled, announces wrong entries to VoiceOver | K, D |
| ST-MFA-07 | Pause is per (business, customer), ends ≤ 1 h, can be lifted with biometric proof; other businesses unaffected | S |
| ST-MFA-08 | Approve from notification always foregrounds the app; no approve from Lock Screen | K, D |
| ST-MFA-09 | High/critical approval refuses `approvalUserPresence`; requires `approvalBiometric` | S |
| ST-PAY-01 | Changing amount/currency/payee/reference breaks verification | B, V |
| ST-PAY-02 | Device in cool-down or D0 cannot approve high/critical | S |
| ST-PAY-03 | High/critical requests carry 3-digit codes; 2-digit refused for them | S |
| ST-PAY-04 | High/critical server-visible request refused in pilot configuration | S |
| ST-REC-01 | Route catalog has no email or SMS recovery; recovery with only an email or phone is impossible | C, S |
| ST-REC-02 | Authority refuses `recovery_activated` before 72 h or after a cancel by any logged key | A |
| ST-REC-03 | App shows pending recovery from a signed key-log head when the push is suppressed; refuses stale heads | K |
| ST-REC-04 | New device key without logged proof is not accepted by authority; existing passkey/D1 rules unchanged | A, S |
| ST-REC-06 | Revoked device: pending approvals and deliveries for it are cancelled; its keys rejected by authority | S, A |
| ST-REC-07 | Simulated AS-1 starts a recovery with no authority-verified code; after 72 h with no cancel the authority issues no grant and no id_token for the account | A |
| ST-REC-08 | A legacy-code recovery yields keys the authority marks non-grant-capable | A |
| ST-REC-09 | The app shows S-SEC-01 when valid heads are withheld for over one hour while online; an absent head is never "no pending recovery" | K, D |
| ST-REC-10 | A `device_added` display whose `kids` differ from the entry, a missing PoP by a new key, an approving device whose `account_ref` differs from the challenge's, or an approving key outside the entry's account → refused | A, K |
| ST-REC-11 | Authority recovery-code attempt limits; a used code is refused | A |
| ST-REC-12 | App refuses a head for another account, with a lower `seq`, stale, with the wrong `typ`, or with a wrong `iss` or `env` | K, V |
| ST-REC-13 | App refuses statements signed by a `kid` listed in a verified revocation list; the revocation is sticky across restarts | K |
| ST-REC-14 | AS-1 (simulated api with full DB and `SERVER_PEPPER`) records every byte relayed at registration and start; it cannot then start a non-legacy recovery; a replayed envelope against another challenge or account, or with a substituted nonce or `new_kids`, is refused (ADR-0034) | A |
| ST-REC-15 | A start whose PoP keys differ from the sealed `new_kids` is refused; an api-substituted key never becomes active; activation adds exactly the sealed `kids` | A |
| ST-REC-16 | `recovery_codes_set` by an `approvalUserPresence` key or a key in cool-down is refused | A |
| ST-REC-17 | A UV passkey assertion over a `keylog_device_added`, `keylog_passkey_added`, `recovery_codes_set` or `enrollment_confirmed` nonce is refused whatever its origin; an `oidc_login` assertion from an origin not on the allow-list is refused | A |
| ST-REC-18 | AS-1 substitutes keys in a genuine device add; the new device refuses the challenge or shows a code that does not match the authority's expected code; no key is appended | A, K |
| ST-REC-19 | A statement-family revocation signed by the active key, or naming the standby, is ignored; a seal-family list naming the seal standby is ignored; a valid list moves verification or sealing to the standby | K, V |
| ST-REC-20 | A key added by a legacy recovery cannot register a code set; a legacy start for an account with an active authority set is refused | A |
| ST-REC-21 | After registration, the api database, logs and `SERVER_PEPPER` contain no value that verifies an authority code; the api's legacy rows for the account are `invalidated` | S, A |
| ST-PH-01 | MO with right nonce from a different From number → no link | S |
| ST-PH-02 | MO nonce expired, reused, or for another account → no link | S |
| ST-PH-03 | New link is not a routing identity until cool-down ends or a trusted-device proof confirms | S |
| ST-PH-04 | MT notice sent on link; `UNLINK` reply revokes and notifies the account | S |
| ST-PH-05 | No outbound SMS contains a code, `/l/` or `/h/` token, or approval wording (outbound corpus test) | S, C |
| ST-PH-06 | `phone_control_mo` satisfies no `AssurancePolicy` level; authority and recovery refuse it | C, A |
| ST-PH-07 | Begin responses and the MO webhook path identical for linked, unlinked, opted-out numbers and every failure | S |
| ST-PH-08 | Spoofed or victim-induced MO against a linked number leaves the existing link in place until cool-down and in-app no-objection | S |
| ST-PH-09 | UNLINK / re-link churn on one number is limited, alerted and notified in app | S |
| ST-PH-10 | Positive aggregator spoof indicator → no link | S |
| ST-PH-11 | A `phone_control_mo` number receives no interaction content over SMS | S |
| ST-AUTH-01 | `id-viadere-api` has no role on `kv-vdr-auth` or its keys (plan-time and live) | I |
| ST-AUTH-02 | Authority exposes no route that signs caller-supplied bytes; fuzz all routes | A |
| ST-AUTH-03 | Key-log append for existing account without proof → refused | A |
| ST-AUTH-04 | Key-log proof by a revoked or not-yet-usable key → refused | A |
| ST-AUTH-05 | = ST-GW-04 at the authority boundary | A |
| ST-AUTH-06 | `policy/raise` with a lower value → `422`; no lowering route | A |
| ST-AUTH-07 | OIDC client or link client change only via admin job; api-role token refused | A |
| ST-AUTH-08 | Calls without token, with wrong audience, wrong role, unknown `oid`, expired token → `401/403`; NSG refuses non-`snet-cae` sources | A, I |
| ST-AUTH-09 | Factor JWS replay, wrong `aud`, wrong `ach`, wrong nonce, `exp − iat > 120`, future `iat` → refused; `ach` consumed only after all checks | A, V |
| ST-AUTH-10 | Key Vault keys have `exportable=false`; authority never logs or holds private bytes | I |
| ST-AUTH-11 | Authority down: link-service and OIDC fail closed with the outage copy; push MFA unaffected | S, TS |
| ST-AUTH-12 | Authority egress to an arbitrary internet host fails (network) and is refused by the outbound guard (app) | TS, A |
| ST-AUTH-13 | Every issued grant/token has an issuance record and audit event with jti and kid | A |
| ST-AUTH-14 | `viadere_app` cannot connect to `viadere_authority`; UPDATE/DELETE on key log refused | A, I |
| ST-AUTH-05a | Valid evidence from account A with `accountId = V` → refused and alerted | A |
| ST-AUTH-15 | Genesis has no account-id field; requests naming an imported or non-minted id are refused; during a simulated authority outage onboarding creates no consumer row (no api path creates one without a minted id); concurrent forged genesis cannot attach keys to the real account | A, S |
| ST-AUTH-16 | The api identity cannot add an `authority_tenant_keys` row or host (no route, `404`); the admin job refuses a registration without a valid PoP JWS, without the key's thumbprint in the attested DNS/well-known evidence for every host, or with `not_after` beyond 13 months | A |
| ST-AUTH-17 | api-supplied tenant or audience that differs from the client record is refused (tenant) or has no effect (grant `aud`/`tid` from the record) | A |
| ST-AUTH-18 | A worker token on `evidence` → `403`; on `revocations` → allowed | A |
| ST-AUTH-19 | An api token cannot read another tenant's link clients, consents, grants or audit through any authority route; only signed heads and tenant records are readable | A |
| ST-AUTH-20 | Signature-valid factor JWS with a wrong `match` increments the counter; the 3rd fails the challenge; invalid signatures do not | A |
| ST-AUTH-21 | Module scan: no KMS `sign` call outside the builders; Key Vault sign reconciliation alerts on an injected unmatched signature | A, I |
| ST-AUTH-22 | Authority refuses to start or switch to a key version whose thumbprint is not in the published inventory (app-pinned constants for `device-statement-signing` and `recovery-seal`) | A |
| ST-AUTH-23 | `enrollment_confirmed` with a stale `head_hash`/`seq` is refused; a genesis entry with an extra attacker key makes no key grant-capable unless every key confirmed the same head; unconfirmed imported keys stay non-grant-capable | A |
| ST-AUTH-24 | A challenge flood for one tenant leaves heads, tenant records, revocation lists, grants and other tenants' challenges unaffected | A |
| ST-GR-01 | Grant JWT claims exactly as ADR-0023 §5; SDK verifier checks `iss`, `aud`, `typ`, `exp`, `jti` single use | B, W, V |
| ST-GR-02 | `alg:none`, `HS256` with public key as secret, `jku/jwk/x5u/crit` headers, `kid` path traversal → refused | A, B, W, V |
| ST-GR-03 | Cross-JWT confusion: id_token presented as grant (and vice versa) refused by `typ` and `iss` | B, W, V |
| ST-GR-04 | Non-canonical payload or duplicate JSON members refused | C, V |
| ST-GR-05 | Clock skew bounds (±60 s) enforced | A, B |
| ST-GR-06 | Low-S normalisation: both encodings verify, replay keys never on signature string | C |
| ST-GR-07 | An unknown `kid` in the live grant or OIDC JWKS raises a monitor alert | TS |
| ST-OIDC-01 | id_token verifies only under static JWKS; api-signed token refused by conformance RP | TS |
| ST-OIDC-02 | Discovery and JWKS served from Workers static assets; api hostname path for them returns `404` | TS |
| ST-OIDC-03 | Missing/`plain` PKCE, reused code, code > 60 s, code for other client/redirect → `invalid_grant` | A, TS |
| ST-OIDC-04 | Redirect URI not exactly registered → error page, no redirect | TS |
| ST-OIDC-05 | `response_type` other than `code`, `response_mode` other than `query` → `unsupported_response_type` | TS |
| ST-OIDC-06 | Same account at two sectors → different `sub`; same sector → stable | A |
| ST-OIDC-07 | acr/amr mapping per evidence type exactly as ADR-0024 §5 | A |
| ST-OIDC-08 | Client requiring `urn:viadere:acr:passkey` cannot be satisfied by app approval | A, TS |
| ST-OIDC-09 | Missing `state`/`nonce`, CSRF token mismatch, framing → refused | TS |
| ST-OIDC-10 | `OIDC_PROVIDER_ENABLED=true` with `ENVIRONMENT=production` refuses boot | S |
| ST-OIDC-11 | `token_endpoint_auth_method=none` and public-client registration are refused | A, TS |
| ST-OIDC-12 | Client assertion with `aud` = token endpoint URL, or an array → `invalid_client` | A, V |
| ST-OIDC-13 | `iss` present in success and error authorization responses; metadata advertises it | TS |
| ST-OIDC-14 | `login_hint` prompts above the budget are not alerted | A, S |
| ST-OIDC-15 | An unreviewed change to `Site/content/id/` cannot deploy (site workflow refuses; publish needs the environment); a JWK not in the attested inventory is refused | I, TS |
| ST-OIDC-16 | Documents R-17: with an api-controlled authorize page, a genuine login can be bound to another RP session (counts toward no §26 row) | TS |
| ST-OIDC-17 | Unauthenticated `/oidc/authorize` loads create no authority challenge and no Key Vault sign; method-choice POSTs above the per-IP or per-client limit get OIDC-11 and create nothing | A, TS |
| ST-WH-01 | v2 signature covers method, path, host, timestamp, event id, tenant, key id, body digest; changing any breaks it | C, B, W, V |
| ST-WH-02 | Receiver window 300 s; durable dedup refuses repeated event id | B, W |
| ST-WH-03 | `auth.*` events only on v2 subscriptions | S |
| ST-WH-04 | Forged webhook with stolen secret cannot yield a verified result (fetch + verify fails) | TS |
| ST-WH-05 | Retry schedule bounded, then DLQ; dedup on event id | S |
| ST-WH-06 | An event re-delivered at the final retry offset is deduplicated (dedup horizon derived from the Core backoff table) | C, B, W |
| ST-WH-07 | Two `v2=<kid>:<mac>` entries each verify with their own secret; duplicate `kid`, two `t=`, LF in any field → malformed | C, B, W, V |
| ST-CI-01 | Federated credential subjects: api deploy identity cannot obtain a token in the authority environment and vice versa | I |
| ST-CI-02 | Managed Identity Operator on `id-viadere-authority` held only by `id-gh-deploy-auth-<env>` | I |
| ST-CI-03 | Activity-log alerts exist for role assignments, Key Vault key operations and policy changes in both vaults | I |
| ST-CI-04 | Main apply identity has no role on `rg-viadere-<env>-auth` | I |
| ST-CI-05 | Authority deploy verifies cosign signature and digest; unsigned image refused | I, TS |
| ST-CI-06 | No workflow references `flyctl`, `FLY_API_TOKEN`, Neon or GCP KMS | I |
| ST-CI-07 | Cloudflare route/DNS for `id.` and JWKS managed in IaC; drift job flags manual changes | I |
| ST-CI-08 | A run triggered by the reviewer's own identity cannot approve itself; CODEOWNERS exists and code-owner review is enforced on authority paths and `Site/content/id/**` | I |
| ST-CI-09 | `RESIDENCY-US`, `AUTH-KEY-BACKUP`, `AUTH-SIGNER-ROLE` (incl. unwrap only on `recovery-seal-kek`), `AUTH-STANDBY-ROLE`, `AUTH-REVOCATIONS-ROLE`, `GHCR-NO-PAT` policy rules fail on violating plans | I |
| ST-CON-01 | Destination add requires fresh passkey, notifies Owners, holds young tenants 24 h | S |
| ST-CON-02 | Operator console has no route touching authority policy, clients or keys | S |
| ST-CON-03 | Console delivery log never renders P-class fields | S |
| ST-CON-04 | Evidence access requires `security_auditor`, step-up and reason; audited `evidence.accessed` | S |
| ST-CON-05 | Business console "require stronger" maps to `policy/raise`; "weaken" creates a review request only | S |
| ST-PRIV-01 | Logger and telemetry initializer emit only allow-listed fields on auth, phone-link and OIDC routes (unit test: an unknown field and a query string are dropped); plus a scan over push payloads, logs (App Insights export), **Cloudflare log export**, the authorize URL path, webhooks, queue envelopes, crash reports for URLs, codes, `otpauth`, `login_hint`, phone numbers, emails in a full pilot run | S, TS |
| ST-PRIV-02 | APNs payload schema: only allowed keys (`aps`, `cat`, `adl`/`req`, opaque thread id) | S |
| ST-PRIV-03 | `viadere_app` DB dump contains no plaintext URL or code (only ciphertext) during an open delivery, none after expiry | S |
| ST-PRIV-04 | Retention sweeps delete P within one minute of terminal state; T after 30 days; E per ADR-0026 table | S |
| ST-PRIV-04b | Restore runbook: a restored backup re-runs sweeps and tombstones before serving | S |
| ST-PRIV-05 | Lock Screen: no code, number, amount, payee, URL; preview hidden follows the system setting; placeholder text "You have a security item."; interruption level `active`; Android `VISIBILITY_PRIVATE` with generic public version | D |
| ST-PRIV-06 | Deletion test per new table (auth, authority, consents, phone-link MO); export lists every store by category | S, A |
| ST-UX-01 | Business cannot change security copy, warning hierarchy or button roles; brand kit cannot restyle Deny | S, K |
| ST-UX-02 | Deny and Approve are one component with equal size, weight, type and contrast, neutral palette, Deny first in layout and reading order, at all Dynamic Type sizes up to AX5; This wasn't me is a ≥ 44 pt button in the footer; no slide-to-approve | K, D |
| ST-UX-03 | Approve never visually dominant when context is missing (server-visible label shown) | K |
| ST-UX-04 | OTP screen shows the "never share" line and the business name | K |
| ST-UX-05 | Auth deliveries/approvals never start a Live Activity | S |
| ST-UX-06 | Watch shows Deny and "This wasn't me" only for auth/payment items | K, D |

## 7. Stop-ship rules (spec §27) and the evidence that clears each

| Rule | Cleared by |
|---|---|
| A single ordinary public service can independently issue a successful authentication grant | ST-GW-01, ST-AUTH-02, ST-AUTH-05a, ST-AUTH-15, ST-AUTH-23, ST-LS-07, ST-REC-07, ST-REC-14, ST-REC-15, ST-REC-17, ST-REC-18, ST-REC-21, ST-AUTH-19, ST-GW-08 (legacy path frozen), ST-CI-01..02, ST-OIDC-15; R-17 is the named staging exception for OIDC, limited to single-session binding |
| A link token appears in push payloads or logs | ST-PRIV-01..03, ST-ML-06, ST-OTP-01 |
| A verified business domain can be bypassed | ST-ML-03..05, ST-ML-10..13, ST-LS-02, ST-LS-07; residual R-07' only (A2 ruling; the revision 1 interpretation is withdrawn) |
| Cross-tenant access is possible | ST-TEN-01..06, ST-AUTH-17, ST-AUTH-19 |
| Critical keys exportable to application processes | ST-AUTH-01, ST-AUTH-10, ST-GW-02, ST-CI-09 (`AUTH-KEY-BACKUP`) |
| Account recovery bypasses the configured assurance level | ST-REC-01, ST-REC-07, ST-REC-08, ST-REC-14, ST-REC-15, ST-REC-16, ST-REC-20, ST-REC-21, ST-PH-06 |

## 8. Residual risks (tracked, spec §4.4)

| Id | Risk | Why accepted (staging) | Owner of follow-up |
|---|---|---|---|
| R-01 | AS-1 sees pending secrets (business URLs, OTPs) during their minutes-long window, because the api decrypts them to hand them to the device | Viadere is a transport for these by decision 2/3; E2EE delivery (Phase B) removes it for businesses that adopt it | A3, A4 |
| R-02 | AS-1 suppresses pushes and notices (recovery start, new device) | Signed key-log head in the app gives detection on next open, and S-SEC-01 when heads are withheld; since ADR-0032 a suppressed recovery cannot end in grant-capable keys without an authority-verified code; availability is not guaranteed | A6, A2 |
| R-03 | AS-1 plus a victim approving an attacker-initiated prompt yields a login | Requires the victim's authenticator and an approval of a prompt the victim did not start. Cross-device flows: number matching narrows it. Same-device link service has no number matching; since ADR-0033 the code reaches only the registered, signed return URL, so AS-1 can no longer redirect it to its own host, and PKCE binds redemption to the initiating browser. Matches the §13 metric's exception ("without an independent authenticator") | A2 |
| R-04 | Stolen business API key + signing key lets the attacker push prompts to that tenant's customers | Same tenant only, verified destinations only, rate limits and fatigue controls | A4 |
| R-05 | Phished operator can suspend tenants or revoke devices (reduce-only) | Reduce-only actions are audited and reversible by a second operator | A11 |
| R-06 | Server-side open redirects on a verified host are invisible to Viadere | Business attestation; query check catches the common form | A2 |
| R-07' | (replaces R-07, A2 ruling) Under AS-1 the api can deliver a *genuine* business-signed URL that the business issued for the attacker's own account to the victim (login CSRF: the victim lands in the attacker's account) | URL rewrite is blocked by ADR-0031. Also within R-07' (S1-A3-R04): AS-1 can pair a genuine statement with another delivery of the same tenant within `exp` (the `brq`/`purpose` check compares api-supplied data), and can serve a pre-revocation tenant record under 15 minutes old to a device that has not seen a newer `seq`. `sub` binding would narrow the first two only if the device knew its `subject_ref` independently (ledger L-10, optional). Severity Low | A2 |
| R-08 | Locked device: Deny (approvals) and This wasn't me (links) work from the notification without unlocking (after first unlock since boot) | They only reduce; intentional | A9 |
| R-09 | Unlocked device with enrolled biometrics in attacker hands can approve | Inherent; revocation from another device or recovery | A2 |
| R-10 | Email provider sees email-fallback codes | Only on explicit per-request fallback; labelled lower assurance | A10 |
| R-11 | Cloud control-plane, GitHub org, Cloudflare account or malicious merged code defeats isolation | Separate severe class (spec §4.4, Appendix B); detection and dual approval only | A5, A11 |
| R-12 | Real-time phishing relays the number-matching code | Inherent to push; passkey bias, acr labelling | A1 |
| R-13 | MO spoofing, porting and SIM swap can link a number | Phone link is never an authenticator; mandatory spoof indicator; no displacement of an existing link before cool-down and in-app no-objection; notice + `UNLINK` + `STOP`; MO-linked numbers get only on-ramp text | A2, A10 |
| R-13b | A victim is persuaded to send the nonce text for the attacker's begin | SMS-02 states the effect plainly; per-number caps; existing links protected; never a factor | A2, A9 |
| R-14 | AS-1 can revoke keys or freeze (DoS) | Reduce-only; audited; recoverable | A11 |
| R-15 | Lean profile: software keys (backup restricted by role), public Key Vault endpoint with firewall, authority in same subscription | Budget exceptions (CLAUDE.md); removed by the standard profile before any real customer data | A5 |
| R-16 | Pre-migration device keys are imported into the authority key log on trust (one-time, audited) | No proof chain exists for keys created before the authority; import is a reviewed admin job that runs once and records the snapshot digest; keyless accounts are never grant-capable; imported keys become grant-capable only after the device confirms its own head | A3 |
| R-17 | A compromised api, which hosts the authorize endpoint and the WebAuthn origin, can bind a victim's genuine, in-progress authentication to an attacker-initiated RP session, **for that one session only**. A lasting key addition through the same origin is excluded: passkey assertions are accepted only for `oidc_login` and `recovery_cancel` (ADR-0023 §3a) | Staging only; named exception to the §13 metric. Removal: before any production IdP the browser-facing authorization endpoint and passkey origin run outside the ordinary tier with their own identity and deploy path, plus external review (spec §13) | A2 |
| R-18 | `kd-log-signing` held by the api (decision 12) lets AS-1 present a fabricated key directory to a device with no pinned head; the device then accepts forged E2EE `ApprovalRequest` signers and display | Yields no authorization (the business checks `txn_digest`), but can mislead the person. Removal: ADR-0028 C2 | A3 |
| R-19 | Under AS-1 a revoke-and-freeze flood (R-14) can target authority key-log entries through `revocations` | Reduce-only; mass revocation alerts | A11 |
| R-20 | An attacker who can make a business create sign-in requests can make the person **retry** when the typed number collides with an attacker request's code (about k/90 for k open attacker requests with 2-digit codes); it can no longer cancel the person's own request (S2-A2-9) | Budgets limit alerts only; no supersession without a matching `session_handle`; bound is the business's own trigger throttling (guidance and SDK helper) and the per-tenant limit | A2, A8 |
| R-21 | Staging has one human reviewer: admin, deploy and JWKS publication are a single owner approval | Removal: a second human reviewer is named before production or any real customer data; production requires two | A2 |
| R-22 | A compromised active `device-statement-signing` (or `recovery-seal`) key is trusted by apps that have not yet received the revocation list; loss of both keys of a family fails closed until an app release | Standby pinned as a separate key object without a role before rollover; only the standby can revoke the active statement key, never the reverse; revocations are sticky and returned with every head and tenant record; app update removes the key (ADR-0033 §3) | A3 |
| R-23 | An authority **process** compromise (T-AUTH-12 class) can read the in-memory active `recovery-seal` private key and open recovery envelopes recorded since that key became active | Key Vault has no key-agreement operation; the key is wrapped at rest under a non-exportable KEK with an unwrap-only role, every unwrap is reconciled, retired seal keys are destroyed, and the same compromise already reaches the signing builders. Re-assessed in Stage 6 if a Key Vault or Managed HSM key-agreement operation exists (ADR-0034) | A3 |

## 9. Standards relied on (spec §29)

RFC 9180 (HPKE, recovery envelopes), RFC 7515 (JWS), RFC 7517 (JWK), RFC 7519 (JWT), RFC 7638 (JWK thumbprint), RFC 8725 (JWT BCP), RFC 6749, RFC 7636 (PKCE), RFC 9700 (OAuth security BCP), RFC 9449 (DPoP, considered, not adopted in staging), RFC 9421 (HTTP Message Signatures), RFC 9530 (Digest fields), RFC 6238 (TOTP), RFC 8176 (amr values), OpenID Connect Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0, W3C WebAuthn Level 3, NIST SP 800-63-4 (B: authenticator assurance), NIST SP 800-207, OWASP ASVS and MASVS, Apple UserNotifications and Universal Links, Android FCM, App Links and Credential Manager. Exact revisions are re-checked by the implementing stage (spec §29 source-of-truth rule).
