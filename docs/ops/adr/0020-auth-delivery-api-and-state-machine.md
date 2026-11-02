# ADR-0020: Auth-delivery API, state machine, tenant authorization, idempotency and outbox

- **Status:** proposed (2026-11-02); revision 3 (2026-11-02), additive only: optional `session_handle` and supersession narrowed to it (S2-A2-9; §2, §8), `destination_unverified` denials excluded from fatigue counting (S2-A2-10; §1, §5); revision 2 (2026-11-02): `audience` removed (S1-A2-8), destination signature (ADR-0031), RFC 9421 profile (S1-A3-19), budgets limit alerting (S1-A2-6), Android push pipeline (A6/A7 finding 3), variables as personal data (S1-A10-9), email fallback limits (S1-A10-6), log allow-list (S1-A10-2)
- **Spec reference:** §3.1, §6.1, §6.2, §6.5, §12, §19, Appendix A; owner decisions 1, 2, 3, 4, 7, 9
- **Related:** ADR-0014 (outbox), ADR-0019, ADR-0021 (magic links), ADR-0022 (push MFA), ADR-0025 (webhooks), ADR-0026 (retention); SECURITY §2.27 (idempotency), §2.29 (policy), §2.30 (`subject_ref`), §2.91 (queue envelope)
- **Review:** A4 (author of Stage 2 contract), A2, A10, A8

## Context

No delivery API, state machine or auth event exists (GAP §2). Business calls are bearer-only (F-19). The spec lists illustrative endpoints at `/v1/auth-deliveries` with two vocabularies for states (§6.2 and §19). Decision 1 excludes SMS; decision 3 makes Viadere a transport for partner codes.

## Decision

### 1. Endpoints

Business routes stay under the existing `/v1/business/` namespace (the route catalog convention, `APIRoutes.swift`); the spec says names are illustrative (§6.1).

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/business/auth-deliveries` | business (§3), scope `auth_deliveries:write`, `Idempotency-Key` required | create a `magic_link`, `otp` or `notice` delivery |
| `GET /v1/business/auth-deliveries/{id}` | business, `auth_deliveries:read` | status and events, never a secret |
| `POST /v1/business/auth-deliveries/{id}/cancel` | business, `auth_deliveries:write`, `Idempotency-Key` | cancel (deletes P-class data) |
| `POST /v1/business/auth-deliveries/{id}/complete` | business, `auth_deliveries:write`, `Idempotency-Key` | business reports its own verification outcome `{outcome: "succeeded" \| "failed"}` |
| `POST /v1/business/auth-approvals` | business, `auth_approvals:write`, `Idempotency-Key` | push approval: an Approve v2 request with number matching (ADR-0022); same delivery id space and events |
| `GET /v1/business/auth-approvals/{id}` | business | status + `result_ref` (the JWS is fetched from the existing results route) |
| `POST /v1/business/auth-links/redeem` | business, `auth_deliveries:write` | link-service redemption (ADR-0021 §5) |
| `POST /v1/business/webhooks/test` | business, test key only | signed sample `auth.*` events (spec §6.1) |
| `GET /v1/auth-deliveries` | device-signed bearer | inbox: open deliveries for this device's account |
| `GET /v1/auth-deliveries/{id}` | device-signed bearer | display object (no secret); marks `delivered` |
| `POST /v1/auth-deliveries/{id}/open` | device-signed bearer (request key) | returns the URL or code once, deletes ciphertext, marks `opened` |
| `POST /v1/auth-deliveries/{id}/deny` | device-signed bearer | Deny or "This wasn't me": `denied`, optional `report: true`, optional `reason: "destination_unverified"` (ADR-0031 §4, audited and alerted; since revision 3 sent only for integrity failures, never for a stale record or clock skew, and not counted toward fatigue, §5) |
| `GET /v1/auth-tenants/{tenant_id}/destination-keys` | device-signed bearer | relays the authority-signed `viadere-tenant-keys+jws` unchanged (ADR-0031 §2) |
| `POST /v1/auth-deliveries/{id}/approve` | device-signed bearer + factor JWS | link-service and OIDC app approval: relays evidence to the authority |

`POST /v1/devices/link` (spec §6.1) is **not added**: device association already exists as passkey- or D1-confirmed enrollment and `POST /v1/devices/{id}/confirm` (SECURITY §2.5, §2.17), now also appended to the authority key log (ADR-0023 §4).

### 2. Create request (`AuthDeliveryCreateRequest`, strict, ≤ 16 KiB)

| Field | Type | Rule |
|---|---|---|
| `method` | `magic_link` \| `otp` \| `notice` | required |
| `request_id` | string 1-128 `[A-Za-z0-9_.:-]` | business's id, unique per tenant (also the default idempotency scope) |
| `subject_ref` | string | the tenant's pairwise reference (SECURITY §2.30); unknown → `404 not_deliverable` |
| `purpose` | `sign_in` \| `step_up` \| `verify_contact` \| `account_notice` | selects allowed templates and TTL bounds |
| `template` | template id, e.g. `auth.sign_in_link.v1` | Viadere-owned catalog (UX_COPY); business cannot supply text |
| `variables` | object | only keys the template declares; `action_display` ≤ 60, `reference` ≤ 40; NFC; no control, bidi or zero-width characters; no URL-looking strings, no e-mail-address or phone-number patterns. Treated as **personal data** (S1-A10-9): stored only in `auth_delivery_secrets` (P class) and deleted at terminal state; `auth_deliveries` keeps a SHA-256 digest; never in audit events, webhooks or the support console; the developer guide says these fields must not carry contact data |
| `destination` | object | `magic_link` only: `{link_mode: "business", url, signature}` (`signature` = `viadere-destination+jws`, required while `AUTH_DESTINATION_SIGNATURE_REQUIRED`, ADR-0031) or `{link_mode: "viadere", link_client_id, return_url, code_challenge, code_challenge_method: "S256"}` (ADR-0021) |
| `otp` | object | `otp` only: `{code: 4-10 chars [0-9A-Z], code_kind: "otp" \| "totp"}` |
| `correlation_id` | string ≤ 128 | echoed in events |
| `client_transaction_ref` | string ≤ 128 | opaque business handle, echoed |
| `session_handle` | string 1-64 `[A-Za-z0-9_-]`, optional | *(revision 3, additive; S2-A2-9)* opaque value the business derives from its own initiating session; class T; never shown, never in webhooks. The only input to supersession (§8). Also accepted on `POST /v1/business/auth-approvals` (ADR-0022 §5.2) |
| `expires_in_seconds` | int | `magic_link` 120-600 (default 300), `otp` 60-600 (default 300), `notice` 300-86400 |
| `channels` | array of `push`, `inbox`, `email` | default `["push","inbox"]`; `email` needs `fallback.email` |
| `fallback` | `{email: {address}}` | §7 |
| `callback` | `{webhook_id}` | a registered v2 subscription (ADR-0025) |

Any member not listed, **including `tenant_id` and `audience`**, is `422 validation_failed` (spec App. A: tenant is authenticated from the credential, never from the payload). Grant `aud` and `tid` come only from the authority's link-client record (S1-A2-8; revision 1's `audience` member is removed).

Response `201` (`200` on idempotent replay): `{id: "adl_<22 b64url>", request_id, status, expires_at, created_at, correlation_id}`.

### 3. Business authentication for auth routes

- **Live keys** (`vdk_live_…`): the API key **and** either (a) an RFC 9421 HTTP Message Signature with a business key registered in the console (purpose `api-request-signing`, P-256 `ecdsa-p256-sha256` or `ed25519`), covering `@method`, `@target-uri`, `content-digest` (RFC 9530, `sha-256`), `idempotency-key`, with `created` (±300 s) and `nonce` (replay scope `bizsig:{business}:{keyid}`, TTL 600 s), `keyid` owned by the key's business; or (b) Tier E mTLS (existing). Missing or invalid → `401 signature_required` / `signature_invalid`.
- **RFC 9421 profile (S1-A3-19).** The verifier derives the algorithm from the registered key and refuses a contradicting `alg` parameter (RFC 9421 §3.2); `tag="viadere-biz-v1"` is required; `ecdsa-p256-sha256` signatures are raw `r‖s` and both S forms are accepted (SECURITY §2.1); `@target-uri` is reconstructed from the canonical public origin, never the tunnel-internal host; for bodiless methods `content-digest` is omitted and refused if present; `expires` is required and ≤ `created` + 300; RFC 9421 Appendix B vectors are part of `docs/protocol/vectors/`.
- **Key registration (S1-A2-13).** Registering or replacing a request-signing key, like adding a destination host, needs a fresh dashboard passkey step-up by an Owner or Security Admin and sends a notice to every Owner (AS-3/AS-4).
- **Test keys** may omit the signature, and only reach sandbox subjects (SECURITY §2.18).
- Rationale: spec §6.1 asks for mTLS or signed client authentication; a stolen bearer key alone must not send auth prompts (THREAT_MODEL T-GW-8). RFC 9421 is a standard (no custom format) and has test vectors to reuse in `docs/protocol/vectors/`.

### 4. Tenant authorization

- The tenant is the API key's business; every query filters by it; a foreign id is `404` (same body as unknown).
- `subject_ref` resolves only within the tenant. A delivery is created only if the relationship is active, the business is verified and not suspended, the consumer has at least one eligible app device (not App Clip, not delegate), the consumer has not paused auth requests from this business, and the policy capability (`auth.delivery`, `auth.challenge`, `transaction.approve`) is entitled.
- **Non-disclosure**: unknown subject, no eligible device, paused, and frozen all return `404 not_deliverable` with the same body; the business sees no reason (spec §6.1).

### 5. State machine

States (lowercase on the wire; `cancelled` spelling matches existing events):

`created → validated → queued → sent → delivered → opened → completed`, and terminal `expired`, `cancelled`, `denied`, `failed`, `completed`.

| From | To | Actor and trigger | Notes |
|---|---|---|---|
| — | `created` | api, inside create transaction | row inserted |
| `created` | `validated` | api, same transaction | destination, policy, budgets passed; invalid requests are refused and never persisted |
| `validated` | `queued` | api, same transaction | outbox row `auth.delivery.dispatch` written (ADR-0014) |
| `queued` | `sent` | worker/api job | at least one channel accepted by its provider (APNs `200`, email provider `202`); **not** human receipt |
| `queued`, `sent` | `delivered` | device-signed `GET /v1/auth-deliveries/{id}`, or an email provider delivery receipt | first fetch only |
| `queued`, `sent`, `delivered` | `opened` | device-signed `open` (business link, OTP view) or verified factor evidence (link service) | the P-class secret is deleted in the same transaction |
| `opened` | `completed` | business `complete {outcome: succeeded}`, or authority redemption (link service) | only the verifier/business; Viadere never infers it |
| `opened` | `failed` | business `complete {outcome: failed}` | |
| any non-terminal | `denied` | device-signed `deny` | P deleted; event; fatigue counter, **except** `reason: destination_unverified`, which never counts toward the fatigue counter or pause (revision 3, additive; ADR-0031 §4, S2-A2-10) |
| any non-terminal | `cancelled` | business `cancel`, supersession (§8), operator, device revocation | P deleted |
| any non-terminal | `expired` | `expires_at` reached (job `auth.delivery.expire`, scheduled at create) | P deleted |
| `queued` | `failed` | no channel could be attempted (no device token and inbox disabled), or tenant suspended | |

Every transition is a compare-and-swap `UPDATE … WHERE id = ? AND status = ? AND version = ?`; a lost race returns `409 conflict` to the caller and changes nothing. `opened` is never authentication success; `delivered` and `sent` never imply `opened`. Each transition writes one `auth_delivery_events` row and an outbox webhook event in the same transaction.

### 6. Secrets, push payloads, OTP and TOTP

1. P-class values (business URL, OTP/partner code) are stored only in `auth_delivery_secrets(delivery_id PK, ciphertext, key_id, expires_at)`, sealed with `AUTH_SECRET_KEY` (AES-256-GCM, field-encryption `v2.` format with AAD `auth_delivery_secrets.ciphertext#<delivery id>`, SECURITY §2.21), deleted on open, terminal state or expiry; a sweep runs every minute.
2. Push payload (APNs): `apns-push-type: alert`, `aps.alert` with generic title and body (UX_COPY N-01), `aps.category` (`viadere.auth.link`, `viadere.auth.code`, `viadere.approve`), `aps.thread-id` = per-device opaque value, `aps.interruption-level: active`, `mutable-content: 1` (the NSE runs only for alert pushes with it), custom key `adl` (delivery id) only; `apns-collapse-id` = delivery id. No business id, name, URL, code or amount. The NSE fetches the display object; the app re-fetches on foreground because the NSE cannot read the Keychain before first unlock (N-08 then stays). No flow depends on silent pushes. **FCM (Android):** data-only, high priority, `{adl}` only, no `notification` block; the app renders N-01 and updates the same notification id after the fetch (ADR-0022 §9).
3. **OTP and partner TOTP codes are delivered, never verified by Viadere** (decision 3). The code is shown in the app after the user opens the item; Lock Screen never shows it. Validation refuses `otpauth://` in any field (case-insensitive, after one percent-decode): TOTP seeds never transit Viadere in plaintext (THREAT_MODEL T-TOTP-1). Phase B may add `totp_enrollment` only as an E2EE envelope (ADR-0007).

### 7. Channels and fallback

- Channels: `push` (APNs; FCM in Stage 4 behind a push-provider seam), `inbox` (always on for app accounts), `email` (MailerSend v1, existing adapter).
- **No SMS adapter for any auth method** (decisions 1 and 9). The transport seam stays; adding SMS needs a new ADR and owner approval (decision 1). `channels` containing `sms` is `422`.
- Email: the consumer account has no address; the business supplies `fallback.email.address` per request. Allowed only if the tenant's policy `allow_email_fallback` is on (**default off**; the console explains the privacy difference when a tenant turns it on) and the method is `otp` or `magic_link` (business link mode only, with a valid destination signature). Codes and links sent by email have a TTL of at most 15 minutes. The address is stored in `auth_delivery_secrets` (P class) and deleted after send. The email uses a fixed Viadere template from a Viadere sending domain; the business URL must pass the same destination policy. Using it emits `auth.delivery.fallback_used` with `assurance: "email"`. There is no automatic fallback: the business asks for it explicitly per request.
- **Email fallback gate (decision 13, S1-A10-6).** Email fallback stays disabled in every environment until (a) MailerSend's storage location for message content and activity is verified and recorded in `docs/ops/DATA-INVENTORY.md`, and (b) content retention is off or at its minimum and activity retention at the shortest plan setting; if MailerSend stores authentication content outside the US, the fallback stays off (decision 13: nothing authentication-related is stored outside the US) unless a US-located provider is chosen by a new ADR. Bounce and complaint webhooks store only the delivery id and status. Suppression-list handling and a delete path are documented in the runbook; MailerSend is listed as a sub-processor.

### 8. Rate limits, collapse and budgets

New fail-closed namespaces (added to the `DatabaseRateLimitStore` fail-closed list): `authdl-tenant` (per tenant, plan-dependent; **the only budget that refuses with `429`**), `authdl-subject` (per tenant+subject: 5 per 10 min, 20 per day; **alert budget**), `authdl-open` (per device), `authdl-deny`, `authlink-redeem` (per tenant), `bizsig-nonce`, `authority-challenge` (per tenant and per account, at the authority).

**Budgets limit alerting, not availability (S1-A2-6).** When a per-subject or per-relationship budget is exhausted, the new delivery is still created, collapsed and placed in the inbox, but delivered **silently** (no alert push); the inbox shows "You have a pending sign-in from {Business}". An attacker who knows a victim's identifier can therefore no longer make the victim's own sign-in undeliverable. Collapse (narrowed in revision 3, S2-A2-9): a new `sign_in` delivery or approval for the same (tenant, subject) cancels an open one with reason `superseded` **only when both carry the same `session_handle`** (§2); requests without a matching `session_handle` stay open side by side until they complete, expire or are answered (for approvals the typed number selects the request, ADR-0022 §5.2), so an attacker who triggers sign-ins cannot cancel the person's own request; while over budget, supersession is silent too. Fatigue counters are shared with Approve (ADR-0022 §5). Business guidance and the SDK helper throttle unauthenticated sign-in triggers per client IP and per account on the business side (residual R-20).

### 9. Idempotency, outbox and audit

- `Idempotency-Key` required on every POST above (SECURITY §2.27 semantics: one row per `(business, operation, key)` with the SHA-256 of operation and request; same key + same request replays; different request `409 idempotency_conflict`). `request_id` is additionally unique per tenant.
- Outbox: dispatch, expiry and webhook rows are written in the creating transaction; queue envelopes carry ids only (SECURITY §2.91; new message types `auth.delivery.dispatch`, `auth.delivery.expire`; unknown types dead-lettered).
- Audit events (no secrets, no `variables`): `auth_delivery.created|opened|denied|cancelled|completed|expired|cross_tenant_refused|destination_unverified`, with tenant, pseudonymous actor, delivery id, method, purpose, policy version, request-signing key id, correlation id.
- **Log allow-list (S1-A10-2).** Auth-delivery, phone-link and OIDC routes log only an allow-list of fields (route template, status, ids, latency, error code); never the query string, body or headers other than ids. The allow-list is implemented in the logger and in the App Insights telemetry initializer (fields not on the list are dropped), not by regex redaction.
- Template ids are fixed: N-06 "{Business} sent a security notice." never takes business text (S1-A9-14).

### 10. Contract artifacts (Stage 2)

`contracts/openapi/auth-delivery-v1.yaml` (OpenAPI 3.1) for these routes, JSON Schemas for the create request, the display object, every event and the webhook envelope in `contracts/schemas/`, and a parity test against `APIRoutes` like the existing `OpenAPIParityTests`. `docs/openapi.yaml` links to it.

## Consequences

- Businesses must register a request-signing key before sending live auth deliveries; the Swift, TypeScript and Kotlin backend SDKs implement RFC 9421 signing (ADR-0030).
- Two vocabularies in the spec collapse into one enum; `accepted` (§19) is represented by `validated`/`queued`.
- Email fallback is the only path where a code or link leaves Viadere through a third party; it is explicit and labelled.

## Threat assumptions changed

- Stolen API key alone no longer suffices for live auth routes (AS-2b narrowed).
- OPENED is explicitly not proof of identity; any business that treats it as such is outside the contract (documented in the SDK and harness).

## Reviewers required

A4 (state machine, outbox), A2 (tenant isolation, non-disclosure), A10 (stored fields, email address handling), A8 (contract and SDK impact).
