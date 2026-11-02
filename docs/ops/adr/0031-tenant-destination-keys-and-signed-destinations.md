# ADR-0031: Tenant destination keys and business-signed magic-link destinations (closes R-07)

- **Status:** proposed (2026-11-02, Stage 1 revision 2)
- **Spec reference:** §4.2 (gateway compromise), §4.3, §6.4, §26 ("swap business destination domain … blocked before magic-link handoff"), §27 ("a verified business domain can be bypassed"); owner decision 2
- **Related:** ADR-0019 §5 (admin path), ADR-0021 §3 (validator), ADR-0023 §2 (JOSE profile), ADR-0033 (authority device statements and pinned keys); A2 review `docs/reviews/STAGE1_A2_SECURITY_REVIEW.md` "R-07 ruling" and S1-A2-3
- **Review:** A2 (required design author of the ruling), A3 (signature formats, key choice), A6/A7 (device verification), A8 (SDK signing), A9 (copy)

## Context

Revision 1 accepted that a compromised api (AS-1) could rewrite a stored business URL before handoff, relying on the app showing the true host (R-07), and asked A2 to accept a narrowed reading of §27. A2 rejected that reading: showing a host lets a person notice a look-alike, it does not block it, and the proposed "Phase B" signature used a key-directory key the api holds (decision 12 exception, SECURITY §2.58 residuals 1 and 10). Decision 2 keeps business-supplied URLs as the default mode, so the fix must not route every link through the link service.

## Decision

A2's required design is adopted as normative, with the key choice made by this ADR.

### 1. Authority-attested tenant destination keys

1. A tenant that uses `link_mode: "business"` registers one or more P-256 public keys with purpose `auth-destination-signing`. They are stored only in the authority: `authority_tenant_keys {tenant_id, kid (RFC 7638 thumbprint), public_key, purpose, allowed_hosts[], display_name, status, not_after}`.
2. Rows are added or extended **only by the authority admin job** (ADR-0019 §5): adding a key or a host increases authority. The change file names the tenant, key, hosts and the domain-control evidence (DNS TXT or well-known file record and the `auth_links` purpose row); the reviewer checks that evidence. `allowed_hosts` is copied from the tenant's verified `auth_links` hosts at registration and can only be narrowed afterwards without the admin job.
3. `display_name` is the tenant's verified business display name at registration (the same value UX_COPY rule 1 uses); a change is an admin-job change.
4. The api may call `POST revocations` for these keys and hosts (reduce-only). No other api route touches the table (ST-AUTH-16).

### 2. Signed tenant record for devices

The authority signs a `viadere-tenant-keys+jws` (ES256, JOSE profile of ADR-0023 §2) with the **`device-statement-signing`** key (ADR-0033; the same pinned key family that signs key-log heads and challenges, separated from them by `typ`). Payload:

`{v:1, iss:"urn:viadere:authority:<env>", aud:"urn:viadere:device", tenant_id, display_name, allowed_hosts[], keys:[{kid, public_key (JWK, crv P-256), not_after}], issued_at}`

The authority re-signs a record when it changes and at most every 5 minutes otherwise (cached; no Key Vault `sign` per request). The device fetches it through the api (`GET /v1/auth-tenants/{tenant_id}/destination-keys`), verifies it against the pinned `device-statement-signing` keys (`VIADERE_AUTHORITY_DEVICE_KEYS`, active and standby, ADR-0033 §3), checks `typ`, `iss`, `aud`, and refuses a record whose `issued_at` is older than 15 minutes. A revocation therefore reaches devices within 15 minutes.

### 3. Business-signed destination statement

On create, the business sends `destination: {link_mode: "business", url, signature}` where `signature` is a compact JWS, header exactly `{alg: "ES256", kid, typ: "viadere-destination+jws"}`, canonical payload:

`{v:1, iss:<tenant id>, aud:"urn:viadere:device", sub:<subject_ref>, brq:<request_id of the create request>, purpose:<sign_in|step_up|verify_contact>, url_sha256:<base64url SHA-256 of the exact URL bytes>, host:<lowercase A-label host>, iat, exp, jti}`

Rules: `exp − iat ≤ 600`; `exp ≤` the delivery's `expires_at`; `jti` 128 random bits; integers only; duplicate members refused. The statement carries a digest of the URL, not the URL, so it is not a bearer value and is stored as class T.

The api validates the statement shape and the URL (ADR-0021 §3) at create, but **its check is not relied on**: the device check below is the control.

### 4. Device verification before Continue is enabled

On the link screen the app verifies, in this order (any failure: Continue stays disabled, the URL is never requested):

1. the authority tenant record (§2) for the `tenant_id` the delivery names: signature, `typ`, freshness;
2. the destination statement's signature with a key from that record, `kid` present, `not_after` not passed;
3. `typ`, `aud = urn:viadere:device`, `iss = tenant_id`;
4. `brq` and `purpose` equal the delivery's display object;
5. `exp` against the device clock (±60 s skew);
6. `host ∈ allowed_hosts` of the authority record;
7. `jti` not seen before (the app keeps seen `jti` values until `exp` + 60 s).

The **business name and host on the link screen come from the authority record and the signed statement**, never from the api's display fields.

After the person taps Continue and `open` returns the URL, the app computes SHA-256 over the exact URL bytes it received and requires it to equal `url_sha256`, requires the parsed host to equal `host`, re-runs `AuthDestinationValidator` (Core), and only then calls the system open API. On any failure the URL is not opened; the app shows S-LINK-09 ("We couldn't confirm this link came from {display_name}. We didn't open it.") and sends `POST /v1/auth-deliveries/{id}/deny {reason: "destination_unverified"}`, which is audited and raises an operator alert.

### 5. Fail closed in the pilot

`AUTH_DESTINATION_SIGNATURE_REQUIRED=true` in every staging pilot configuration, with no off switch in pilot configuration (the flag exists only so the unit tests can exercise both paths; the pilot release check refuses `false`). If the tenant has no active destination key, business-mode create returns `422 destination_signature_required`. The tenant can use the link service instead (ADR-0021 §5).

### 6. SDKs and vectors

The Swift, TypeScript and Kotlin backend SDKs gain `signAuthDestination(url:, subjectRef:, requestId:, purpose:, expiresAt:, key:)`. Vectors: `docs/protocol/vectors/auth-destination-v1.json` (valid, wrong key, revoked key, stale tenant record, replayed `jti`, wrong `brq`, host outside `allowed_hosts`, URL byte change).

### 7. Residual R-07' (replaces R-07)

The api still sees the URL during its minutes-long life (R-01, unchanged). Under AS-1 it can also deliver a *genuine* signed URL that the business issued for the attacker's own account to the victim's device (login-CSRF style: the victim lands in the attacker's account). `sub` binding narrows this only to the degree that the device knows its own `subject_ref` from a source other than the api; in this design it does not, so R-07' stands. Severity Low, owner A2.

### 8. Tests (Stage 7)

ST-ML-10 (any byte of the stored URL rewritten after create → device refuses to open), ST-ML-11 (refusal corpus of §4), ST-ML-12 (api-fabricated or stale tenant record refused), ST-ML-13 (create without signature → `422` while the flag is on), ST-AUTH-16 (api identity cannot add an `authority_tenant_keys` row; no route, `404`). Each fails if its control is removed.

## Consequences

- Business-mode tenants must register a destination key through a reviewed admin change before they can send business links in the pilot; onboarding is slower by design (owner question OQ-7 in `IMPLEMENTATION_LEDGER.md`, informational: decision 2 is kept).
- The authority gains one table, one record type and one reduce-only revocation target.
- The app gains a verification step that needs a fresh tenant record; when it cannot get one (offline, authority outage beyond 15 minutes), business-mode links cannot be opened from Viadere (fail closed, E-01 copy).

## Threat assumptions changed

- AS-1 can no longer rewrite a business URL undetected: T-GW-6 and T-ML-7 move from residual to controlled; §27 "verified domain bypass" no longer depends on an interpretation.

## Reviewers required

A2, A3 (formats and key), A6/A7 (device verification and timing), A8 (SDK signing), A9 (S-LINK-09).
