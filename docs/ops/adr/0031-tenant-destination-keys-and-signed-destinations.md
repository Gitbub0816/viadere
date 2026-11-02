# ADR-0031: Tenant destination keys and business-signed magic-link destinations (closes R-07)

- **Status:** proposed (2026-11-02, Stage 1 revision 2); revision 3 (2026-11-02): proof of possession and domain-evidence binding at key registration, 13-month key lifetime, api-independent revocation, automatic host removal (S1-A3-R03, S2-A2-10); integrity versus availability failures on the device (S2-A2-10); tenant record `seq`, URL digest encoding, member and size rules (S1-A3-R04); revision 3.1 (2026-11-02): registration PoP verification rules and DNSSEC (S3-A3-03), lower `seq` as integrity and clock skew judged against authority time (S3-A2-5)
- **Spec reference:** §4.2 (gateway compromise), §4.3, §6.4, §26 ("swap business destination domain … blocked before magic-link handoff"), §27 ("a verified business domain can be bypassed"); owner decision 2
- **Related:** ADR-0019 §5 (admin path), ADR-0021 §2-§3 (domain verification, validator), ADR-0023 §2 (JOSE profile), ADR-0033 (authority device statements and pinned keys); A2 review `docs/reviews/STAGE1_A2_SECURITY_REVIEW.md` "R-07 ruling" and S1-A2-3; re-reviews S2-A2-10, S1-A3-R03, -R04
- **Review:** A2 (required design author of the ruling), A3 (signature formats, key choice), A6/A7 (device verification), A8 (SDK signing), A9 (copy)

## Context

Revision 1 accepted that a compromised api (AS-1) could rewrite a stored business URL before handoff, relying on the app showing the true host (R-07), and asked A2 to accept a narrowed reading of §27. A2 rejected that reading: showing a host lets a person notice a look-alike, it does not block it, and the proposed "Phase B" signature used a key-directory key the api holds (decision 12 exception, SECURITY §2.58 residuals 1 and 10). Decision 2 keeps business-supplied URLs as the default mode, so the fix must not route every link through the link service.

The re-reviews added two gaps. A3: nothing proved that the registered public key came from the tenant, so an AS-1 that sits between the business dashboard and the operator could substitute its own key while the domain evidence stayed genuine (S1-A3-R03). A2: the device turned every verification failure into a user denial, mixing tampering with outages (S2-A2-10).

## Decision

A2's required design is adopted as normative, with the key choice made by this ADR.

### 1. Authority-attested tenant destination keys

1. A tenant that uses `link_mode: "business"` registers one or more **P-256** public keys (ES256 only; the device verifier accepts both S forms, SECURITY §2.1, because business SDKs on Node and the JVM do not normalize S) with purpose `auth-destination-signing`. They are stored only in the authority: `authority_tenant_keys {tenant_id, kid (RFC 7638 thumbprint), public_key, purpose, allowed_hosts[], display_name, status, not_after}`.
2. Rows are added, extended or renewed **only by the authority admin job** (ADR-0019 §5): adding a key or a host increases authority. A registration needs all of (S1-A3-R03):
   - **Proof of possession.** A compact JWS by the new key, header `{alg: "ES256", kid, typ: "viadere-destination-key-registration+jws"}`, payload `{v:1, iss: <tenant_id>, aud: "urn:viadere:authority:<env>", kid, hosts[], nonce, iat, exp}`, where `nonce` is issued by the admin job for this registration and `exp − iat ≤ 3600`. The admin job verifies it with the submitted public key and checks that `kid` is that key's thumbprint. **Verification rules (revision 3.1, S3-A3-03):** (a) the job issues the `nonce` (at least 128 bits from its CSPRNG) in a first run, records it in the authority database with the tenant, the `kid` and an expiry, and accepts it **once** (consumed by compare-and-swap in the registering run); (b) `iat` ≤ now + 60 s and `exp` ≥ now, in addition to `exp − iat ≤ 3600`; (c) `iss` equals the change file's tenant, `aud` the job's own environment, and `hosts[]` exactly the change file's hosts (same set, no extra, no missing); (d) the strict JOSE profile of ADR-0023 §2 applies (header exactly `alg`, `kid`, `typ`; both S forms accepted).
   - **The thumbprint in the domain-control evidence itself.** For every host, either a DNS TXT record `_viadere-destkey.<host>` with value `v=1; kid=<thumbprint>`, or the thumbprint listed in the tenant's existing well-known verification file for that host (ADR-0021 §2). The evidence is fetched by the reviewer-gated `authority-admin.yml` workflow (outside the api and the dashboard: two independent DNS-over-HTTPS resolvers for TXT, HTTPS with certificate validation for the file; where the zone is DNSSEC-signed the workflow validates the chain and refuses a bogus answer, and it records whether the answer was validated; without DNSSEC the evidence rests on the two resolvers agreeing, which is stated in the change artifact for the reviewer; revision 3.1, S3-A3-03), and the raw responses go into the attested change artifact. The admin job re-checks that the attested evidence names the key's thumbprint for every host and refuses otherwise. The reviewer therefore checks a thumbprint that the workflow obtained from DNS or HTTPS, never one the dashboard displayed. (The authority job itself keeps its egress deny, TRUST_BOUNDARIES §9.)
   - The tenant's verified `auth_links` purpose row for each host; `allowed_hosts` is copied from those hosts and can only be narrowed afterwards without the admin job.
3. **Lifetime.** `not_after` ≤ 13 months from registration; renewal repeats §1.2 with a new nonce. A key past `not_after` is not listed in the tenant record.
4. `display_name` is the tenant's verified business display name at registration (the same value UX_COPY rule 1 uses); a change is an admin-job change.
5. **Reduction.** The api may call `POST revocations` for these keys and hosts (reduce-only). No other api route touches the table (ST-AUTH-16). Revocation also works **without the api**: the admin job has `revoke-tenant-key` and `remove-tenant-host` commands (S2-A2-10). When the weekly domain re-check (ADR-0021 §2) fails for a host, the worker removes that host from `allowed_hosts` through `revocations` (reduce-only, `Authority.Revocations` role), and Owners are notified.

### 2. Signed tenant record for devices

The authority signs a `viadere-tenant-keys+jws` (ES256, JOSE profile of ADR-0023 §2) with the **`device-statement-signing`** key (ADR-0033; the same pinned key family that signs key-log heads and challenges, separated from them by `typ`; A3 confirmed this key choice, S1-A3-R07). Payload, exactly these members:

`{v:1, iss:"urn:viadere:authority:<env>", aud:"urn:viadere:device", env, tenant_id, seq, display_name, allowed_hosts[], keys:[{kid, public_key (JWK, crv P-256), not_after}], issued_at}`

`seq` increases by one on every change of the tenant's keys, hosts or name (S1-A3-R04 item 5). The authority re-signs a record on change and whenever the cached copy is older than 5 minutes at the time it is served (ADR-0033 §2). The device fetches it through the api (`GET /v1/auth-tenants/{tenant_id}/destination-keys`; the response also carries the latest pinned-key revocation list), verifies it against the pinned `device-statement-signing` keys (ADR-0033 §3), checks `typ`, `iss`, `aud`, `env`, refuses a record whose `issued_at` is older than 15 minutes, and refuses a record whose `seq` is lower than the highest it has stored for that tenant. A revocation therefore reaches a device within 15 minutes; for a device that has already seen the post-revocation record, at once. AS-1 can still serve a **pre-revocation** record that is under 15 minutes old to a device that has not seen a newer one; this bounds the revocation latency and is stated in R-07'.

### 3. Business-signed destination statement

On create, the business sends `destination: {link_mode: "business", url, signature}` where `signature` is a compact JWS, header exactly `{alg: "ES256", kid, typ: "viadere-destination+jws"}`, canonical payload with exactly these members:

`{v:1, iss:<tenant id>, aud:"urn:viadere:device", sub:<subject_ref>, brq:<request_id of the create request>, purpose:<sign_in|step_up|verify_contact>, url_sha256, host:<lowercase A-label host>, iat, exp, jti}`

- `url_sha256` = base64url **without padding** of SHA-256 over the UTF-8 bytes of the URL exactly as `open` returns it: no normalization, no trimming (S1-A3-R04 item 1). (`display_digest` elsewhere is lowercase hex; each encoding is fixed per member.)
- `exp − iat ≤ 600`; `exp ≤` the delivery's `expires_at`; `jti` 128 random bits; integers only; duplicate members refused; total ≤ 4096 bytes (S1-A3-R04 item 6).
- `sub` is carried for the business's own audit and for a later device-side subject check; **the device does not check it today** (it has no independent copy of its `subject_ref`). The optional subject statement that would let it (A2 S2-A2-11 item 5, A3 S1-A3-R04 item 3) is deferred as ledger item L-10 (owner A2, Stage 5).

The statement carries a digest of the URL, not the URL, so it is not a bearer value and is stored as class T. The api validates the statement shape and the URL (ADR-0021 §3) at create, but **its check is not relied on**: the device check below is the control.

### 4. Device verification before Continue is enabled

On the link screen the app verifies, in this order (any failure: Continue stays disabled, the URL is never requested):

1. the authority tenant record (§2) for the `tenant_id` the delivery names: signature, `typ`, `iss`, `aud`, `env`, freshness, `seq`;
2. the destination statement's signature with a key from that record, `kid` present, `not_after` not passed;
3. `typ`, `aud = urn:viadere:device`, `iss = tenant_id`, exact member set;
4. `brq` and `purpose` equal the delivery's display object. **This compares against api-supplied data**: it protects against misrouting, not against AS-1, which can pair a genuine statement with another delivery of the same tenant within `exp` (part of R-07'; S1-A3-R04 item 2);
5. `exp` against the device clock (±60 s skew);
6. `host ∈ allowed_hosts` of the authority record;
7. `jti` not seen before (the app keeps seen `jti` values until `exp` + 60 s).

The **business name and host on the link screen come from the authority record and the signed statement**, never from the api's display fields.

After the person taps Continue and `open` returns the URL, the app computes `url_sha256` over the exact bytes it received and requires equality, requires the parsed host to equal `host`, re-runs `AuthDestinationValidator` (Core), and only then calls the system open API.

**Failure classes (S2-A2-10).** The app sorts every failure into one of two classes:

| Class | Failures | App behavior | Server effect |
|---|---|---|---|
| **`destination_mismatch`** (integrity) | bad statement or record signature; record signed by a non-pinned or revoked key; `kid` not in the record; `typ`/`iss`/`aud`/`env`/members wrong; `brq` or `purpose` mismatch; host outside `allowed_hosts`; replayed `jti`; URL digest or host mismatch after `open`; *(revision 3.1, S3-A2-5)* a record `seq` lower than the stored one (evidence of a replayed record); a statement `exp`/`iat` outside the window while the device clock agrees with authority time (below) | URL not opened; S-LINK-09 | `POST /v1/auth-deliveries/{id}/deny {reason: "destination_unverified"}` (the existing ADR-0020 wire value; it now means exactly this class); audit `auth_delivery.destination_unverified`; operator alert at **high** priority; business sees `denied`. **Does not count toward the fatigue pause** (ADR-0022 §5.4) |
| **`destination_unverifiable`** (availability) | tenant record absent, older than 15 minutes, or not obtainable (authority outage, offline); statement `exp`/`iat` outside the window **and** the device clock disagrees with **authority time** (revision 3.1, S3-A2-5: judged against the authority-signed `issued_at` of a head or tenant record verified within the last minute, never the api's `Date` header; the device clock "agrees" when it lies between `issued_at` − 60 s and `issued_at` + 5 min + 60 s, since a served statement is at most 5 minutes old) | URL not opened; S-LINK-11 with "Try again" (or S-LINK-12 "Check your phone's date and time" for clock skew); the delivery **stays open** and the person can retry until it expires | **no server call**: no deny, no business event, no pause count, no operator alert (client telemetry counts only) |

The stale-record case is an availability dependency of F1/F2 on the authority (THREAT_MODEL T-AUTH-8, FLOW_MATRIX F1/F2). Every availability-class failure is still counted in client telemetry (reason, tenant, no URL), so a pattern of them is visible to operators even though no server call is made (revision 3.1, S3-A2-5).

### 5. Fail closed in the pilot

`AUTH_DESTINATION_SIGNATURE_REQUIRED=true` in every staging pilot configuration, with no off switch in pilot configuration (the flag exists only so the unit tests can exercise both paths; the pilot release check refuses `false`). If the tenant has no active destination key, business-mode create returns `422 destination_signature_required`. The tenant can use the link service instead (ADR-0021 §5).

### 6. SDKs and vectors

The Swift, TypeScript and Kotlin backend SDKs gain `signAuthDestination(url:, subjectRef:, requestId:, purpose:, expiresAt:, key:)` and `signDestinationKeyRegistration(tenantId:, hosts:, nonce:, key:)`. Vectors: `docs/protocol/vectors/auth-destination-v1.json` (valid, wrong key, revoked key, stale tenant record, lower `seq`, replayed `jti`, wrong `brq`, host outside `allowed_hosts`, URL byte change, high-S signature accepted, non-canonical payload refused, registration PoP valid and invalid; revision 3.1: reused nonce, expired and future-dated PoP, `hosts[]` mismatch).

### 7. Residual R-07' (replaces R-07)

The api still sees the URL during its minutes-long life (R-01, unchanged). Under AS-1 it can also (a) deliver a *genuine* signed URL that the business issued for the attacker's own account to the victim's device (login-CSRF style: the victim lands in the attacker's account), (b) pair a genuine statement with another delivery of the same tenant within `exp` (check 4 compares against api data), and (c) serve a pre-revocation tenant record that is under 15 minutes old to a device that has not seen a newer `seq`. `sub` binding would narrow (a) and (b) only if the device knew its own `subject_ref` from a source other than the api (L-10). Severity Low, owner A2.

### 8. Tests (Stage 7)

ST-ML-10 (any byte of the stored URL rewritten after create → device refuses to open and reports `destination_unverified`), ST-ML-11 (refusal corpus of §4), ST-ML-12 (api-fabricated, stale or lower-`seq` tenant record refused), ST-ML-13 (create without signature → `422` while the flag is on), ST-ML-15 (K, S: a stale record or clock skew leaves the delivery open, makes no server call and shows S-LINK-11/-12; an integrity failure sends `destination_unverified`, alerts at high priority and does not count toward the pause), ST-AUTH-16 (api identity cannot add an `authority_tenant_keys` row; no route, `404`; the admin job refuses a change file without a valid registration PoP, without the thumbprint in the attested evidence for every host, or with `not_after` beyond 13 months; revision 3.1: a reused nonce, an expired or future-dated PoP, a wrong `iss`/`aud`, a `hosts[]` set different from the change file's, and a DNSSEC-bogus answer are refused). ST-ML-15 extended (revision 3.1): a lower `seq` and a stale statement with a correct device clock are integrity failures; a spoofed api `Date` header changes nothing. Each fails if its control is removed.

## Consequences

- Business-mode tenants must publish a DNS TXT (or well-known) thumbprint and sign a registration with the new key, then pass a reviewed admin change before they can send business links in the pilot; renewal at least every 13 months (OQ-7, informational: decision 2 is kept).
- The authority gains one table, one record type, one registration format and reduce-only revocation targets that work with or without the api.
- The app gains a verification step that needs a fresh tenant record; when it cannot get one, business-mode links wait (S-LINK-11) instead of being denied.

## Threat assumptions changed

- AS-1 can no longer rewrite a business URL undetected (T-GW-6, T-ML-7) or substitute a tenant destination key at registration (T-ML-8).
- Outages no longer look like user denials to businesses or the pause counter.

## Reviewers required

A2, A3 (formats and key), A6/A7 (device verification and timing), A8 (SDK signing), A9 (S-LINK-09, -11, -12).
