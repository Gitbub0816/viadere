# ADR-0023: Signed factor assertions, the authority key log and the grant decision

- **Status:** proposed (2026-11-02)
- **Spec reference:** §4.3, §5 (MFA Authority, Policy/Grant Authority), §9.3, §17 Phase B, §18, §26 (replay, gateway compromise); RFC 7515, 7517, 7519, 7638, 8725
- **Related:** ADR-0019 (authority), ADR-0021 §5 (link service), ADR-0022 (business-verified JWS), ADR-0024 (OIDC), ADR-0028 (keys); SECURITY §2.1, §2.2, §2.54; findings F-12, F-23
- **Review:** A3 (author role, crypto), A2, A1 — cryptography and grant authorization need A2 **and** A3 (§15.1)

## Context

Viadere-asserted results (link-service redemption, OIDC tokens) must be impossible to mint from a compromised ordinary workload (§4.3). The authority must therefore verify evidence that the api cannot fabricate. Device public keys and passkeys live in the api database today, so an api compromise could register an attacker key for any account (THREAT_MODEL T-GW-3). Existing formats compose standard primitives; F-23 asks A3 to review any new format. RFC 8725 recommends explicit typing, algorithm allow-lists and audience checks.

## Decision

### 1. Artifact types (all compact JWS, RFC 7515)

| `typ` | Signer | Audience | Purpose |
|---|---|---|---|
| `viadere-approval+jws` (existing, v1/v2) | device pairwise key | the business | business-verified push MFA (ADR-0022) |
| `viadere-factor+jws` (new) | device account key (`approvalUserPresence` or `approvalBiometric`) | `urn:viadere:authority:<env>` | evidence to the authority |
| `viadere-grant+jwt` (new) | authority `grant-signing` | the tenant (`aud` = tenant client id) | link-service result |
| `JWT` id_token, `at+jwt` access token (RFC 9068) | authority `oidc-signing-*` | OIDC client / userinfo | OIDC (ADR-0024) |
| `viadere-keylog-head+jws` (new) | authority `keylog-signing` | devices of the account | key-log head |

### 2. JOSE profile (applies to every new type)

- Header members exactly `alg`, `kid`, `typ`; any other member (`jku`, `jwk`, `x5u`, `x5c`, `crit`, `b64`, `zip`, `cty`) refused. `alg` fixed by `typ`: `ES256` for all except id_tokens/access tokens, which allow `RS256` or `ES256` per client registration. `none` and every `HS*` refused (RFC 8725 §3.1, §3.2).
- `kid` = RFC 7638 JWK thumbprint (SHA-256, base64url) of the public key; for device keys the same thumbprint indexes the key log; for authority keys the static JWKS lists it.
- ECDSA signatures raw `r‖s`, low-S normalized (SECURITY §2.1); payload canonical JSON (SECURITY §2.2), re-serialized and compared byte-for-byte; duplicate members refused; integers only; total length ≤ 4096 bytes.
- Explicit typing prevents cross-JWT confusion (RFC 8725 §3.11): every verifier checks `typ`, `iss` and `aud` for its own type.

### 3. Factor assertion `viadere-factor+jws` (device → authority)

Payload members:

| Member | Rule |
|---|---|
| `v` | `1` |
| `aud` | `urn:viadere:authority:<env>` (`stg`, `prod`) |
| `ach` | authority challenge id `ach_` + 22 base64url |
| `nonce` | the challenge's 256-bit nonce (base64url, 43) |
| `purpose` | `link_open`, `oidc_login`, `keylog_device_added`, `keylog_passkey_added`, `recovery_cancel` |
| `display_digest` | lowercase hex `SHA-256("VIADERE-DISPLAY-V1\n" ‖ canonical(display))`, where `display` is exactly the object the app rendered (business display name, purpose, client display name, host or redirect host, `match_digits?`) |
| `decision` | `approve`, `deny`, `report` |
| `uv` | `biometric`, `device_passcode` (existing amr vocabulary); must match the key purpose |
| `match` | entered number, iff the challenge required one |
| `code_hash` | `link_open` same-device only: base64url SHA-256 of the device-generated link code |
| `iat`, `exp` | `exp − iat ≤ 120`; `iat` ≤ now + 60 s |

Authority verification order (any failure → deny, generic `401 evidence_invalid`, audit with reason; `ach` is consumed **only after** every check passes, so a forged assertion cannot burn a real challenge):

1. strict parse and JOSE profile (§2);
2. `kid` is in the key log, `active`, `usable_from ≤ now`, purpose consistent with `uv`, account not frozen;
3. signature with the logged public key;
4. `aud` equals the authority's own; `ach` exists, `pending`, unexpired; `nonce` equals (constant time); `purpose` equals the challenge purpose;
5. `display_digest` equals the digest of the display object stored with the challenge;
6. `match` equals the challenge code if required (constant time); `code_hash` present iff required;
7. time bounds (±60 s skew);
8. policy (§6): the evidence type satisfies the client's/tenant's required level;
9. single-use: `UPDATE authority_challenges SET state='used' WHERE id=? AND state='pending'` (one row or deny).

### 4. Authority key log (independent knowledge of keys)

The authority keeps, per account, an append-only log of public keys it will accept (`authority_keylog_entries {account_ref, seq, type, kid, public_key, key_purpose, proof, usable_from, created_at, prev_hash, entry_hash}`), with a signed head `{account_ref, seq, head_hash, pending_recoveries[], issued_at}` (`viadere-keylog-head+jws`). `account_ref` = `acct_` + 32 hex of `HMAC-SHA256(OIDC_PAIRWISE_KEY, "account-ref\n" ‖ accountId)` (the authority never needs the raw id in its tables, but receives it in requests and recomputes).

Entry types and the proof each needs (the api relays; the authority verifies):

| Type | Proof | Effect |
|---|---|---|
| `genesis` | proof-of-possession signature by each key over `VIADERE-KEYLOG-V1\n{account_ref}\n{kid}\ngenesis` and, when App Attest mode is `require`, the attestation; refused if the authority has ever seen the account | first keys of a **new** account; a forged genesis only creates an attacker's own account |
| `device_added` | a `viadere-factor+jws` (`purpose: keylog_device_added`, display includes the new device name and key thumbprints) by an existing logged `approvalBiometric` key of a D1-equivalent device, **or** a WebAuthn assertion by a logged passkey with UV; new keys get `usable_from = now + 24 h` (72 h if unattested), matching SECURITY §2.5a | adds keys |
| `passkey_added` | as `device_added` | adds a passkey public key |
| `recovery_started` | the api's statement (the recovery code is verified by the api today) | starts an authority-timed hold; head lists it as pending |
| `recovery_activated` | allowed only ≥ 72 h after `recovery_started` with no `recovery_cancel` by any logged key; adds the recovery passkey, revokes all earlier keys | authority enforces the hold even if the api lies |
| `recovery_cancel` | `viadere-factor+jws` by any logged active key | closes the pending recovery |
| `key_revoked` | none (reduce-only; the api may revoke) | key no longer accepted |

The app fetches the signed head through the api (`GET /v1/security/key-log-head`), verifies it against the pinned `keylog-signing` public keys (build setting `VIADERE_AUTHORITY_KEYLOG_KEYS`), refuses heads older than 15 minutes, and shows pending recoveries and unknown devices even if their pushes were suppressed. Stage 6 moves verification of newly issued recovery codes into the authority (ADR-0028 §4).

**Migration:** pre-existing device keys and passkeys are imported once by `ViadereAuthority admin keylog-import` from a reviewed snapshot (residual R-16); imported entries are marked `imported` and are grant-capable.

### 5. Grant `viadere-grant+jwt` (authority → business)

Header `{"alg":"ES256","kid":"<thumbprint>","typ":"viadere-grant+jwt"}`. Payload:

| Claim | Value |
|---|---|
| `iss` | `https://id.<domain>/grant` |
| `aud` | the link client id (tenant-scoped) |
| `sub` | the tenant's `subject_ref` for the account that owns the signing key, computed by the authority with its copy of `SUBJECT_REF_KEY` (SECURITY §2.30); never taken from the request |
| `tid` | tenant id |
| `txn` | the delivery id (`adl_…`) |
| `purpose` | `sign_in`, `step_up` |
| `acr` | `urn:viadere:acr:app` (both `uv` values involve device user verification; see ADR-0024 §5 for the full acr table) |
| `amr` | RFC 8176 values: `uv = device_passcode` → `["hwk","pin","mfa"]`; `uv = biometric` → `["hwk","user","mfa"]` (RFC 8176 has no modality-neutral biometric value, so `user` is used and no stronger claim is made) |
| `auth_time`, `iat` | seconds |
| `exp` | `iat + 60` |
| `jti` | 128-bit random, recorded in `authority_grants` |
| `cch` | the `code_challenge` the business sent (it checks equality) |

SDK verifiers (Swift, TypeScript, Kotlin; ADR-0030) check signature against the static grant JWKS, `typ`, `iss`, `aud`, `exp` (skew ±60 s), `cch`, and consume `jti` once.

### 6. The grant decision (no signing oracle)

- The authority has no route that signs caller-supplied bytes. Key Vault `sign` is invoked only by three builders: `GrantBuilder`, `OIDCTokenBuilder`, `KeyLogHeadBuilder`, each called only after §3 verification and policy evaluation succeed in the same request.
- Policy = platform floor compiled into the authority (`AuthorityPolicy.v1`, versioned, in Core) + per-tenant/per-client raises (`authority_policy_versions`). The api can only call `policy/raise`; lowering is an admin-job change (ADR-0019 §5). Every grant records `policy_version`.
- Every decision (allow or deny) writes an authority audit event with tenant, `account_ref`, `ach`, evidence type, `kid`, policy version, decision reason, correlation id; no secrets (spec §12.1).

### 7. Replay stores

| Store | Key | Lifetime |
|---|---|---|
| `authority_challenges` | `ach` (state pending → used/expired) | until `exp` + 1 day, then purged (class T) |
| `authority_link_codes` | `code_hash` unique, state | 120 s + purge |
| `authority_oidc_codes` | code hash unique | 60 s + purge |
| `authority_grants` | `jti` unique | class E (ADR-0026) |
| business side | `jti` / `aud‖kid‖challenge` | until `exp` + skew (SDK `ReplayStore` interface with atomic insert) |

### 8. Clock

Authority and api use the platform clock (Azure time sync); skew allowance ±60 s everywhere; a health check fails the authority if its clock differs from the database clock by more than 5 s.

## Consequences

- Every device that will be used for link service or OIDC needs its keys in the authority log; enrollment calls the authority synchronously (if the authority is down, enrollment still succeeds for messaging and business-verified approvals; the key-log append is retried by the outbox and the device is not grant-capable until it lands).
- Three new JWS types are additions to a family that already exists (F-23); they use only ES256/RS256, standard JOSE structure and existing canonicalization, no new primitive.
- `sub` in grants equals the business's existing `subject_ref`, so a business can match the result to its customer without extra mapping.

## Threat assumptions changed

- The api is no longer trusted to say which keys belong to an account (T-GW-3) or which account a subject reference names (T-GW-4).
- New residuals: R-16 (one-time import on trust), R-02 (notice suppression, detection only).

## Reviewers required

A3 and A2 (both required: cryptography and grant authorization), A1 (acr/amr semantics), A6 (app verification of key-log heads).
