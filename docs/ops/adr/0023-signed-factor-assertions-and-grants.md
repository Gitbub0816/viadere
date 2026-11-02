# ADR-0023: Signed factor assertions, the authority key log and the grant decision

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02) after the Stage 1 reviews: account identity, binding and recovery in ADR-0032; authority-built displays and device statements in ADR-0033; tenant destination keys in ADR-0031. Revision 3 (2026-11-02): WebAuthn assertions only for `oidc_login` and `recovery_cancel` (S2-A2-2, new §3a); device-add comparison code and sealed recovery in the key-log table (S2-A2-1, -3; ADR-0034); `enrollment_confirmed` commits to the head (S2-A2-4); third `kid` definition and builder `kid` rule (S1-A3-R04, -R06); `amr` for unattested keys (S2-A2-11 item 3, S1-A3-R06 item 3)
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
| `viadere-keylog-head+jws`, `viadere-challenge+jws`, `viadere-tenant-keys+jws`, `viadere-device-keys-revocation+jws` (new) | authority `device-statement-signing` (ADR-0033; revocation lists by the standby only for the statement family, §3.3 there) | `urn:viadere:device` | key-log head, signed challenge with authority-built display, tenant destination keys (ADR-0031), pinned-key revocation list (ADR-0033 §3) |
| `viadere-destination+jws` (new) | business `auth-destination-signing` key | `urn:viadere:device` | business-signed magic-link destination (ADR-0031 §3) |
| `viadere-destination-key-registration+jws` (new) | business `auth-destination-signing` key (proof of possession) | `urn:viadere:authority:<env>` | registration of a tenant destination key (ADR-0031 §1) |
| HPKE envelope (not JWS) | device, sealed to `recovery-seal` | the authority | recovery code set and recovery start (ADR-0034) |

### 2. JOSE profile (applies to every new type)

- Header members exactly `alg`, `kid`, `typ`; any other member (`jku`, `jwk`, `x5u`, `x5c`, `crit`, `b64`, `zip`, `cty`) refused. `alg` fixed by `typ`: `ES256` for all except id_tokens/access tokens, which allow `RS256` or `ES256` per client registration. `none` and every `HS*` refused (RFC 8725 §3.1, §3.2).
- `kid` has three definitions, never mixed (S1-A3-12, S1-A3-R04 item 4): **device keys and passkeys** use the existing `KeyIdentifier` (SHA-256 of the DER SPKI, `E2EE/E2EEKeys.swift`; a passkey's COSE key is converted to SPKI first) in factor JWS, Approve results, PoPs, sealed `new_kids` and the key log; **authority keys** (signing and `recovery-seal`) use the RFC 7638 JWK thumbprint (SHA-256, base64url), as listed in JWKS and pinned in the app; **tenant destination keys** use the RFC 7638 thumbprint as well (ADR-0031 §1), scoped to their tenant record. Every verifier looks up by `kid`, then recomputes the identifier from the stored public key and compares the full key.
- **Builders emit RFC 7638 `kid`s (S1-A3-R06 item 4).** `KMSSigningKey.kid()` (`Security/KMS/KeyManagementService.swift`) returns the SPKI-hash `KeyIdentifier`; `GrantBuilder`, `OIDCTokenBuilder` and `DeviceStatementBuilder` must not use it for JOSE headers, JWKS or pins. A vector proves that the JWKS `kid`, the header `kid` and the app pin agree for each authority key.
- ECDSA signatures raw `r‖s`, low-S normalized (SECURITY §2.1); payload canonical JSON (SECURITY §2.2), re-serialized and compared byte-for-byte (a strictness measure; the signature covers the received bytes); duplicate members refused; integers only; total length ≤ 4096 bytes. The canonical form is SECURITY §2.2 (UTF-16 code-unit key order); it is **not** called JCS (RFC 8785). Cross-language vectors cover escapes, non-ASCII, key ordering and large integers (S1-A3-22).
- Explicit typing prevents cross-JWT confusion (RFC 8725 §3.11): every verifier checks `typ`, `iss` and `aud` for its own type.

### 3. Factor assertion `viadere-factor+jws` (device → authority)

Payload members:

| Member | Rule |
|---|---|
| `v` | `1` |
| `aud` | `urn:viadere:authority:<env>` (`stg`, `prod`) |
| `ach` | authority challenge id `ach_` + 22 base64url |
| `nonce` | the challenge's 256-bit nonce (base64url, 43) |
| `purpose` | `link_open`, `oidc_login`, `keylog_device_added`, `keylog_passkey_added`, `recovery_cancel`, `recovery_codes_set`, `enrollment_confirmed` |
| `display_digest` | lowercase hex `SHA-256("VIADERE-DISPLAY-V1\n" ‖ canonical(display))`, where `display` is the **authority-built** object from the verified `viadere-challenge+jws` that the app rendered (ADR-0033 §1); the api never supplies display text |
| `return_url` | `link_open` only: the exact return URL from the challenge statement; the device opens only this URL (ADR-0033 §4) |
| `decision` | `approve`, `deny`, `report` |
| `uv` | `biometric` (accepted only from an `approvalBiometric` key) or `user_presence` (an `approvalUserPresence` key: biometric or passcode, modality unknown) (S1-A3-21) |
| `match` | entered number, iff the challenge required one (2 digits for cross-device link and OIDC app path; 6 digits for the `keylog_device_added` comparison code, ADR-0033 §4.1) |
| `envelope_digest` | `recovery_codes_set` only: base64url SHA-256 of `enc ‖ ct` of the sealed set (ADR-0034 §1) |
| `head_hash`, `seq` | `enrollment_confirmed` only: the head the device verified (ADR-0032 §1.4); refused unless equal to the current head |
| `code_hash` | `link_open` same-device only: base64url SHA-256 of the device-generated link code |
| `iat`, `exp` | `exp − iat ≤ 120`; `iat` ≤ now + 60 s |

Authority verification order (any failure → deny, generic `401 evidence_invalid`, audit with reason; `ach` is consumed **only after** every check passes, so a forged assertion cannot burn a real challenge):

1. strict parse and JOSE profile (§2);
2. `kid` is in the key log, `active`, `grant_capable` (ADR-0032 §1.4, §3.3) for grant-yielding purposes, `usable_from ≤ now`, purpose consistent with `uv`, account not frozen;
3. signature with the logged public key;
3a. account binding: any `accountId` the request carries is checked in constant time against the `account_ref` of the signing key's log entry (ADR-0032 §2); a mismatch is refused and audited as `account_binding_mismatch`;
4. `aud` equals the authority's own; `ach` exists, `pending`, unexpired; `nonce` equals (constant time); `purpose` equals the challenge purpose;
5. `display_digest` equals the digest of the **authority-built** display stored with the challenge; for `link_open`, `return_url` equals the challenge's registered URL byte for byte;
6. `match` equals the challenge code if required (constant time); `code_hash` present iff required. A signature-valid assertion with a wrong `match` atomically increments `authority_challenges.match_failures` and is refused; at 3 failures the challenge becomes `failed` and the failure counts toward the per-account pause (ADR-0022 §5). Only failures before signature verification leave the challenge untouched (S1-A3-05);
7. time bounds (±60 s skew);
8. policy (§6): the evidence type satisfies the client's/tenant's required level;
9. single-use: `UPDATE authority_challenges SET state='used' WHERE id=? AND state='pending'` (one row or deny).

### 3a. WebAuthn assertions: which purposes, which origins (S2-A2-2)

The authenticator signs `clientDataJSON` over an opaque challenge and shows the person no purpose, and the WebAuthn origin `https://id.<domain>` is served by the api (R-17). A passkey assertion therefore proves only "this passkey was used in some ceremony on that origin". Rules, until the passkey origin leaves the ordinary tier (R-17 removal condition):

1. A WebAuthn assertion is accepted as authority evidence **only** for `oidc_login` and for the reduce-only `recovery_cancel`. It is **never** accepted for `device_added`, `passkey_added`, `recovery_codes_set`, `enrollment_confirmed` or `link_open`; those need a `viadere-factor+jws` by a logged, grant-capable device key over an authority-signed display (§4).
2. The authority checks `clientDataJSON.type = "webauthn.get"`, the challenge, `rpIdHash`, UV, and `clientDataJSON.origin` against a **per-purpose allow-list** held in its own configuration: `oidc_login` → exactly `https://id.<domain>`; `recovery_cancel` → `https://id.<domain>` and the existing Viadere web origin `https://<RP_ID>`. Any other origin, `crossOrigin: true`, or a `topOrigin` is refused.
3. The one other use of a passkey signature is the PoP of a passkey being **added** inside a sealed recovery start (ADR-0032 §3.2). It authorizes nothing (the sealed code does), and its challenge is the SHA-256 of a `VIADERE-KEYLOG-V1` PoP string, which no other ceremony uses.
4. A passkey-only person adds a device through an existing device (§4, ADR-0033 §4.1) or through recovery (ADR-0032 §3); FLOW_MATRIX F10 says so.
5. Test ST-REC-17 (A): a UV passkey assertion over a `keylog_device_added`, `keylog_passkey_added`, `recovery_codes_set` or `enrollment_confirmed` nonce is refused whatever its origin; an `oidc_login` assertion from an origin not on the list is refused.

### 4. Authority key log (independent knowledge of keys)

The authority keeps, per account, an append-only log of public keys it will accept (`authority_keylog_entries {account_ref, seq, type, kid, public_key, key_purpose, proof, usable_from, grant_capable, created_at, prev_hash, entry_hash}`; hash chain per ADR-0033 §5), with a signed head (`viadere-keylog-head+jws`, ADR-0033 §2) listing the active keys, pending recoveries, `seq` and `env`. `account_ref` = `acct_` + lowercase hex of the first 16 bytes of `HMAC-SHA256(ACCOUNT_REF_KEY, "account-ref\n" ‖ account_id)` (a dedicated key, ADR-0032 §1.1, §4). **The account id is minted by the authority at genesis** (ADR-0032 §1); the authority never accepts a caller-chosen account id and refuses ids it neither minted nor imported.

Entry types and the proof each needs (the api relays; the authority verifies):

| Type | Proof | Effect |
|---|---|---|
| `genesis` | no account id in the request; PoP by each key over `VIADERE-KEYLOG-V1\n{env}\ngenesis\n{kid}\n{nonce}` with a fresh authority nonce, plus the App Attest assertion wherever the mode is not `off` | the authority mints `account_id` and returns it with the signed head; keys are not grant-capable until `enrollment_confirmed` (ADR-0032 §1) |
| `enrollment_confirmed` | factor JWS carrying `head_hash` and `seq` of the current head, plus a PoP by **each** key of the entry over that `head_hash`, after the app verified a head whose entry lists exactly its own keys (imported accounts: contains them) (ADR-0032 §1.4) | marks the entry's keys grant-capable only when every key of the entry confirmed the same head |
| `device_added` | factor JWS (`purpose: keylog_device_added`, authority-built display, `match` = the 6-digit comparison code shown on the new device, ADR-0033 §4.1) by a logged, grant-capable `approvalBiometric` key whose `usable_from` has passed ("D1-equivalent") and that belongs to the entry's account; **plus** PoP by each new key. **No WebAuthn assertion** (§3a). New keys get `usable_from = now + 24 h` (72 h if unattested), matching SECURITY §2.5a, and become grant-capable after `enrollment_confirmed` | adds keys |
| `passkey_added` | factor JWS (`purpose: keylog_passkey_added`) by a logged, grant-capable `approvalBiometric` key **of the device that created the passkey in the Viadere app**; the app checks that the challenge's `kids` equal the credential it just created before signing (same device, so no comparison code); **no WebAuthn assertion** (§3a). Passkeys created elsewhere (for example on a web page) are not added to the authority log | adds a passkey public key |
| `recovery_codes_set` | factor JWS with `envelope_digest` by a logged, grant-capable `approvalBiometric` key whose `usable_from` has passed; the codes arrive only sealed (ADR-0034) and the authority stores only keyed verifiers (ADR-0032 §3.1) | registers an authority-verified code set; invalidates the previous authority set |
| `recovery_started` | a sealed envelope with a code the **authority** verifies and the new keys' `new_kids`, plus a PoP by each new key committing to `envelope_digest` (ADR-0032 §3.2, ADR-0034); without a sealed code the entry is `recovery_started_legacy`, refused for accounts with an active authority set | starts an authority-timed hold; the head lists it as pending with its `kids` |
| `recovery_activated` | allowed only ≥ 72 h after the start with no `recovery_cancel`; adds **exactly** the start's `kids` and revokes all earlier keys; the new keys are grant-capable only if the start was authority-verified | the authority enforces the hold even if the api lies |
| `recovery_cancel` | `viadere-factor+jws` by any logged active key, **or** a UV WebAuthn assertion by a logged passkey from an allowed origin (§3a; reduce-only) | closes the pending recovery |
| `key_revoked` | none (reduce-only; api and worker may revoke) | key no longer accepted; a mass revocation alerts (R-19) |

The app fetches the signed head through the api (`GET /v1/security/key-log-head`), verifies it against the pinned `device-statement-signing` keys (ADR-0033 §3), refuses heads older than 15 minutes, heads for another account and heads with a lower `seq`, shows pending recoveries and unknown devices even if their pushes were suppressed, and shows S-SEC-01 when it cannot get a valid head (ADR-0032 §3.4).

**Migration:** pre-existing device keys and passkeys are imported once by `ViadereAuthority admin keylog-import` from a reviewed snapshot that covers every consumer id, keyless ones included (residual R-16; ADR-0032 §1.6).

### 5. Grant `viadere-grant+jwt` (authority → business)

Header `{"alg":"ES256","kid":"<thumbprint>","typ":"viadere-grant+jwt"}`. Payload:

| Claim | Value |
|---|---|
| `iss` | `https://id.<domain>/grant` |
| `aud` | the link client id (`lcl_…`, tenant-scoped) from the authority's link-client record, never from the request (S1-A2-8, S1-A3-15) |
| `sub` | the tenant's `subject_ref` for the account that owns the signing key, computed by the authority with its copy of `SUBJECT_REF_KEY` (SECURITY §2.30) after the account binding check (step 3a), with the business id from the link-client record; never taken from the request |
| `tid` | tenant id from the link-client record |
| `txn` | the delivery id (`adl_…`) |
| `purpose` | `sign_in`, `step_up` |
| `acr` | `urn:viadere:acr:app` (both `uv` values involve device user verification; see ADR-0024 §5 for the full acr table) |
| `amr` | RFC 8176 values: `uv = user_presence` → `["hwk","mfa"]` (biometric or passcode; the modality is not claimed, so no `pin`); `uv = biometric` → `["hwk","user","mfa"]` (RFC 8176 has no modality-neutral biometric value, so `user` is used and no stronger claim is made). `hwk` only for keys attested as hardware-bound (Secure Enclave via App Attest; on Android only with key attestation showing TEE or StrongBox). A key **without** such attestation gets `swk` in place of `hwk`: `["swk","mfa"]` or `["swk","user","mfa"]`, so `hwk` is never implied by omission (S2-A2-11 item 3, S1-A3-R06 item 3). The modality from `LAContext.biometryType` is never turned into `face`/`fpt`. A1 confirms in Stage 5 (S1-A3-21) |
| `auth_time`, `iat` | seconds |
| `exp` | `iat + 60` |
| `jti` | 128-bit random, recorded in `authority_grants` |
| `cch` | the `code_challenge` the business sent (it checks equality) |

SDK verifiers (Swift, TypeScript, Kotlin; ADR-0030) check signature against the static grant JWKS, `typ`, `iss`, `aud`, `exp` (skew ±60 s), `cch`, and consume `jti` once.

### 6. The grant decision (no signing oracle)

- The authority has no route that signs caller-supplied bytes. Key Vault `sign` is invoked only by `GrantBuilder`, `OIDCTokenBuilder` and `DeviceStatementBuilder` (heads, challenges, tenant records, revocation lists). Grant and token builders take a `VerifiedEvidence` / `VerifiedCode` value that only the verifier can construct (non-public type, file-private initializer); a test scans the module for any other KMS `sign` call site (S1-A3-11). Key Vault `AuditEvent` diagnostics on `kv-vdr-auth` are reconciled by a worker-independent job against `authority_grants` and statement issuance records; any unmatched `sign` alerts.
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

- Every device that will be used for link service or OIDC needs its keys in the authority log; enrollment calls the authority synchronously. If the authority is down at **account creation**, no account is created and the app retries (ADR-0032 §1.5); if it is down when an **additional device** enrolls, that device is not grant-capable until a later `device_added` with proof by a logged key lands (no outbox retry ever substitutes for proof).
- Three new JWS types are additions to a family that already exists (F-23); they use only ES256/RS256, standard JOSE structure and existing canonicalization, no new primitive.
- `sub` in grants equals the business's existing `subject_ref`, so a business can match the result to its customer without extra mapping.

## Threat assumptions changed

- The api is no longer trusted to say which keys belong to an account (T-GW-3), which account an id names (ADR-0032), which account a subject reference names (T-GW-4), what a prompt displays (ADR-0033) or that a recovery code was accepted (ADR-0032 §3).
- A passkey ceremony the person performs on the api-served origin can no longer be redirected into a lasting key addition (§3a); a device-add approval is bound to the keys of the device the person holds (ADR-0033 §4.1).
- Residuals: R-16 (one-time import on trust; keyless accounts are never grant-capable), R-02 (notice suppression; detection plus the S-SEC-01 state), R-22 (pinned-key compromise until the revocation reaches the app), R-23 (seal key in authority memory, ADR-0034).

## Reviewers required

A3 and A2 (both required: cryptography and grant authorization), A1 (acr/amr semantics), A6 (app verification of key-log heads).
