# Stage 1 revision 3: targeted check by A3 (cryptography and key management), 2026-11-02

| | |
|---|---|
| Reviewer | A3, independent agent reviewer. A3 did not write any Stage 1 artifact or any of the three revisions |
| Previous verdict | `docs/reviews/STAGE1_A3_CRYPTO_REREVIEW.md`: APPROVE WITH CONDITIONS (High S1-A3-R01; Medium -R02, -R03; Low -R04 to -R06; Info -R07, -R08) |
| Response checked | `docs/reviews/STAGE1_RESPONSE.md`, "Revision 3" table |
| Baseline | branch `claude/inspiring-cannon-t5hxfw` at `2eadc4e`; delta `git diff 4a84bde..2eadc4e -- docs/` |
| Read | ADR-0034 (all, new); ADR-0032 §1.1, §3, §4; ADR-0033 §1-§4.1, §6; ADR-0031 §1-§4; ADR-0023 §1-§5 (§3a included); ADR-0028 revision-3 deltas (§1 table, roles, explicit versions, reconciliation, policy rules); ADR-0024 §7.3-§7.4; THREAT_MODEL T-REC-8, T-AUTH-6, T-AUTH-15, AT-1 1.3.3, R-23; TRUST_BOUNDARIES DF-6; IMPLEMENTATION_LEDGER L-11, L-12; UX_COPY S-REC-06 |
| Scope | The deltas listed under "A3" in the response's re-review scope. Anything else is out of scope, and nothing outside it was re-opened |

## Verdict

**APPROVE WITH CONDITIONS.**

Revision 3 closes the High finding S1-A3-R01 in the design. Recovery codes are now generated on the device and form a separate set that the api never sees or hashes. They travel only in an RFC 9180 HPKE envelope sealed to a pinned authority key, with purpose and environment in `info` and the answered challenge in `aad`. At a recovery start the code is sealed together with every new key id, and each new key's proof of possession commits to the envelope digest. The pinned-key revocation design (S1-A3-R02) and the tenant destination key registration (S1-A3-R03) now match what I asked for, item by item. No new primitive is introduced: HPKE with suite 0x0010/0x0001/0x0002 is the ADR-0007 suite, and RSA-OAEP-256 is used only to wrap a key.

Two new **Medium** findings remain, and neither changes the architecture:

- **S3-A3-01.** The 6-digit device-add comparison code can be ground by filtering challenges. The code is a public function of the challenge nonce and the key ids, so a compromised api can request challenges for a substituted entry until one matches the code the genuine new device shows. Only then does it forward that challenge to the approving device, and no failed attempt is ever counted. No cap on challenge issuance per entry or per account is stated.
- **S3-A3-02.** Residual R-23 is understated, and there is no production plan for it. Anyone who can read the seal key from authority memory can open every recorded set envelope. That yields **live** recovery codes for every account that registered a set under that key, and the codes stay valid after the incident ends. Lean staging is acceptable with mitigations. Production needs decryption inside the HSM or an explicit owner exception.

Four Lows and one Info point are specification gaps to close during implementation.

## Earlier findings: status

| Finding | Sev. | Status | Evidence | Remark |
|---|---|---|---|---|
| S1-A3-R01: codes visible to the api, same set the api hashes, start not bound to the new key | High | **CLOSED** (design) | ADR-0034 §1-§6; ADR-0032 §3.1-§3.3, §3.5; ADR-0023 §1 (envelope row), §4 (`recovery_codes_set`, `recovery_started` rows); THREAT_MODEL T-REC-8, AT-1 1.3.3 (stays [R] until ST-REC-14/-15/-16/-21 pass) | Item-by-item check below. Item 1: the set is generated on the device, the api's legacy set is invalidated, and a legacy start is refused once an authority set exists. Item 2: HPKE `info`/`aad` as required, `account_ref`, `set_id` and `nonce` inside the plaintext, `envelope_digest` in the factor JWS. Item 3: `new_kids` sealed, PoP string extended with `{envelope_digest}`, set equality enforced, head `pending_recoveries[].kids` checked by the recovering device. Item 4: 50 bits from a CSPRNG, normalization stated, keyed HMAC with lookup by value and the attempt counter in one transaction. Item 5: tests named. The residual R-23 is new; see S3-A3-02 |
| S1-A3-R02: revocation statement and its authority undefined | Medium | **CLOSED** | ADR-0033 §2 (payload with `key_family`), §3.1-§3.8; ADR-0023 §1; ADR-0028 §1 table, roles, explicit versions, `AUTH-STANDBY-ROLE`; ST-REC-13 extended, ST-REC-19 | Every listed item is present. Only the standby revokes, and only the active key. Revocations are sticky with no expiry, and after one the app accepts only the standby. The standby is a separate key object with no role until a reviewer-gated grant. Loss of both keys and routine rotation are stated, and the startup check uses the app-pinned set. Allowing the active statement key to sign seal-family revocations is acceptable: it can move sealing only to a standby it does not control. Two processing details are in S3-A3-04 |
| S1-A3-R03: tenant keys without PoP or domain binding | Medium | **CLOSED** | ADR-0031 §1.2-§1.5; ADR-0023 §1 (registration `typ`); THREAT_MODEL T-ML-9 | PoP payload as required; RFC 7638 thumbprint in DNS TXT `_viadere-destkey.<host>` or the well-known file. The evidence is fetched by `authority-admin.yml` (two DoH resolvers, or HTTPS with certificate validation), attested, and re-checked by the job. `not_after` ≤ 13 months; P-256 only, both S forms accepted; revocation works without the api. Checks on the nonce and the time window are in S3-A3-03 |
| S1-A3-R04: destination statement details | Low | **CLOSED** | ADR-0031 §2 (`seq`, replay window in R-07'), §3 (`url_sha256` encoding, exact members, ≤ 4096 bytes, `sub` marked unchecked), §4 item 4; ADR-0023 §2 (third `kid` definition) | Item 3 deferred as L-10 (owner A2, Stage 5); accepted |
| S1-A3-R05: device statement checks and cadence | Low | **CLOSED** | ADR-0033 §1 (`reported_name`, display for every purpose), §2 (`iss`/`env` in every check, `kid_header` removed, re-sign when the cached copy is older than 5 min at serving time) | — |
| S1-A3-R06: encodings and loose ends | Low | **CLOSED** | ADR-0032 §1.1 (truncation, full 32-character compare); ADR-0034 §2 (normalization); ADR-0023 §2 (builders emit RFC 7638 `kid`s, agreement vector), §5 (`swk`); ADR-0024 §7.3 (inventory channel through the job log, Log Analytics Reader and attestation) | — |
| S1-A3-R07: one key, four `typ`s | Info | **CLOSED** (adopted) | ADR-0033 §2 (single verifier, non-optional `typ`, exact member set, cross-`typ` vector) | — |
| S1-A3-R08: JWKS monitor scope | Info | **CLOSED** (adopted) | ADR-0024 §7.4 (discovery fields, unreachable alert, 45-min dead-man check) | — |

## Targeted checks (ADR-0034 and related)

| Check | Result |
|---|---|
| Suite and mode | RFC 9180 mode_base, single-shot, DHKEM(P-256, HKDF-SHA256) 0x0010 / HKDF-SHA256 0x0001 / AES-256-GCM 0x0002. `enc` = 65 bytes (Nenc for P-256), which is correct. This is the ADR-0007 suite (CryptoKit `P256_SHA256_AES_GCM_256`, swift-crypto HPKE). Base mode gives no sender authentication; it comes instead from the device signature over `envelope_digest` (factor JWS or PoPs). That is the right split. **OK** |
| `info` and domain separation | `"VIADERE-RECOVERY-SET-V1\n" ‖ env` and `"VIADERE-RECOVERY-START-V1\n" ‖ env`. The two purposes and the two environments are separated, and the seal key is dedicated, so there is no cross-protocol use with ADR-0007 E2EE keys. The DHKEM `kem_context` (`enc ‖ pkRm`) binds the recipient key, so `kid` need not go in `info`. **OK** |
| `aad` and replay | `ach ‖ "\n" ‖ nonce` (fixed `ach_` form, 43-character base64url nonce; unambiguous). The plaintext repeats `nonce` and `purpose`, which are checked against the challenge, and the challenge is single-use (ADR-0023 §3 step 9). An envelope replayed against another challenge fails AEAD. One replayed against the same challenge fails single use. One replayed against another account fails `account_ref` (set) or the verifier, which is keyed with `account_ref` (start). **OK** |
| Commitment | `envelope_digest = b64url(SHA-256(enc ‖ ct))`. It is in the factor JWS for a set and in every new key's PoP for a start. A ciphertext under one fixed recipient key cannot be opened under two keys, so a non-committing AEAD is not a problem here. **OK** |
| Binding of the code to the new keys | `new_kids` (device-key `KeyIdentifier`, sorted, 1-4 entries) is sealed with the code. The PoP string `VIADERE-KEYLOG-V1\n{env}\nrecovery_started\n{kid}\n{nonce}\n{envelope_digest}` is distinct from the `genesis`, `device_added` and `enrollment_confirmed` PoP strings. The set of PoP keys must equal `new_kids`, and activation adds exactly those keys. The recovering device checks the pending recovery's `kids` in the signed head. A compromised api that forwards a genuine envelope with its own key fails both the set equality and the PoP. **OK** |
| Code entropy and verification | 10 Crockford symbols = 50 bits from a CSPRNG, 10 per set, pairwise distinct. The verifier is `HMAC-SHA256(RECOVERY_VERIFIER_KEY, "recovery-code-v2\n" ‖ account_ref ‖ "\n" ‖ set_id ‖ "\n" ‖ code)`, and its key exists only in `kv-vdr-auth`. Lookup is by value, with the CAS `active → used` and the attempt counter in one transaction, and limits of 5 per account and 20 per recovery id in 24 h. Online success is about 5 × 10 / 2^50 per day, which is negligible, and offline search needs `RECOVERY_VERIFIER_KEY`. At a start, `set_id` is not in the plaintext, so the authority must use the account's single active set; this is implied but should be stated (S3-A3-05). **OK** |
| `approvalBiometric` for registration | Correct as a D1-equivalent rule: a key with `.biometryCurrentSet`, logged, grant-capable, past cool-down, and never a WebAuthn assertion (§3a). There is an availability side effect for devices without enrolled biometrics; see S3-A3-06 |
| Custody of the seal key | Generated in the reviewer-gated admin job, wrapped locally with RSA-OAEP-256 under a non-exportable RSA 3072 KEK (wrap/unwrap only), unwrapped once per replica start, every `unwrapKey` reconciled, and a separate standby KEK with no role. This is the best available while Key Vault has no ECDH operation. For lean staging it is **acceptable with the S3-A3-02 mitigations**. For production it is **not sufficient** without an owner exception (S3-A3-02) |
| Revocation statement | Payload exact; `key_family` per entry; signer and target rules per family; sticky; `issued_at` ≤ now + 60 s and no freshness limit, which is correct for an irreversible reduce-only statement. Rollback is possible only through an app update that pins a new list. `env` and `iss` stop replay across environments. Two processing gaps are in S3-A3-04 |
| Tenant key PoP and DNS binding | `typ` separated, `aud` scoped to the authority environment, admin-job nonce, `exp − iat ≤ 3600`. The thumbprint is published by the domain controller over DNS or HTTPS and fetched outside the api. That defeats the key substitution of S1-A3-R03 even if the change file is prepared from dashboard data. What the job must check on the nonce and time window is not stated (S3-A3-03) |
| Device-add comparison code | Input `"VIADERE-DEVICE-ADD-V1\n" ‖ env ‖ "\n" ‖ nonce ‖ "\n" ‖ join("\n", sorted kids)` is unambiguous: none of the fields contains `\n`. `decimal6` over 64 bits has bias ≈ 5.4 × 10^-14 (< 2^-44, as stated). Because the challenge nonce is chosen after the entry, an attacker cannot grind its key ids against a fixed nonce. It **can** grind nonces by requesting new challenges (S3-A3-01). A never displaying the code is correct, and I agree with the author's reading of A2's text |
| New `typ`/purpose separation | New `typ`s: `viadere-device-keys-revocation+jws` (pinned statement keys, `aud` device) and `viadere-destination-key-registration+jws` (tenant key, `aud` authority). Both are explicit and distinct from every other `typ`, and both are covered by the strict JOSE profile. The revocation list shares the statement key with three other `typ`s under the single typed verifier (R07). The HPKE envelope is not JWS and has its own `info`. The recovery-start passkey PoP uses a WebAuthn challenge = SHA-256 of a `VIADERE-KEYLOG-V1` string, which no other ceremony uses. The checks on `clientDataJSON` for that PoP are not listed (S3-A3-05). Consistency nit: ADR-0033 §1 defines a `recovery_started` display, but `recovery_started` is not a factor-JWS purpose in ADR-0023 §3. That is harmless, and the display is informational only. **No separation defect** |

## New findings (revision 3 only)

Severity: **Medium** must be resolved in the design before Stage 6 starts. S3-A3-01 must also be resolved before Stage 4 builds the comparison screens, and S3-A3-02's production part before any production authority. **Low** is resolved in the stage that builds the format, with vectors. **Info** is a recommendation.

### S3-A3-01: Medium: the device-add comparison code can be ground by filtering challenges

- **Location:** ADR-0033 §4.1 items 2-5; ADR-0023 §3 step 6; THREAT_MODEL T-REC-10, ST-REC-18.
- **Issue:** the code is a deterministic function of public values: `env`, the challenge `nonce` (in the signed challenge, which the api relays) and the key ids. A compromised api can therefore run this attack:
  1. It lets genuine new device B fetch its own challenge (nonce₁, kids_B) and computes the code c₁ that B shows.
  2. It submits a substituted `device_added` entry with its own kids_X.
  3. It requests `keylog_device_added` challenges for that entry over and over, computing f(nonceᵢ, kids_X) for each one locally.
  4. It forwards to approving device A only the challenge where f = c₁. A then shows a normal prompt, the person types c₁, and the authority's comparison succeeds.

  The expected cost is about 10^6 challenge issuances, and **no `match` failure is ever counted**, because unmatched challenges are never sent to A. The "≤ 3 × 10^-6" bound in §4.1 item 5 holds only for one challenge per entry. Revision 3 caps challenge signing per tenant (bulkhead), not per account or per entry. The 6-digit length is not the problem: short authentication strings are safe only when the attacker gets one try, and here the number of tries is unbounded.
- **Required change:**
  1. At most **one live** `keylog_device_added` challenge per pending `device_added` entry. A new challenge for the same entry is issued only after the previous one is used, has failed or has expired, and the total per entry is at most 3; after that the entry is refused and must be resubmitted.
  2. At most **one pending** `device_added` entry per account, and at most 5 `keylog_device_added` challenges per account per 24 h across entries. Any refusal on these caps raises an operator alert (it signals a filtering attempt).
  3. State the resulting bound in §4.1 item 5: success ≤ (challenges per account in the window) / 10^6, so ≤ 5 × 10^-6 per day per account.
  4. Extend ST-REC-18: a simulated compromised api that asks for a fourth challenge on one entry, or a sixth challenge per account per day, is refused and alerted; a vector shows that a filtering attempt across the permitted challenges stays within the stated bound.
  
  If the product wants a bound that does not depend on rate limits, an alternative is to raise the code to 8 digits or to add a commitment step (B commits to a fresh random value before the authority's nonce is revealed). A3 accepts the caps as sufficient.

### S3-A3-02: Medium: R-23 is understated, there is no plan for production custody, and the exposure window has no limit

- **Location:** ADR-0034 §5, "Threat assumptions changed"; THREAT_MODEL T-AUTH-6, T-AUTH-15, R-23; ledger L-12.
- **Issue:**
  1. R-23 says a process compromise can "open envelopes recorded since that key became active". The consequence is more serious. The api relays and can record every `recovery_codes_set` envelope (AS-1). Anyone who later reads the seal key from authority memory, even briefly (a memory disclosure, a crash dump, a debug session or a compromised sidecar), can open all those set envelopes. That yields the **currently valid** recovery codes of every account that registered a set under that key. These codes stay usable after the incident is contained and the seal key is rotated, because rotating the seal key does not invalidate any verifier. "The same compromise already reaches the signing builders" is true only while the compromise lasts; the stolen codes outlast it. The 72-hour hold and cancellation by logged devices limit the harm for accounts that still have a device, but not for the account population as a whole.
  2. No maximum lifetime is set for a seal key. ADR-0028's "yearly or on suspicion" applies to signing keys; the seal-key lifetime depends on app releases (§3.5). The exposure window is therefore open-ended.
  3. There is no target design for production. As far as A3 knows, neither Key Vault Premium nor Managed HSM offers an ECDH or key-agreement data-plane operation. The L-12 re-check is therefore likely to come back negative, which would leave R-23 in place in production by default.
- **Required change:**
  1. Restate R-23 in THREAT_MODEL and ADR-0034: "opens recorded set envelopes and so learns the live recovery codes of every account whose current set was sealed to that key; the codes remain valid after the incident until those sets are invalidated."
  2. Store the seal `kid` with each set (`authority_recovery_codes.seal_kid`). Add an incident procedure to KEY-ROTATION.md: on suspected process compromise or seal-key exposure, revoke the seal key (§3.3), **invalidate every authority set sealed to it**, and prompt those accounts to register a new set (S-REC-05). The test is an admin-job command, plus an ST case showing that sets sealed to a revoked seal key are refused at start.
  3. Give seal keys a maximum active lifetime (A3 recommends ≤ 12 months in staging and ≤ 6 months in production, aligned with the pinned-release cadence of §3.5), with re-registration prompts when a set's seal key retires.
  4. **Lean staging:** acceptable with items 1-3, the unwrap reconciliation and no real customer data (the lean-profile rule in CLAUDE.md already forbids real customer data).
  5. **Production (before any production authority or any real-customer recovery set):** one of the following.
     - (a) **Decryption inside the HSM.** Seal to an RSA 3072 (RSA-HSM) key in Key Vault Premium or Managed HSM with a standard construction: compact **JWE `alg: RSA-OAEP-256`, `enc: A256GCM`** (RFC 7516/7518). The protected header carries `typ` (`viadere-recovery-set+jwe` / `viadere-recovery-start+jwe`), `kid`, `env`, `ach` and `nonce`, and serves as the AEAD AAD. The authority makes one Key Vault `decrypt` per envelope, each reconciled against a request record. A process compromise then gives a decryption oracle only while it lasts, never a key, and recorded envelopes stay sealed afterwards. The authority's custom role gains `keys/decrypt/action` on that key only (`AUTH-SIGNER-ROLE` updated).
     - (b) HPKE as now, once the L-12 re-check finds a key-agreement operation in the HSM.
     - (c) An owner exception recording R-23 as a production residual. A3 would accept it only together with items 2-3 and with a lifetime of 90 days or less.
     
     Record the choice in ADR-0034 before Stage 6 closes.

### S3-A3-03: Low: tenant key PoP verification rules are incomplete

- **Location:** ADR-0031 §1.2.
- **Issue and required change:** state that the admin job:
  - (a) issues the `nonce` (at least 128 bits) in a first run, records it in the authority database with tenant, `kid` and expiry, and accepts it **once**;
  - (b) checks `iat` ≤ now + 60 s and `exp` ≥ now, in addition to `exp − iat ≤ 3600`;
  - (c) checks that `iss` equals the change file's tenant, `aud` its own environment, and `hosts[]` exactly the change file's hosts;
  - (d) applies the strict JOSE profile (header exactly `alg`, `kid`, `typ`; both S forms accepted).
  
  Also record that DNS evidence relies on two independent DoH resolvers without DNSSEC validation. Validate DNSSEC where the zone is signed, and refuse a DNSSEC-bogus answer. Add to ST-AUTH-16: a reused nonce and an expired PoP are refused. Vectors go in `auth-destination-v1.json`.

### S3-A3-04: Low: revocation-list processing details

- **Location:** ADR-0033 §2, §3.3.
- **Issue and required change:**
  - (a) A list that mixes valid and invalid entries is undefined. Refuse the **whole list** if any entry breaks a rule, so a partly valid list has no effect.
  - (b) Bound `revoked` to at most 2 entries (one per family).
  - (c) The app must store accepted revocations where they survive a reinstall (iOS Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`; Android Keystore-protected storage), not only in app data. Otherwise a reinstall brings back trust in the revoked key until the next list arrives, and a compromised api can withhold that list (widening R-22).
  - (d) State that a revocation is never "un-learned" by a later list that omits it. Stickiness is implied, but the list-replacement semantics should say so.
  
  Extend ST-REC-13/-19 accordingly.

### S3-A3-05: Low: loose ends in the sealed recovery specification

- **Location:** ADR-0034 §2, §4, §5; ADR-0032 §3.1-§3.2; ADR-0023 §3a item 3; ADR-0033 §1 (`recovery_codes_set` display).
- **Required change:**
  1. **`set_id` source.** The authority-built display of `recovery_codes_set` shows the set id, but the id is device-generated and sealed. Either the challenge request carries `set_id`, and authority processing step 3 requires the sealed `set_id` to equal it, or the display drops the set id. Neither is stated.
  2. **Start lookup.** State that at a start the verifier is computed with the account's single active set's `set_id`, and that the account comes from the challenge, never from the request.
  3. **Recovery-start passkey PoP.** List the WebAuthn checks for this PoP: `type = "webauthn.get"`, the challenge equal to SHA-256 of the PoP string, `rpIdHash`, an origin allow-list (the app's associated-domain origin only), and `crossOrigin` and `topOrigin` absent. Also state the COSE → SPKI conversion used for the passkey's `kid` in `new_kids`, with a vector.
  4. **Admin job hygiene.** The `seal-key create` job's log allow-list must contain only the public JWK and the thumbprint (that log feeds the attested inventory, ADR-0024 §7.3). Also state how the job's in-memory private scalar is cleared.
  5. **Vectors.** `recovery-seal-v1.json` should add a set envelope whose `account_ref` differs from the authorizing key's account, and a start whose PoP set is a strict superset or subset of `new_kids`.

### S3-A3-06: Info: availability side effects

- `approvalBiometric` (`.biometryCurrentSet`) is required to register a set. A person without enrolled biometrics therefore cannot register an authority set and stays on legacy recovery, which is never grant-capable. A change of biometric enrollment also invalidates the key, and the key must be re-added. This is the right security choice. The owner should see it in FLOW_MATRIX and UX_COPY, as copy for "set up Face ID / Touch ID to make recovery codes", and A6/A7 should confirm the Android `setUserAuthenticationParameters(…, AUTH_BIOMETRIC_STRONG)` equivalent.
- An HPKE failure counts as a failed start attempt, so a compromised api can burn the 5-per-day budget with garbage envelopes. It can already deny recovery by not relaying, so this adds no new capability. A3 accepts it, but the audit reason should tell AEAD failures apart from wrong codes, so operators can see the pattern.

## Conditions for Stages 4-6

| Stage | Condition |
|---|---|
| 4 (app) | S3-A3-01 is amended in ADR-0033 §4.1 (challenge caps, stated bound, ST-REC-18 extended) **before** the comparison-code screens are built. The app stores revocations as in S3-A3-04 (c) and refuses whole lists as in S3-A3-04 (a). KEY-ROTATION.md is written before any key is pinned (C-6, as already accepted), and it includes the seal-key incident procedure of S3-A3-02 item 2 and the lifetime of item 3. The single typed statement verifier (R07) and the cross-`typ` vector include `viadere-device-keys-revocation+jws` |
| 5 | Nothing new from this check. L-10 (subject statement) stays with A2 |
| Before Stage 6 starts | ADR-0034 and THREAT_MODEL R-23 are amended per S3-A3-02 items 1-3. The production option of item 5 is chosen and recorded (it may be "decided in Stage 6", but it must be decided before Stage 6 closes). A3 re-checks only those deltas and the S3-A3-01 amendment |
| 6 | Implement S3-A3-03, -04, -05 with vectors (`recovery-seal-v1.json`, `keylog-v1.json` including comparison-code and cap cases, `auth-destination-v1.json` with PoP cases, device-statement revocation vectors). ST-REC-13, -14, -15, -16, -18, -19, -21 and ST-AUTH-16 pass. Do the L-12 re-check (Key Vault and Managed HSM key-agreement operations; built-in Crypto User role definition) on Microsoft Learn |
| Flags | Unchanged from the previous verdict. No `AUTH_LINK_SERVICE_ENABLED`, `OIDC_PROVIDER_ENABLED` or `AUTHORITY_OIDC_ENABLED` for any account until ADR-0032 §3 and ADR-0034 are implemented and ST-REC-07, -08, -14, -15, -16 and -21 pass. `RECOVERY_REFRESH_PROMPT_ENABLED` stays off under the same condition (C-4) |
| Production | No production authority and no real-customer recovery set until the S3-A3-02 item 5 choice is implemented (HSM-resident decryption, HSM key agreement, or a recorded owner exception with a seal-key lifetime of 90 days or less) |

## Sign-off

Targeted check of Stage 1 revision 3 by A3 (cryptography and key management), 2026-11-02, at `2eadc4e`.

- **Verdict:** **APPROVE WITH CONDITIONS.**
- **Closed:** S1-A3-R01 (in the design; residual R-23 restated and conditioned by S3-A3-02), S1-A3-R02 and S1-A3-R03. S1-A3-R04 to -R08 are also closed.
- **New:** Medium S3-A3-01 and S3-A3-02; Low S3-A3-03 to -05; Info S3-A3-06.

This is an agent review record. It is not a third-party certification, and it does not replace the external review that spec §13 requires before any production identity provider.
