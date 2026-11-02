# Stage 1 re-review by A3 (cryptography and key management), 2026-11-02

| | |
|---|---|
| Reviewer | A3, independent agent reviewer; did not author any Stage 1 artifact or the revision |
| Earlier review | `docs/reviews/STAGE1_A3_CRYPTO_REVIEW.md` (APPROVE WITH CONDITIONS; High S1-A3-01 to -04) |
| Response reviewed | `docs/reviews/STAGE1_RESPONSE.md` (author revision 2) |
| Baseline | branch `claude/inspiring-cannon-t5hxfw` at `bfa9ff6` |
| Read | ADR-0020 §3, ADR-0022 §2-§3, ADR-0023 (all), ADR-0024 §2-§7, ADR-0025 §1-§3, ADR-0028 (all), ADR-0031, ADR-0032, ADR-0033 (new); `docs/architecture/TRUST_BOUNDARIES.md` rev. 2 (§2-§8); `docs/architecture/THREAT_MODEL.md` (T-GW-3/4/6/13/14, T-REC-2/3, T-AUTH-12/13, T-OIDC-2, T-CP-8, AT-1, §6 tests, R-07', R-16, R-21, R-22); `docs/product/AUTH-OWNER-DECISIONS.md` (binding, decisions 1-16); `docs/SECURITY.md` §2.1, §2.2, §2.26 |
| Code checked | `ViadereCore`: `ContractSupport/ManifestJWS.swift` (header allow-list, non-optional expected `typ`), `Security/DeviceKeys.swift` (`ViadereSignatureEncoding`, both S forms accepted), `E2EE/E2EEKeys.swift` (`KeyIdentifier`); server: `Security/KMS/KeyManagementService.swift` (`KMSSigningKey.kid()` = SPKI hash, P-256 only), `Azure/AzureKeyVaultKMS.swift` (unversioned refs use the current version, cached 600 s) |

## Verdict

**APPROVE WITH CONDITIONS.**

The revision fixes the four earlier High findings in substance. The authority now mints account ids. The device checks its own keys, `env` and a monotonic `seq` in the signed head. `accountId` is bound to the signing key's `account_ref` before any `sub` is derived. JWKS publication sits behind a reviewer-gated environment, an attested inventory and an independent monitor. The new surfaces (business-signed destinations, authority-signed tenant-key records, signed challenges, pinned active and standby keys) still use standard primitives only: ES256, SHA-256, HMAC-SHA256 and compact JWS under the existing strict profile. F-23 still holds.

One **new High** finding re-opens the core of S1-A3-02 by a different route. Under ADR-0032 §3 the authority-registered recovery codes are the **same codes** that the api hashes for its own flow, and they **travel in plaintext through the api** at registration and again at use. A recovery start also does not bind the code to the new key. So a compromised api (AS-1) can still finish an *authority-verified* recovery that yields grant-capable keys: S1-A3-R01. S1-A3-02 is therefore only partly closed. One Low (S1-A3-17) is partly closed and raised to Medium as S1-A3-R02, because the rollover is now load-bearing and its revocation statement is not specified.

Conditions:

1. **S1-A3-R01 (High)** is resolved by amending ADR-0032 §3 (plus TRUST_BOUNDARIES §4.3a and THREAT_MODEL T-REC-2/T-GW-14) **before Stage 6 starts**. It blocks any implementation of ADR-0032 §3 and any enablement of `AUTH_LINK_SERVICE_ENABLED`, `OIDC_PROVIDER_ENABLED` or `AUTHORITY_OIDC_ENABLED`. A3 re-checks only that delta.
2. **Medium S1-A3-R02 and -R03** are resolved in ADR-0033 §3 and ADR-0031 §1 before Stage 6 starts (R03 before any tenant destination key is registered).
3. **Low and Info items** (S1-A3-R04 to -R08) are handled during implementation in the stage that builds the format, each with a test vector or a note in `docs/protocol/vectors/`.
4. Stages 2-5 (delivery-only flows, Approve v2 number matching, webhook v2, app-side verification code without the authority) are **not blocked**.

## Previous findings: status

| Finding | Sev. | Status | Evidence | Note |
|---|---|---|---|---|
| S1-A3-01 JWKS publication | High | **CLOSED** | ADR-0024 §7.1-§7.6 (dedicated `authority-publish.yml` in `authority-publish-<env>`, `main` only, `id.`-only Cloudflare token, site token loses `id.`, site workflow refuses `Site/content/id/**`; CODEOWNERS; admission only by RFC 7638 thumbprint against an attested admin-job inventory; read-only 15-min monitor on unknown `kid` or any off-workflow change); ADR-0028 §6.5, §6.6.3, §8; TRUST_BOUNDARIES §2, B10, §4.2; THREAT_MODEL T-OIDC-2, T-CP-8, AT-1 1.5; ST-OIDC-15, ST-GR-07 | In staging the reviewer gate is a single owner approval (R-21, accepted as recorded). The channel that brings public keys from `job-viadere-authority-admin` into the attested GitHub artifact is not specified (S1-A3-R06 item 5) |
| S1-A3-02 Recovery verified by the api | High | **PARTIALLY CLOSED** | ADR-0032 §3.2-§3.3 (`recovery_started_legacy` never grant-capable; ST-REC-07, -08); ADR-0028 §4; THREAT_MODEL T-REC-2, T-GW-14, AT-1 1.3.3 | Option (b) is accepted, and the reasons for not adopting option (a) are accepted: a pepper copy is a real cost and the imported sets could already have been rewritten. But the new authority-verified path exposes its codes to the api (S1-A3-R01), so AT-1 1.3.3 cannot become [C] as written |
| S1-A3-03 Genesis and head binding | High | **CLOSED** | ADR-0032 §1.1-§1.7 (authority-minted UUIDv4, no caller-chosen id, synchronous genesis, outage accounts permanently refused, one-time import with digest, keyless accounts never grant-capable, `enrollment_confirmed` only after the device verifies a head listing exactly its keys); ADR-0033 §2 (head lists `keys[]`, `env`, `aud`, `kid`; device requires its own kids and `seq` ≥ the highest stored); ADR-0023 §4 genesis row (PoP with `{env}` and authority nonce, App Attest); ST-AUTH-15, ST-REC-12 | The race residual I asked to state no longer exists for minted ids, because an id that does not exist yet cannot be pre-empted. Agreed |
| S1-A3-04 `accountId` binding | High | **CLOSED** | ADR-0032 §2; ADR-0023 §3 step 3a, §5 (`sub`, `aud`, `tid` from the client record); ADR-0024 §6; ADR-0028 §3; TRUST_BOUNDARIES §4.3a (`accountId` row on `evidence`, `link-codes/redeem`, `oidc/token`); T-GW-4; ST-AUTH-05a | — |
| S1-A3-05 Wrong-number counting | Medium | **CLOSED** | ADR-0023 §3 step 6; ADR-0022 §2.1 (rejection sampling), §2.4; ST-AUTH-20 | — |
| S1-A3-06 Display provenance | Medium | **CLOSED** | ADR-0033 §1, §4; ADR-0023 §3 (`display_digest` over the authority-built object); TRUST_BOUNDARIES §4.3a "display text: not accepted"; ST-LS-08, ST-GW-07 | One display member, the device name, is not authority-sourced (S1-A3-R05 item 4) |
| S1-A3-07 Webhook `kid` per MAC | Medium | **CLOSED** | ADR-0025 §1 (`v2=<kid>:<mac>`, one `t=`, duplicates malformed, field charsets, digest compared not copied), §2; ST-WH-07 | — |
| S1-A3-08 Downgrade-proof verifier | Medium | **CLOSED** | ADR-0022 §3 (non-optional `numberMatch`, refusal vectors); ADR-0030 §2 | — |
| S1-A3-09 v2 member set | Medium | **CLOSED** | ADR-0022 §3 "Exact member set" | — |
| S1-A3-10 Version pinning | Medium | **CLOSED** (design) | ADR-0028 §2 (explicit `name/version`, thumbprint in published inventory, `nbf`, RSA in `KeyManagementService`, the current-version lookup not used); T-AUTH-13; ST-AUTH-22 | KEY-ROTATION.md deferred to Stage 6 (accepted). For `device-statement-signing` the "published" list must be the **app-pinned** set, not JWKS (S1-A3-R02 item 6) |
| S1-A3-11 Key Vault semantics | Medium | **CLOSED** | ADR-0028 §2 (custom role `keys/read` + `keys/sign/action`), §5 (`AUTH-KEY-BACKUP`, `AUTH-SIGNER-ROLE`); ADR-0023 §6 (`VerifiedEvidence` builders, module scan, `AuditEvent` reconciliation); TRUST_BOUNDARIES §4.1 "non-exportable" paragraph, §4.2; T-AUTH-12; ST-AUTH-21 | — |
| S1-A3-12 `kid` definitions | Low | **CLOSED** | ADR-0023 §2 | A third key class (tenant destination keys, RFC 7638 per ADR-0031 §1) must be added to that list. `KMSSigningKey.kid()` uses the SPKI hash today, so the authority builders must not reuse it for JWKS or pinned `kid`s (S1-A3-R06 item 4) |
| S1-A3-13 Separate `ACCOUNT_REF_KEY` | Low | **CLOSED** | ADR-0032 §4; ADR-0028 §1; TRUST_BOUNDARIES §4.1 | — |
| S1-A3-14 Pairwise `sub` encoding | Low | **CLOSED** | ADR-0024 §3, §6 | — |
| S1-A3-15 Audiences and namespaces | Low | **CLOSED** | ADR-0024 §2, §3 (`lcl_`/`ocl_`), §6 (single-string `aud` = issuer only; alg from the registered JWK; `iat`; `jti`) | Stricter than I asked (no token-endpoint `aud` even in staging). I confirm the stricter option |
| S1-A3-16 JWKS content and caching | Low | **CLOSED** | ADR-0024 §7.5 | — |
| S1-A3-17 Pinned key rollover | Low | **PARTIALLY CLOSED** | ADR-0033 §3; THREAT_MODEL R-22; ST-REC-13 | Two pins and `kid` in headers are in place. The revocation statement, the revocation authority between the two pins, and the behavior when both keys are lost are missing. Re-raised as **S1-A3-R02 (Medium)** |
| S1-A3-18 Dedup retention | Low | **CLOSED** | ADR-0025 §2.4 (horizon + 300 s from first receipt, Core constant tied to the backoff table) | — |
| S1-A3-19 RFC 9421 profile | Low | **CLOSED** | ADR-0020 §3 "RFC 9421 profile" | — |
| S1-A3-20 Hash chain and proofs | Low | **CLOSED** | ADR-0033 §4 (PoP by the new key, thumbprint check), §5 (`entry_hash`, zero `prev_hash`); ADR-0023 §4 (`{env}` in PoP); ADR-0033 §2 (cached head signing) | See S1-A3-R05 item 3 on refresh cadence |
| S1-A3-21 `uv`/`amr` | Info | **CLOSED** | ADR-0023 §3 (`uv`), §5; ADR-0024 §5 | Ruling below. The `amr` for unattested keys is missing (S1-A3-R06 item 3) |
| S1-A3-22 Canonical JSON naming and vectors | Info | **CLOSED** | ADR-0023 §2 | — |

### Ruling: no `pin` in `amr` (A6/A7 finding 16 versus S1-A3-21)

**Upheld: do not emit `pin`.** An `approvalUserPresence` key (`.userPresence` access control) is released by Face ID, Touch ID or the device passcode, and neither the device nor the authority can prove which one was used. `pin` would therefore be a modality claim that is false whenever biometrics were used, and an RP that branches on `pin` (for example "knowledge factor present") would be misled. `["hwk","mfa"]` is accurate: possession of a hardware key plus local user verification of some kind. `uv = biometric` from `approvalBiometric` (`.biometryCurrentSet`) mapping to `["hwk","user","mfa"]` is conservative and acceptable. RFC 8176 `user` is a presence test, so it could also be added to the `user_presence` row without overclaiming; that is optional and A1's call. Two conditions apply: the modality reported by `LAContext.biometryType` must never be turned into `face`/`fpt` (it is device-asserted, not attested), and the unattested-key case must be defined (S1-A3-R06 item 3).

## New findings

Severity: **High** blocks Stage 6 start and every authority-backed flag; **Medium** must be resolved before Stage 6 starts (R03: before the first tenant destination key is registered); **Low** is resolved during implementation, with vectors; **Info** is a recommendation.

### S1-A3-R01 — High — Authority-verified recovery codes are visible to the api, and a recovery start does not bind the code to the new key

- **Location:** ADR-0032 §3.1 ("The request carries the codes … The api keeps its own hashes for the existing flow"), §3.2; TRUST_BOUNDARIES §4.3a row `keylog/entries | recovery code | person via api`; DF-5; SECURITY §2.26 (10 codes of about 50 bits each, peppered HMAC at the api); THREAT_MODEL T-REC-2, T-GW-14, AT-1 1.3.3.
- **Issue:** the authority has no ingress except through the api (B5), so every recovery code reaches the authority **through the api in plaintext**, both when a set is registered and when a recovery starts. Three AS-1 attacks follow:
  1. **Capture at registration.** An api compromised while a person makes the post-release "Make new recovery codes" set (ADR-0032 §3.5, which every user is asked to do) logs the plaintext codes. Later it starts an authority-verified recovery for that account with one of them, suppresses notices (R-02), and after 72 h the recovered key is **grant-capable**. That is exactly the S1-A3-02 takeover, and here the start is authority-verified.
  2. **Offline search from api data.** Because the authority set is the same set the api hashes, an AS-1 that holds the api database and `SERVER_PEPPER` (both inside AS-1's reach) can search the 50-bit space offline. With 10 codes per account, an expected 2^50/10 HMAC-SHA256 evaluations is hours of GPU time per targeted account. The authority's keyed verifier and attempt limits do nothing against this, because the code is found offline and then presented once, correctly.
  3. **Key substitution at use.** `recovery_started` carries a code and the recovery passkey, relayed by the api. Nothing binds the code to the new public key, so AS-1 can forward a genuine person's valid code with **its own** passkey. A real person recovering a lost account (who by definition has no logged device to cancel) then gives the attacker a grant-capable key after 72 h.

  The authority's keyed HMAC store, attempt limits and hold are sound in themselves; the trouble is that the secret they protect is shared with the component they are meant to be independent of.
- **Required change (ADR-0032 §3, TRUST_BOUNDARIES §4.3a, THREAT_MODEL):**
  1. **Separate code sets.** Authority recovery codes are generated on the device independently of the api's codes, are never sent to the api in any form the api can use, and the api never stores a hash of them. (If the product wants one set for the user, the api's legacy set is retired once the authority set exists. Either way the api must hold nothing from which an authority code can be searched.)
  2. **Confidential to the authority in transit.** At registration the device sends the codes (or per-code verifier material) encrypted to an authority-held **encryption** key that is pinned in the app next to the `device-statement-signing` keys. Use HPKE (RFC 9180, the construction already used by ADR-0007) with a key held only by `id-viadere-authority`, or RSA-OAEP-256 with a `kv-vdr-auth` RSA key and the `keys/decrypt/action` data action added to the authority's custom role **for that key only** (`AUTH-SIGNER-ROLE` updated accordingly). The AAD binds `env`, purpose `recovery_codes_set`, `account_ref`, the set id and the authority nonce. The `recovery_codes_set` factor JWS commits to the ciphertext digest, so the api cannot swap in its own set.
  3. **Bound at use.** At `recovery_started` the device encrypts `{code, recovery id or set id, authority nonce, RFC 7638 thumbprint of every new key}` to the same authority key, and each new key gives a PoP over `VIADERE-KEYLOG-V1\n{env}\nrecovery_started\n{kid}\n{nonce}`. The authority refuses a start whose new keys differ from the thumbprints inside the ciphertext.
  4. **Entropy and storage.** Codes have at least 50 bits from a CSPRNG; this is adequate given (1)-(3) and the authority's online limits. Storage stays `HMAC-SHA256(RECOVERY_VERIFIER_KEY, …)`; I do not require Argon2id, because the key lives only in `kv-vdr-auth` and the codes are random. State the code normalization before hashing (alphabet, case folding, separators removed), and state that verification computes the HMAC of the presented code and either looks it up by that value or compares against each stored verifier in constant time, marking it used in the same transaction as the attempt counter.
  5. **Tests.** ST-REC-14: an api-side capture of the registration and start requests yields nothing that the authority accepts (ciphertext replayed to another account, nonce or new-key thumbprint substituted → refused). ST-REC-15: the api database and pepper contain no material that verifies an authority code. Mark AT-1 1.3.3 [C] only once these pass.
  6. If the owner instead accepts the api seeing codes, that is a §27 stop-ship exception ("any single ordinary public service can independently issue a successful authentication grant") and needs an owner decision and a named residual. A3 does not accept it as a design default.

### S1-A3-R02 — Medium — Pinned-key rollover: the revocation statement and its authority are unspecified

- **Location:** ADR-0033 §3; ADR-0023 §1 (type table); ADR-0028 §2 ("published `kid`s"); THREAT_MODEL R-22, ST-REC-13.
- **Issue:**
  1. `viadere-device-keys-revocation+jws` appears only in prose. It has no payload, is missing from the ADR-0033 §2 and ADR-0023 §1 type tables, and has no freshness or monotonicity rule.
  2. The rule "once it has verified a revocation signed by **a pinned key**" lets the holder of a compromised *active* key sign a revocation of the *standby*. An AS-1 that also controls the relay can then deliver only that revocation, and the app permanently distrusts the one clean key. Rollover is then defeated rather than merely delayed (worse than R-22 as stated).
  3. If the active and standby keys are versions of one Key Vault key, the realistic compromise route (code execution in the authority, i.e. use of `id-viadere-authority`, T-AUTH-12) reaches both once the standby is enabled, because the custom role is key-scoped, not version-scoped. The standby protects against key-material exposure (a lean backup blob), not against authority code execution. The ADR should say so.
  4. Loss of both keys (both compromised, or both destroyed) is not addressed. The consequence is that every head, challenge and tenant record fails closed: link service, OIDC app path and business-mode links stop, and S-SEC-01 is shown. Recovery is only through an app release.
  5. Routine (non-emergency) rotation needs an app release that pins the next key before the switch. This is not stated.
  6. ADR-0028 §2's startup check compares the version thumbprint against the "published inventory". For this key the relevant set is the app-pinned set.
- **Required change:**
  - Define `viadere-device-keys-revocation+jws`: `{v:1, iss, aud:"urn:viadere:device", env, revoked:[kid…], issued_at}`.
  - Pin roles in the app: index 0 = active, index 1 = standby. **Only the standby may sign a revocation, and it may revoke only the active key.** A revocation naming the standby, or signed by the active key, is refused.
  - Revocations are sticky (never undone without an app update), carry no expiry, and are stored by the app.
  - After the app verifies a standby-signed revocation, it accepts only standby-signed statements.
  - Create the standby as a **separate Key Vault key object** (for example `device-statement-signing-standby`), disabled, with **no** role for `id-viadere-authority` until rollover. The rollover role grant goes through `id-gh-infra-auth-apply` (reviewer-gated), so authority code execution before rollover cannot sign as the standby.
  - State the loss-of-both behavior (fail closed, app release, residual owner A3) and the routine rotation sequence (an app release pins `{current, next}` at least one release cycle before the switch).
  - ADR-0028 §2's startup check uses the app-pinned list for this key.
  - Add vectors and ST-REC-13 cases: an active-key-signed revocation of the standby is refused, and a revocation is sticky across restarts.

### S1-A3-R03 — Medium — Tenant destination keys are registered without proof of possession or a binding to the domain-control evidence

- **Location:** ADR-0031 §1.1-§1.2; ADR-0019 §5; TRUST_BOUNDARIES §4.1 "Tenant destination public keys".
- **Issue:** the admin change file names "the tenant, key, hosts and the domain-control evidence", and the reviewer checks the *domain* evidence. Nothing proves that the *key* came from the tenant. If the public key reaches the operator through the business dashboard or console (the api), AS-1 can substitute its own public key before the change file is written, and the reviewer approves it, because the domain evidence is genuine. The attacker can then sign destinations to **any path** on the tenant's verified hosts, which is an open-redirect or sensitive-path lever, and can deny service to the tenant's real key. There is also no proof that the registrant holds the private key, and no maximum key lifetime.
- **Required change:**
  - Registration needs a **proof-of-possession JWS** by the new key: `typ: viadere-destination-key-registration+jws`, payload `{v, iss: tenant_id, aud: "urn:viadere:authority:<env>", kid, hosts[], nonce (from the admin job), iat, exp}`.
  - The key's RFC 7638 thumbprint must appear in the domain-control evidence itself, as a DNS TXT `_viadere-destkey.<host>` value or in the well-known file. The admin job verifies the PoP and fetches the evidence itself, so the reviewer checks a thumbprint the job obtained from DNS or HTTPS, not one the dashboard displayed.
  - Set `not_after` ≤ 13 months, renewed through the same path.
  - Key type is P-256 only (ES256). The device verifier accepts both S forms (SECURITY §2.1), because business SDKs on Node and the JVM do not normalize S.
  - Extend ST-AUTH-16 so that a change file without a valid PoP or without the thumbprint in the evidence is refused by the job.

### S1-A3-R04 — Low — Destination statement and tenant record details

- **Location:** ADR-0031 §2-§4, §7.
- **Required change:**
  1. Pin `url_sha256` as base64url, without padding, of SHA-256 over the UTF-8 bytes of the URL exactly as returned by `open` (no normalization, no trimming). Note that `display_digest` uses lowercase hex; either is fine if stated.
  2. State that check 4 (`brq`, `purpose` against the delivery's display object) compares against **api-supplied** data. It gives integrity against misrouting, not against AS-1. AS-1 can pair a genuine statement with any delivery of the same tenant within `exp`. That is R-07', and the R-07' text should say so explicitly.
  3. `sub` is carried but cannot be checked by the device. Either drop it (it is otherwise only a pairwise identifier relayed through the api), or narrow R-07' as follows. The authority holds the `SUBJECT_REF_KEY` copy and can bind the account (ADR-0032 §2), so it can give the device a per-tenant `subject_ref` statement (`device-statement-signing`, new `typ`), obtained once with a factor JWS. The device then refuses a destination whose `sub` differs. This is a recommendation for A2 (owner of R-07').
  4. Add the third `kid` definition (tenant destination keys, RFC 7638) to ADR-0023 §2.
  5. The tenant record has no version counter, so the 15-minute revocation latency includes AS-1 replaying a pre-revocation record that is still fresh. State this. Optionally add a per-tenant `seq` that the app stores, as for heads.
  6. Statement size limits (≤ 4096 bytes) and "exactly the listed members" apply to the destination statement too.

### S1-A3-R05 — Low — Device statement checks and cadence

- **Location:** ADR-0033 §1, §2; ADR-0031 §2.
- **Required change:**
  1. Every statement check on the device includes `iss = urn:viadere:authority:<build env>` and, where present, `env`. The challenge row lists only signature, `typ`, `aud` and `exp`, so a staging statement could otherwise be accepted by a production build that pins the same key.
  2. Define `kid_header` in the head payload or remove it. The `kid` belongs in the JOSE header.
  3. "Refreshed at most every 5 minutes" must be phrased as a guarantee: a cached head or tenant record is re-signed when it is older than 5 minutes **at the time it is served**, so that a served statement is never older than the device's 15-minute limit minus relay time.
  4. `keylog_device_added` displays the "new device name", which comes from the new device through the api and is not authority-sourced. Mark it in the display object as reported text (for example `reported_name`), render it as such, and keep the thumbprints as the security-relevant members.
  5. `enrollment_confirmed` is a factor-JWS purpose with no display row in ADR-0033 §1. Define one (for example the device's own key thumbprints and `account_ref`) so that `display_digest` is defined for every purpose.

### S1-A3-R06 — Low — Encodings and loose ends

1. `account_ref = "acct_" ‖ hex32(HMAC…)`: state that this is the first 16 bytes (128 bits) in lowercase hex, and that the binding check recomputes the same truncation.
2. Recovery verifier input normalization: see S1-A3-R01 item 4.
3. `amr` for keys **without** hardware attestation (a `device_added` key with a 72 h hold): define `["swk","mfa"]` (or refuse grant capability for unattested keys), so that `hwk` is never implied by omission.
4. `KMSSigningKey.kid()` (`Server/Sources/ViadereServerKit/Security/KMS/KeyManagementService.swift`) derives the SPKI-hash `KeyIdentifier`. The authority's `GrantBuilder`, `OIDCTokenBuilder` and `DeviceStatementBuilder` must emit RFC 7638 thumbprints. Add a vector proving the JWKS `kid`, the header `kid` and the app pin agree.
5. ADR-0024 §7.3: name the channel by which the public keys printed by `job-viadere-authority-admin` reach the `authority-admin.yml` attestation (for example, the workflow reads the job's execution log with a read-only Log Analytics role and attests the parsed JWKs), and bind each JWK to its Key Vault `name/version`. Otherwise "attested" covers a value whose origin is not stated.

### S1-A3-R07 — Info — One key, four `typ`s: accepted with a verifier rule

The response asks A3 to confirm the key choice for `viadere-tenant-keys+jws`. **Confirmed.** Signing heads, challenges, tenant records and revocation lists with one `device-statement-signing` key, separated by `typ`, is sound because:
- every verifier is the app, built from one codebase;
- the payload member sets are disjoint;
- RFC 8725 §3.11 explicit typing is enforced.

Condition: one Core verifier, following the `ManifestJWS.verify(_:type:…)` pattern, takes the expected `typ` as a **non-optional** parameter and checks the exact member set per `typ`. A cross-`typ` vector shows each of the four presented as each of the others is refused.

Device-key signatures checked without `typ` remain domain-separated:
- the key-log PoP strings start with `VIADERE-KEYLOG-V1\n`;
- request signatures start with `VIADERE-SIG-V1`;
- a JWS signing input starts with `eyJ`.

These are prefix-free, so no signature in one format verifies in another.

### S1-A3-R08 — Info — JWKS monitor scope

The monitor (ADR-0024 §7.4) should also compare `issuer`, `jwks_uri` and the `alg` lists in the discovery document against the committed copy, and should alert when the documents themselves become unreachable. A silent outage of the monitor should page as well (dead-man check). This is a recommendation; T-OIDC-2 is closed without it.

## Conditions for Stages 2-6

| Stage | Condition |
|---|---|
| 2-5 | Not blocked. Stage 2 implements ADR-0025 v2 and ADR-0022 §3 exactly as amended, with vectors. Stage 4 (app) builds the single typed statement verifier (R07), the pinned pair with role semantics (R02), sticky revocations, `seq` storage for heads, and the business-mode destination checks of ADR-0031 §4 with R04 items 1 and 6 |
| Before Stage 6 starts | ADR-0032 §3 amended per **S1-A3-R01**; ADR-0033 §3 per **S1-A3-R02**; ADR-0031 §1 per **S1-A3-R03**; A3 re-checks those deltas only |
| 6 | Implement R05, R06 with vectors (`keylog-v1.json`, `auth-destination-v1.json`, a device-statement vector file, a recovery vector file); KEY-ROTATION.md including the device-statement rollover and loss-of-both runbook; ST-REC-14/-15 and the extended ST-REC-13 and ST-AUTH-16 pass. Re-check the Key Vault key types for Ed25519 and the built-in Crypto User role definition on Microsoft Learn, as already planned |
| Flags | No `AUTH_LINK_SERVICE_ENABLED`, `OIDC_PROVIDER_ENABLED` or `AUTHORITY_OIDC_ENABLED` for any account until R01 is implemented and ST-REC-07/-08/-14/-15 pass |

## Sign-off

Re-review by A3 (cryptography and key management), 2026-11-02, at `bfa9ff6`. Verdict: **APPROVE WITH CONDITIONS**. S1-A3-01, -03 and -04 are closed. S1-A3-02 is partly closed and superseded by the new High S1-A3-R01. S1-A3-17 is partly closed and superseded by S1-A3-R02. This is an agent review record, not a third-party certification, and it does not replace the external review that spec §13 requires before any production identity provider.
