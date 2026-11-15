# Stage 1 review by A3 (cryptography and key management), 2026-11-02

| | |
|---|---|
| Reviewer | A3, independent agent reviewer; did not author any Stage 1 artifact |
| Request | `docs/reviews/STAGE1_REVIEW_REQUEST.md`, section "A3" |
| Baseline | branch `claude/inspiring-cannon-t5hxfw` at `0fab4ce` |
| Read | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §4, §6.3-§6.5, §9.3, §18, §19, §26, §27, §29, Part II; `docs/product/AUTH-OWNER-DECISIONS.md` (binding); `docs/architecture/TRUST_BOUNDARIES.md`; `docs/architecture/THREAT_MODEL.md` §3.4, §3.7, §3.10, §3.11, §4 (AT-1, AT-4), §6 (ST-AUTH, ST-GR, ST-OIDC, ST-WH), §8; ADR-0019, 0020 §3/§6, 0021, 0022, 0023, 0024, 0025, 0028 |
| Code checked | `ViadereCore`: `ContractSupport/ManifestJWS.swift`, `Approve/ApprovalResult.swift`, `Security/WebhookSignature.swift`, `Security/DeviceKeys.swift` (`ViadereSignatureEncoding`), `E2EE/E2EEKeys.swift` (`KeyIdentifier`), `Encoding/JSONValue.swift` (`CanonicalJSON`); server: `Security/KMS/KeyManagementService.swift`, `Azure/AzureKeyVaultKMS.swift`; `Infra/azure/keyvault.tf`, `locals.tf`; `docs/SECURITY.md` §2.1-§2.3 |
| Standards | RFC 7515, 7517, 7518, 7519, 7523, 7636, 7638, 8176, 8725, 9068, 9421, 9449, 9530, 9700; RFC 6238; OpenID Connect Core 1.0 §8.1 and Discovery 1.0 |

## Verdict

**APPROVE WITH CONDITIONS.**

The design uses only standard primitives: ECDSA P-256 (ES256), RSASSA-PKCS1-v1_5 with RSA 3072 (RS256), HMAC-SHA256, SHA-256 and AES-256-GCM. They are arranged in compact JWS/JWT, RFC 9421 and LF-delimited strings-to-sign, all of which already exist in the repo. **There is no bespoke cryptography (F-23 is satisfied).** The new items are wire formats over standard primitives, not new primitives. The JOSE profile is stricter than RFC 8725 requires, and it matches the code that already exists (`ManifestJWS`, `ApprovalResultJWS`).

The following parts are sound:
- the evidence model (authority challenge, then device JWS, then the authority key log, with single-use consumption after all checks);
- the "no raw sign route" rule;
- PKCE as S256 only;
- the `cch` binding of grants.

Four findings are rated **High**. All four fall where the authority's independence from the api depends on details that are not specified yet:
- who can publish JWKS (S1-A3-01);
- recovery that the api still verifies (S1-A3-02);
- genesis and key-log head binding (S1-A3-03);
- binding of `accountId` to the key-log account (S1-A3-04).

None of them blocks Stage 2-5 work (delivery-only flows, Approve v2 number matching, webhook v2). **They block the start of Stage 6 (authority implementation) and any enablement of `AUTH_LINK_SERVICE_ENABLED` or `OIDC_PROVIDER_ENABLED`.** The conditions are:

1. High findings S1-A3-01 to S1-A3-04 are resolved by amending the named ADRs (and THREAT_MODEL where noted) before Stage 6 starts.
2. Medium findings are resolved in the ADRs, or recorded as tracked items with an owner, before the stage that implements the affected format: Stage 2 for S1-A3-07, -08 and -09; Stage 6 for the rest.
3. Low and Info findings are addressed during implementation; each one needs a test vector or a note in `docs/protocol/vectors/`.

## Decisions put to A3 (review request, A3 checklist)

| Item | A3 position |
|---|---|
| JOSE profile (ADR-0023 §2) | **Accepted**, with S1-A3-12 (`kid` definition) and S1-A3-16 (JWKS `alg`/`use`) |
| Factor JWS verification order (ADR-0023 §3) | **Accepted**: consume after all checks, constant-time comparisons, ±60 s skew, `exp − iat ≤ 120`. Amend per S1-A3-05 (wrong-number counter) and S1-A3-06 (display object provenance) |
| `display_digest` domain separation | **Accepted**: `VIADERE-DISPLAY-V1\n` is a prefix-free label over canonical JSON |
| Key-log genesis replay / `account_ref` / shared `OIDC_PAIRWISE_KEY` | Genesis: **not accepted as written** (S1-A3-03). Two labelled uses of one HMAC key are cryptographically sound (the labels are prefix-free), but **a separate key is required** for operational reasons (S1-A3-13) |
| Grant claims, OIDC tokens, `jti`, pairwise `sub`, `cch` | **Accepted**, with S1-A3-04 (binding), S1-A3-14 (truncation ambiguity) and S1-A3-15 (namespaces, `private_key_jwt` audience) |
| `ApprovalResult` v2 | **Accepted** as an additive version, with S1-A3-08 (downgrade-proof verifier API) and S1-A3-09 (member set) |
| Webhook v2 MAC | **Accepted**: v1, v2 and the verification-response messages are disjoint by first byte (digit / `V` / `v`), so sharing one secret across them is safe during dual signing. Amend per S1-A3-07 (`kid` per MAC) and S1-A3-18 (dedup retention) |
| Key custody (ADR-0028) | **Accepted** with S1-A3-01, S1-A3-10 (version pinning), S1-A3-11 (role scope, backup), S1-A3-17 (pinned-key rollover) |
| `SUBJECT_REF_KEY` copy | **Accepted, conditional on S1-A3-04.** The claim "the api knowing it does not help" holds only if the authority checks that the `accountId` it hashes belongs to the account of the verified key |
| `kd-log-signing` verify-before-sign | **Accepted** as a plan: verifying an append-only consistency check against the last signed root before signing is the right semantic front end. It stays a tracked exception until C2 |
| Ed25519 absence (ADR-0024 §2) | **Accepted for now.** Key Vault (Standard/Premium) key types are EC P-256/P-256K/P-384/P-521 and RSA, with no Ed25519. ES256 meets spec §9.3 ("ECDSA P-256 or Ed25519"). Re-check in Stage 6 as the ADR already says |
| RS256 alongside ES256 (decision 3 in the request) | **Accepted.** OIDC Discovery 1.0 requires RS256, and RSA 3072 is adequate. Separate keys per algorithm are correct (no key reuse across algorithms) |
| RFC 9421 for live keys (decision 5) | **Accepted**, with S1-A3-19 |
| DPoP (RFC 9449) | Not claimed and deferred (ADR-0024 §10). That is consistent with spec §18. Nothing to review |
| TOTP (decision 3) | Viadere verifies no TOTP, the on-device seeds never leave the device, and `otpauth://` is refused in transit (ADR-0020 §6.3). RFC 6238 replay prevention is the business's job and has to be stated in the developer docs. **Accepted** |
| F-23 custom crypto | **Accepted**: custom formats over standard primitives only (list in the appendix) |

## Findings

Severity: **High** blocks Stage 6 start / authority-flag enablement; **Medium** must be resolved before the affected stage; **Low** must be resolved during implementation; **Info** is a recommendation.

### S1-A3-01 — High — JWKS publication is an unguarded trust root

- **Location:** ADR-0024 §7; ADR-0028 §6 and §8; THREAT_MODEL T-OIDC-2 and AT-1 1.5; TRUST_BOUNDARIES B10.
- **Issue:** RPs and the business SDKs trust whatever key appears in `/oidc/jwks.json` or `/grant/jwks.json`. Publishing a key is therefore equivalent to holding the signing key. If an attacker adds their own key there, they can mint id_tokens and grants without touching the authority, the Key Vault or the key log. But the publication path is an ordinary PR to `Site/content/id/`, deployed by the ordinary site workflow with its own Cloudflare token. That workflow is not behind the reviewer-gated authority environment (ADR-0028 §6 gates only `authority-deploy.yml` and `authority-admin.yml`). A compromised site deploy credential, or one merged PR, therefore defeats every authority control. This contradicts spec §9.4 ("compromised build credentials cannot silently update all trust authorities"). "Reviewed commit" in ADR-0024 §7 is the same review every ordinary change gets, so it adds no separation.
- **Required change:**
  1. Move JWKS publication for `id.<domain>` (discovery, OIDC JWKS, grant JWKS) into a dedicated workflow and GitHub environment (for example `authority-publish-<env>`). It needs the same required reviewers as authority deploys, branch `main` only, and its own Cloudflare token scoped to the `id.` route assets only. Remove the `id.` scope from the general site token.
  2. Add CODEOWNERS on `Site/content/id/**` and require code-owner review on that path.
  3. Admit a JWK to the published set only if it equals, by RFC 7638 thumbprint, a public key that the authority admin job printed from `kv-vdr-auth`. The publish job compares against a signed or attested admin-job output, not against a hand-pasted value.
  4. Add a scheduled monitor (outside both tiers' deploy identities) that fetches the live JWKS documents and alerts on any `kid` not in the authority's key inventory.
  5. Update T-OIDC-2 to name this control, and add tests `ST-OIDC-11`/`ST-GR-07`: an unreviewed change to `Site/content/id/` cannot deploy, and an unknown `kid` raises an alert.

### S1-A3-02 — High — Recovery still verified by the api lets AS-1 alone obtain grant-capable keys after 72 h

- **Location:** ADR-0023 §4 (`recovery_started` = "the api's statement", `recovery_activated`); ADR-0028 §4 ("existing code sets stay api-verified until the person regenerates them"); THREAT_MODEL T-REC-2, AT-1 1.3.3, R-02.
- **Issue:** Under AS-1 the api can claim "recovery code accepted" for any account, suppress the notices (R-02), and wait 72 h. `recovery_activated` then adds an attacker passkey to the authority log and revokes the victim's keys. The new key is grant-capable, so the attacker obtains link-service grants and id_tokens. The authority-timed hold and the key-log head only *detect* the attack, and only if the victim opens the app within 72 h. For an inactive customer this is a takeover by one compromised ordinary workload. That breaks spec §4.3 invariant 1 and reaches the §27 stop-ship rule ("any single ordinary public service can independently issue a successful authentication grant"). AT-1 marks the leaf [C], which overstates it.
- **Required change:** before link service or OIDC is enabled, choose one of the following and record it in ADR-0023 §4 and ADR-0028 §4:
  - (a) **import the existing recovery-code verifiers** into the authority in the same reviewed one-time snapshot as R-16 keys. That means the peppered HMACs, a copy of the pepper used for them, and the recovery id. The authority then verifies every `recovery_started` itself from day one.
  - (b) Keys added by a `recovery_activated` whose start was api-attested are **never grant-capable**. They become grant-capable only after a later authority-verified event, such as authority-held recovery codes being generated and a `device_added` proof by that key after a further hold.

  Either way, AT-1 1.3.3 must be re-rated, and a test (`ST-REC-05`) must show that an api-only recovery cannot yield a grant.

### S1-A3-03 — High — Genesis is first-come and the key-log head does not identify the account to the device

- **Location:** ADR-0023 §4 (genesis "refused if the authority has ever seen the account"; head `{account_ref, seq, head_hash, pending_recoveries[], issued_at}`; app verification); ADR-0023 "Consequences" (enrollment appends are retried by the outbox); TRUST_BOUNDARIES DF-5; THREAT_MODEL T-GW-3, T-REC-3.
- **Issue:**
  1. `account_ref` is computed from the `accountId` that the api supplies. For any account whose genesis has not yet landed (an account created during an authority outage while the outbox retries, or any account missing from the R-16 snapshot), a compromised api can submit a genesis containing **its own** keys with a valid proof of possession for those keys. The real device's genesis is then refused. "A forged genesis only creates an attacker's own account" is therefore not true for those accounts.
  2. The signed head carries `account_ref` and `head_hash` but no key list. The device cannot compute `account_ref` because it does not hold the HMAC key. So it cannot tell whether the head it was served belongs to its own account. The api can relay the head of another, clean account and hide pending recoveries and unknown devices, which defeats T-REC-3.
  3. Nothing requires `seq` to be monotonic on the device, so a stale but still-fresh head (within 15 min) can be replayed after a newer one.
- **Required change:**
  - The signed head payload includes the active key list (each entry's `kid`, purpose, `usable_from`, entry type and `imported` flag), and `aud`/`env` (`urn:viadere:authority:<env>`).
  - The app refuses a head that does not list its own current key `kid`s.
  - The app stores the highest `seq` it has accepted and refuses a lower one.
  - Enrollment does not count as complete (the device is not grant-capable, and the app shows a blocking security state) until the app has verified a head whose genesis or `device_added` entry contains exactly its own keys.
  - Genesis carries the device's App Attest assertion wherever the mode is not `off`.
  - The R-16 import refuses to run twice. It records the snapshot digest in the log, and it is followed immediately by synchronous genesis for new accounts (no outbox deferral for genesis).
  - THREAT_MODEL T-GW-3 must state the residual: a race against a not-yet-logged account is detected by the device, not prevented.

### S1-A3-04 — High — `accountId` supplied by the api must be bound to the account of the verified key before `sub` is computed

- **Location:** ADR-0023 §4 ("receives it in requests and recomputes"), §5 (`sub` = `subject_ref` via `SUBJECT_REF_KEY`); ADR-0024 §6 (pairwise `sub` from `accountId`); ADR-0028 §3; SECURITY §2.30 (`subject_ref` = HMAC over `VIADERE-SUBJECT-V1\nbusinessId\nconsumerId`).
- **Issue:** Both `subject_ref` and the OIDC pairwise `sub` are functions of the raw `accountId`, which the authority does not store and receives from the api. The key log identifies the signer's account only by `account_ref`. The ADRs never say that the authority checks `HMAC(K, "account-ref\n" ‖ accountId) == account_ref(kid)` before using `accountId`. Without that check, a compromised api can pair a valid evidence JWS from account A (the attacker's own device) with `accountId = V`, and the authority would compute V's `subject_ref`. That is exactly T-GW-4, which the ADRs claim is closed.
- **Required change:**
  - State in ADR-0023 §3 (as a new step between 3 and 4) and in ADR-0024 §6: every derivation of `sub` takes `accountId` only after it has been checked, in constant time, against the `account_ref` of the key-log entry that signed the evidence (or of the passkey that asserted). A mismatch is `evidence_invalid` plus an audit event.
  - The same applies to `tid`/`businessId` for `subject_ref`: take it from the authority's link-client or OIDC-client record, never from the request.
  - Add `ST-AUTH-05a`: valid evidence from A with `accountId = V` is refused.

### S1-A3-05 — Medium — Wrong-number guessing is limited only on the device

- **Location:** ADR-0022 §2.4 (3 attempts, a local counter); ADR-0023 §3 steps 6 and 9 (`ach` not consumed on failure); ADR-0021 §6; ADR-0024 §4.
- **Issue:** Two digits gives 90 values and three gives 900. Three attempts gives 3.3% (2 digits) or 0.33% (3 digits) per prompt for a customer who guesses to make a prompt go away. That is acceptable against fatigue only if the attempt limit is enforced by the verifier. For authority flows, a validly signed factor JWS with a wrong `match` fails at step 6 and leaves the `ach` pending. A modified or buggy client can therefore keep submitting, and nothing at the authority counts the failures. "A forged assertion cannot burn a real challenge" is right for *invalid signatures*, but a *valid signature with a wrong number* is a real attempt.
- **Required change:**
  - At the authority, a signature-valid assertion whose `match` is wrong increments `authority_challenges.match_failures` atomically. At 3 failures the challenge becomes `failed`, and the failure counts toward the per-account pause (ADR-0022 §5).
  - Only failures before signature verification leave the challenge untouched.
  - For Approve v2, the business SDK verifiers treat `invalid_match_attempts` as advisory and do not accept a second result for the same challenge (the existing `aud‖kid‖challenge` consumption already does this; state it).
  - Keep 2 digits for `auth.challenge` low/medium and OIDC/link cross-device, and 3 for payments and high/critical. Generate codes with uniform rejection sampling from a CSPRNG (SDK test vectors).

### S1-A3-06 — Medium — The display object behind `display_digest` comes from the api

- **Location:** ADR-0023 §3 (`display_digest`, step 5); TRUST_BOUNDARIES §4.3 (`POST challenges` takes "display object" from the api); ADR-0024 §8 (consent proof).
- **Issue:** `display_digest` proves that the device signed what it rendered, and that this equals what the api stored with the challenge. It does not prove that the display was true. A compromised api can make a challenge for client X display as "Bank Y" (business name, client display name, host). The device-signed evidence then "proves" consent to something the person never saw. This is the A2 checklist item "api-controlled input the authority trusts". The cryptographic consequence is that the digest binds api-chosen content.
- **Required change:** the authority builds the display object itself from its own records: the business display name from the link-client or OIDC-client registration, the client display name, the return-URL or redirect host from the registered URL, `match_digits`, and the purpose. It returns that object (or its canonical bytes) with the challenge, and the api may only relay it. Fields the authority cannot source are not in the object. The app renders exactly the relayed object.

### S1-A3-07 — Medium — The webhook v2 header cannot carry several keys

- **Location:** ADR-0025 §1 (`Viadere-Signature: t=…,kid=…,v2=…`, "several `v2=` entries during rotation"; `kid` is inside the string to sign).
- **Issue:** During rotation the two MACs come from two secrets with two `kid`s. But the header has one `kid=` parameter, and `kid` is part of the signed string, so at most one `v2=` entry can verify. Receivers would either fail during rotation or guess which `kid` goes with which entry. A parser that accepts the last `kid=` of several is also a canonicalization ambiguity.
- **Required change:**
  - Bind each MAC to its key in the header, for example `v2=<kid>:<mac>` with the `kid` charset `[a-z0-9_]{1,64}`. Allow exactly one `t=`.
  - Duplicate `kid` entries are malformed.
  - Every field in the string to sign has a stated charset that excludes LF: the method token, the A-label host with optional `:port`, the `path?query` RFC 3986 characters, the decimal `t`, the `evt_…` id, the tenant id and the `kid`. The verifier refuses inputs outside it.
  - Receivers compute the body digest from the received bytes and only *compare* `Content-Digest`; they never copy it into the string to sign.
  - Publish vectors covering rotation, a non-default port and a query string.

### S1-A3-08 — Medium — An `ApprovalResult` v2 verifier must not let the business downgrade by omission

- **Location:** ADR-0022 §3; `Packages/ViadereCore/Sources/ViadereCore/Approve/ApprovalResult.swift` (`ApprovalExpectation`, `claims(of:)` checks `v == 1` exactly).
- **Issue:** The rule "if the pending request has `number_match` then `v == 2` and `match == code`" depends on the business passing its stored code. If the SDK makes this an optional parameter that defaults to "none", any integration that forgets it accepts a v1 result, or a v2 result without `match`, for a number-matched request. The number-matching control then silently fails open at the business.
- **Required change:**
  - `ApprovalExpectation` (Swift, TypeScript, Kotlin) gains a **non-optional** `numberMatch: .notRequested | .required(code)`. It has no default value and every initializer requires it.
  - `.required` means `v == 2`, `match` is present, and the comparison is constant-time. `.notRequested` means `match` is absent, and v1 and v2 are both accepted.
  - The cross-language vectors include "number-matched request, v1 result" and "v2 result without `match`" as refusals.

### S1-A3-09 — Medium — The `ApprovalResult` v2 member set is inconsistent

- **Location:** ADR-0022 §2.4 (`invalid_match_attempts` "also reported in the result") versus §3 (v2 adds only `match` and `deny_reason`).
- **Issue:** The existing verifier checks the payload's exact key set. If the device adds a member the ADR does not list, every verifier refuses the result, and if the ADR lists a member the devices omit, the strict set check fails the other way. Optional members also need an allowed-set definition so that the strict check does not become a lenient one.
- **Required change:** list the v2 members exactly:
  - required: the v1 set plus `v = 2`;
  - optional: `match` (iff the request had `number_match`), `deny_reason` (only when `decision ∈ {deny, report}`), and `invalid_match_attempts` (integer 0-3) if it is kept.

  Each must have a format. The verifier checks `keys ⊆ required ∪ optional`, `required ⊆ keys`, and the conditional-presence rules.

### S1-A3-10 — Medium — Rotation timing breaks because `AzureKeyVaultKMS` follows the "current" key version

- **Location:** ADR-0028 §2 (a new version is published ≥ 24 h before it is "activated by an admin-job command"); ADR-0024 §7; `Server/Sources/ViadereServerKit/Azure/AzureKeyVaultKMS.swift` (resolves the current version with `GET keys/{name}`, cached 600 s); `Infra/azure/keyvault.tf` (new versions are created by crypto officers).
- **Issue:** In Key Vault a newly created version becomes the current version immediately. If the authority reuses `AzureKeyVaultKMS` unchanged, it starts signing with the new key within 10 minutes of creation, before the JWKS publication and its 24 h lead time. RPs then fail to verify tokens (an availability failure), and the "activation" step does nothing. Emergency rollover similarly depends on an explicit switch.
- **Required change:**
  - The authority signs only with an **explicit key version** (`name/version`) taken from its configuration, which the admin job changes. The version is never "latest".
  - At startup and on every switch, the authority checks that the version's RFC 7638 thumbprint is in its configured "published `kid`s" list, and fails closed otherwise.
  - Create new versions with `nbf` set to the planned activation time as a second guard.
  - `KeyManagementService` is extended for RSA (`RS256`) with the same verify-after-sign check.
  - Document this in KEY-ROTATION.md.

### S1-A3-11 — Medium — Key Vault semantics: what "non-exportable" means in lean, role scope, and the signer front end

- **Location:** ADR-0028 §2 (Crypto User, key scope, `exportable = false`, software keys in lean); TRUST_BOUNDARIES §4.1/§4.2; ADR-0023 §6; spec §9.3, §18, §4.4; THREAT_MODEL T-AUTH-5, T-AUTH-6, AT-4.
- **Issue:**
  1. On Key Vault Standard (lean), keys are software-protected. `exportable = false` refers only to Secure Key Release; it does not prevent a **key backup** blob. The built-in *Key Vault Crypto User* role, as Microsoft documents it, also includes `keys/backup/action` and `keys/update/action` besides sign/verify (re-verify on current Microsoft Learn in Stage 6). A backup blob can be restored into another vault in the same subscription and geography. In lean, the authority shares the subscription with an ordinary infra identity that has Contributor and constrained RBAC-admin rights. "Non-exportable" is therefore weaker in lean than TRUST_BOUNDARIES §4.1 suggests.
  2. Key Vault enforces no semantic policy. Any holder of the authority managed-identity token (any code path in the authority container, through the identity endpoint) can sign arbitrary digests. The authority process *is* the semantic signer front end (spec §9.3), but merged with the grant/policy logic, so a logic bug or RCE in any authority dependency (webauthn-swift parsing, Vapor) is a signing oracle. Spec §4.4 accepts this, but the design should make misuse detectable and harder to hit by mistake.
- **Required change:**
  - Use a **custom data-plane role** for `id-viadere-authority` with `keys/read` and `keys/sign/action` only (`verify` can be local). It must not have backup, update, encrypt/decrypt or wrap/unwrap. The crypto-officer PIM role keeps backup but uses it only by runbook.
  - Add an Azure Policy or `policy_check.py` rule that fails when any principal other than the officer group holds `keys/backup/action` on `kv-vdr-auth`.
  - In code, `GrantBuilder`, `OIDCTokenBuilder` and `KeyLogHeadBuilder` take a `VerifiedEvidence` (or `VerifiedCode`) value. Only the verifier can construct it (the type is not public and the initializer is file-private). The KMS `sign` call is reachable only through these builders, enforced by a test that scans the module for other call sites.
  - Enable Key Vault `AuditEvent` diagnostics on `kv-vdr-auth`. A worker-independent job reconciles every `sign` operation against `authority_grants` and key-log-head issuance records, and alerts on any unmatched signature. That detects use of the managed identity outside the builders.
  - Record in TRUST_BOUNDARIES §4.1 that "non-exportable" in lean means "no API export; backup restricted by role", and that standard means HSM.

### S1-A3-12 — Low — The `kid` definition conflicts with existing device key ids

- **Location:** ADR-0023 §2 (`kid` = RFC 7638 JWK thumbprint, "for device keys the same thumbprint indexes the key log"); `E2EE/E2EEKeys.swift` (`KeyIdentifier.make` = SHA-256 of the DER SPKI); SECURITY §2.54.
- **Issue:** Device-signed artifacts that exist today use SPKI-hash `kid`s. If device keys in the key log are indexed by RFC 7638 thumbprints, the device would have to emit a different `kid` for factor JWS than for Approve results. Two definitions for the same key invite lookup mistakes.
- **Required change:** keep `KeyIdentifier` (the SPKI SHA-256) for device keys in factor JWS and the key log, and use RFC 7638 thumbprints only for authority keys in JWKS. State both explicitly. Every verifier keeps the existing rule: look up by `kid`, then recompute the identifier from the stored public key and compare the full key.

### S1-A3-13 — Low — `OIDC_PAIRWISE_KEY` is used for two purposes

- **Location:** ADR-0023 §4 (`account_ref`), ADR-0024 §6 (pairwise `sub`), ADR-0028 §1.
- **Issue:** The labels `account-ref\n` and `oidc-sub\n` are prefix-free, so the two derivations are independent PRF outputs, and that part is fine. But the two have different lifecycles. `account_ref` is the authority's internal primary key and is relayed to devices. Pairwise `sub` is an external, RP-visible, effectively permanent identifier. Rotating either one for a suspected exposure would force re-keying the other: either the whole key log or every RP's subject mapping.
- **Required change:** create a separate `ACCOUNT_REF_KEY` (32 bytes, `kv-vdr-auth` secret, authority only) now, while it costs nothing. `OIDC_PAIRWISE_KEY` is then used only for `sub`.

### S1-A3-14 — Low — Pairwise `sub` encoding is ambiguous

- **Location:** ADR-0024 §6 (`base64url(HMAC-SHA256(...))` "truncated to 32 bytes").
- **Issue:** HMAC-SHA256 output is already 32 bytes. "Truncated to 32 bytes" could mean no truncation (43 base64url characters) or 32 characters (24 bytes, 192 bits). The inputs are also not pinned: whether `sector_identifier` is a lowercase A-label host and whether `accountId` is a lowercase UUID.
- **Required change:** specify `sub = base64url(HMAC-SHA256(K, "oidc-sub\n" ‖ sector_host_lowercase_alabel ‖ "\n" ‖ accountId_lowercase_uuid))` with no truncation (43 characters). The registration validator refuses LF in the sector identifier, and the spec adds a vector.

### S1-A3-15 — Low — Token audiences and namespaces

- **Location:** ADR-0023 §5 (grant `aud` = link client id); ADR-0024 §2/§6 (`aud` = OIDC client id; `private_key_jwt` `aud` = token endpoint URL).
- **Issue:**
  1. If a link client id and an OIDC client id can be the same string, the only things keeping a grant from being accepted as an id_token are `iss` and `typ`. They suffice in theory, but disjoint namespaces add an independent layer.
  2. For `private_key_jwt`, the 2025 OpenID Foundation advisory on client-assertion audience confusion recommends a single-valued `aud` equal to the authorization server's issuer identifier (draft RFC 7523bis), with arrays refused.
- **Required change:**
  - Link client ids use the `lcl_` prefix and OIDC client ids `ocl_`; registration enforces this.
  - Client assertions: `aud` must be a single string equal to the issuer (the token endpoint URL may be accepted as a single string during staging only), and arrays are refused. `alg` ∈ {ES256, RS256, PS256} is resolved from the registered JWK, never from the header alone. `jti` single use until `exp` + skew, and `iat` required.

### S1-A3-16 — Low — JWKS content and caching

- **Location:** ADR-0024 §7, ADR-0028 §2.
- **Required change:**
  - Every published JWK carries `kid`, `use: "sig"` and `alg` (`RS256` or `ES256`; RFC 7517 §4.4), so a verifier never pairs a key with another algorithm.
  - Serve with `Cache-Control: max-age ≤ 3600`, and purge the edge cache on publication.
  - SDK verifiers refetch on an unknown `kid` at most once per 5 minutes (no amplification).
  - Emergency rollover has a documented maximum RP exposure (cache TTL plus token lifetime).
  - The grant JWKS and the OIDC JWKS never share a key.

### S1-A3-17 — Low — `keylog-signing` is pinned in the app with no rollover path

- **Location:** ADR-0023 §4 (`VIADERE_AUTHORITY_KEYLOG_KEYS` build setting).
- **Issue:** A compromise or emergency rotation of `keylog-signing` would need an app release. Until users update, the app trusts either the compromised key or nothing.
- **Required change:**
  - Pin two keys from day one: the active key and a pre-created standby version, held disabled and unpublished until needed.
  - Heads carry `kid`.
  - Define the response to compromise: ship an app update removing the key; until then, the authority signs with the standby, and the app treats heads signed by the revoked `kid` as invalid once it learns of the revocation from an app-config list signed by the standby.

  Alternatively, record a residual risk with an owner.

### S1-A3-18 — Low — Webhook dedup retention is tied to the wrong timestamp

- **Location:** ADR-0025 §2.4 ("persist event id until `t + 24 h` … retries carry fresh `t`").
- **Issue:** Retention has to cover the whole retry horizon measured from the *first* receipt. Each retry carries a fresh `t`, so a store keyed on the first receipt and keeping entries for 24 h re-processes any retry that arrives after 24 h.
- **Required change:** retention is the maximum retry horizon of the delivery schedule plus 300 s, measured from first receipt, and documented with the schedule. Alternatively, the sender stops retrying before 24 h.

### S1-A3-19 — Low — The RFC 9421 profile needs more detail

- **Location:** ADR-0020 §3.
- **Required change:**
  - The verifier derives the algorithm from the registered key, and a contradicting `alg` parameter is refused (RFC 9421 §3.2 step 6).
  - Require `tag="viadere-biz-v1"` for application binding (RFC 9421 §2.3).
  - `ecdsa-p256-sha256` signatures are raw `r‖s`, and both S forms are accepted (SECURITY §2.1).
  - `@target-uri` is reconstructed from the canonical public origin, not the tunnel-internal host.
  - For bodiless methods, `content-digest` is omitted and refused if present.
  - Require `expires` ≤ `created` + 300.
  - Use the RFC 9421 Appendix B test vectors.

### S1-A3-20 — Low — The key-log hash chain and its proofs are underspecified

- **Location:** ADR-0023 §4 (`prev_hash`, `entry_hash`, genesis proof string).
- **Required change:**
  - Define `entry_hash = SHA-256("VIADERE-KEYLOG-ENTRY-V1\n" ‖ canonical(entry without entry_hash))`, with `prev_hash` of genesis = 32 zero bytes.
  - The genesis PoP string includes the environment (`…\n{env}\n…`).
  - `device_added` also requires PoP by the **new** key over the same string with `device_added`, so a public key the submitter does not control cannot be logged.
  - The authority checks that the new key's thumbprint equals the one in the signed display.
  - Head signing is on change, cached, and refreshed at most every 5 minutes, so `GET head` is not a Key Vault `sign` per request (throttling, a DoS lever).

### S1-A3-21 — Info — `uv`/`amr` for the user-presence key

- **Location:** ADR-0023 §3 (`uv` "must match the key purpose"), §5 (`amr` mapping); ADR-0021 §5.3 (link service signs with `approvalUserPresence`).
- **Note:** A `.userPresence` Secure Enclave key cannot prove which modality was used. Accept `uv = biometric` only from `approvalBiometric`, and map `approvalUserPresence` to a value that does not claim `pin`, or claim `pin` only with A1's agreement. Emit `hwk` only for keys attested as hardware-bound (relevant when Android arrives). This is mainly an A1 point.

### S1-A3-22 — Info — Canonical JSON in cross-language verifiers

- **Location:** ADR-0023 §2 ("re-serialized and compared byte-for-byte") applied to the TypeScript and Kotlin grant verifiers (ADR-0030).
- **Note:** The signature covers the bytes as received, so canonical comparison is a strictness measure, not a security dependency. The security-relevant part is refusing duplicate members and doing strict parsing. If byte comparison is kept in the SDKs, `docs/protocol/vectors/` must include escapes, non-ASCII, key-ordering and large-integer cases. SECURITY §2.2 sorts by UTF-16 code units, as RFC 8785 does, but it is not JCS, so it must not be called JCS.

## Appendix — new formats (F-23 inventory)

| Format | Primitive | Standard envelope | Custom part |
|---|---|---|---|
| `viadere-factor+jws` | ECDSA P-256 | RFC 7515 compact | claim set; `display_digest` (SHA-256, labelled) |
| `viadere-grant+jwt` | ECDSA P-256 | RFC 7519 | claim set (`cch`, `txn`, `tid`) |
| id_token / `at+jwt` | RSA PKCS#1 v1.5 or ECDSA P-256 | OIDC Core, RFC 9068 | none |
| `viadere-keylog-head+jws` | ECDSA P-256 | RFC 7515 | claim set; hash chain (SHA-256) |
| Key-log PoP | ECDSA P-256 | LF string-to-sign (as in `VIADERE-SIG-V1`) | label string |
| `account_ref`, pairwise `sub`, recovery verifier | HMAC-SHA256 | — | labelled inputs |
| Webhook v2 | HMAC-SHA256 | LF string-to-sign; RFC 9530 header | field list |
| Business request signing | ECDSA P-256 / Ed25519 | RFC 9421 | none |
| Link code, authorization code | CSPRNG 256-bit, SHA-256 at rest | RFC 7636 PKCE S256 | none |

None of these introduces a primitive, mode or construction outside these standards. Nothing combines password hashes into tokens (spec §9.3, §18).

## Sign-off

Review by A3 (cryptography and key management), 2026-11-02. Verdict: **APPROVE WITH CONDITIONS**. S1-A3-01 to S1-A3-04 must be resolved before Stage 6 starts and before any authority-backed flag is enabled. This is an agent review record, not a third-party certification. It does not replace the external review that spec §13 requires before any production identity provider.
