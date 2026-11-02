# Stage 1 revision 3: targeted check by A2 (application security / threat model), 2026-11-02

| | |
|---|---|
| Reviewer role | A2. Independent of the Stage 1 author: did not write any reviewed artifact or the author response |
| Previous verdict | `docs/reviews/STAGE1_A2_SECURITY_REREVIEW.md`: BLOCK (narrow), baseline `bfa9ff6` |
| Baseline | `claude/inspiring-cannon-t5hxfw` at `2eadc4e`; deltas read with `git diff 4a84bde..2eadc4e -- docs/` |
| Read | `STAGE1_RESPONSE.md` "Revision 3"; ADR-0034 (whole); ADR-0032 §1.4-§1.7, §3, §5; ADR-0023 §3, §3a, §4; ADR-0033 §1-§4.1, §6; ADR-0031 §1-§4; ADR-0022 §5.1-§5.2 and §1 (code generation); ADR-0020 §2, §8 deltas; ADR-0024 §4 deltas; ADR-0028 key table and policy rules (seal rows only); TRUST_BOUNDARIES §1, §4.1-§4.3a, DF-5, DF-6; THREAT_MODEL T-REC-2, -8..-12, T-AUTH-6, -15, T-MFA-6, AT-1 1.3, §6 (new test ids checked by id), R-17, R-20, R-23; UX_COPY S-DEV-03..05, S-REC-04..06, S-SEC-04, S-MFA-14/-15, S-LINK-11/-12; ledger L-12, OQ-8..OQ-10 |
| Not re-read | Material unchanged since `bfa9ff6`, which the earlier reviews already accepted |

## Verdict: **APPROVE WITH CONDITIONS**

Revision 3 does what the block asked. The three blocking paths are closed in their structure:

- Recovery codes now travel only as HPKE envelopes to a pinned authority key, as a set the api never sees or hashes, bound to the new keys at start (S2-A2-1).
- No passkey assertion can add a key (S2-A2-2).
- A device add needs a comparison code that the new device derives from its own key ids (S2-A2-3).

All seven Mediums and the Low items are closed. The author's clarification on S2-A2-3 is **confirmed**: the existing device must never show the code. The authority computes the expected value, and the person types the number shown on the new device. That is what I meant.

One new **High** finding remains: **S3-A2-1**. As written, the comparison code can be ground. Nothing limits how many `keylog_device_added` challenges AS-1 may obtain per entry, nor how many entries may be pending per account. Nothing says the challenge nonce is drawn only after the entry's keys are fixed. A birthday search over about 2 000 authority challenges, or an offline search over attacker keys if the nonce is known early, therefore defeats the code.

I am not blocking on it, for three reasons:

1. The control is the right one. The gap is a missing quantitative bound that I failed to specify in S2-A2-3.
2. The fix is three normative sentences, given below.
3. Nothing is coded before the Stage 2 contracts.

The fix is therefore condition **C-13**, a hard gate before the Stage 2 authority contract is frozen, checked by A2 against the documents with no further review round. If C-13 is not met, this approval does not apply to Stage 2.

R-23, the seal private key held in authority memory, is **acceptable for the lean staging pilot** under C-15. It is **not acceptable for production** as written. C-16 sets the production gate.

## 1. Open findings from the previous verdict

| Finding | Sev. | Status | Evidence | What remains |
|---|---|---|---|---|
| **S2-A2-1** codes and recovery key through the api in clear | Critical | **CLOSED** (design) | ADR-0034 §1-§6: HPKE suite 0x0010/0x0001/0x0002, per-purpose `info` containing `env`, `aad = ach‖nonce`, strict wire form, `envelope_digest` committed by the factor JWS (set) and by every new key's PoP (start); codes generated on the device, api holds no hash (§3); keyed verifier with CAS (§4.6). ADR-0032 §3.1: `approvalBiometric`, D1-equivalent, previous authority set invalidated. §3.2: sealed `new_kids`, PoP keys = `new_kids`, head `pending_recoveries[].kids` checked by the recovering device; a legacy start is refused when an authority set exists. §3.5: refresh prompt gated (C-4). ADR-0023 §4 rows; TRUST_BOUNDARIES §4.3a, DF-6; T-REC-8; AT-1 1.3.3 stays [R] until ST-REC-14..-16 and -21 pass | R-23 (§3 below), conditions C-15 and C-16. Custody details in S3-A2-3 |
| **S2-A2-2** passkey assertions add keys | High | **CLOSED** | ADR-0023 §3a items 1-5: assertions accepted only for `oidc_login` and the reduce-only `recovery_cancel`, with a per-purpose origin allow-list held in authority config; `crossOrigin` and `topOrigin` refused. `passkey_added` only by factor JWS from the creating device. The recovery PoP assertion authorizes nothing and has a domain-separated challenge. ADR-0024 §4 R-17 narrowed to one session; T-REC-9; AT-1 1.3.4; FLOW_MATRIX F10; ST-REC-17 | — |
| **S2-A2-3** device add not bound to the device held | High | **PARTIALLY CLOSED** | ADR-0033 §1 (`reported_name` labelled, `kids`, `match_digits: 6`), §4.1 items 1-5 (B checks exact `kids`; derivation with `env`, nonce, sorted `kids`; A never shows the code; authority recomputes from the stored entry; approving key checked against the account); DF-5; S-DEV-03..05; ST-REC-18. Clarification confirmed (above) | **S3-A2-1**: the code can be ground. No bound on challenges per entry or entries per account, and the timing of the nonce is unspecified. Fixed by C-13 |
| S1-A2-2 remainder | Critical | **CLOSED** (design) | via S2-A2-1 and S2-A2-7 | Same R-23 conditions as S2-A2-1 |
| S1-A2-6 remainder / **S2-A2-9** collapse supersedes the victim | High / Medium | **CLOSED** | ADR-0022 §5.2: supersession only with the same business `session_handle`; grouping; the typed number selects the request; a collision signs nothing (S-MFA-15); Deny and Report answer the group as one count; nothing is refused or cancelled because of a count (§5.1). ADR-0020 §2 and §8 changes are additive. R-20 narrowed; ST-MFA-10 extended | Collisions are not bounded by Viadere: **S3-A2-2** (Medium). `session_handle` derivation rules: S3-A2-6 (Low) |
| S2-A2-4 enrollment confirmation | Medium | **CLOSED** | ADR-0032 §1.4: `head_hash` and `seq` in the factor JWS, PoP by every key over `head_hash`, grant-capable only when all keys confirmed the same head; imported accounts confirm per device with S-SEC-05; "exactly" versus "contains" made explicit in ADR-0033 §2; ST-AUTH-23 | — |
| S2-A2-5 revocation against the standby | Medium | **CLOSED** | ADR-0033 §3.2-§3.6: separate standby key objects with no role until a reviewer-gated rollover; statement-family lists signed only by the standby and naming only index 0; sticky; routine rotation through an app release plus `AUTHORITY_MIN_APP_VERSION`; loss of both stated. Seal-family lists may be signed by the active statement key, which is acceptable: its worst effect is availability, and that key's holder can already do more. ST-REC-19; C-6 moved to Stage 4 | — |
| S2-A2-6 unauthenticated authorize | Medium | **CLOSED** | ADR-0024 §4: sign-free client check on load; challenge only after a CSRF-protected method choice; `oidc-authorize-ip` and `-client` fail-closed limits; ADR-0033 §2 per-tenant challenge bulkhead with reserved capacity for heads, tenant records, revocations and grants; ST-OIDC-17, ST-AUTH-24 | — |
| S2-A2-7 S-REC-04 self-service path | Medium | **CLOSED** | UX_COPY S-REC-04 rewritten; ADR-0032 §3.3 states both paths (an earlier authority set, or admin job); ST-REC-20 | A9 sign-off under C-12 |
| S2-A2-8 permanently limited accounts | Medium | **CLOSED** | ADR-0032 §1.5 option (a): no consumer without a minted id; retries; S-SEC-04; L-1 closed | OQ-8 owner wording pending (not a security blocker). The retry path adds S3-A2-4 (Low) |
| S2-A2-10 verification failures as denials | Medium | **CLOSED** | ADR-0031 §4 failure classes, neither counted toward the pause; §1.2 registration PoP, thumbprint in DNS or the well-known file fetched by the reviewer-gated workflow; §1.3 13-month `not_after`; §1.5 revocation without the api and automatic host removal; T-AUTH-8, F1/F2; S-LINK-11/-12; ST-ML-15 | S3-A2-5 (Low): the api can steer some integrity failures into the silent class |
| S2-A2-11 items 1-4 | Low | **CLOSED** | T-GW-5, T-AUTH-7; "re-signed when older than 5 min at serving"; `swk`; `account_ref` checks in ST-REC-10 | — |
| S2-A2-11 item 5 (optional) | Low | **Deferred, accepted** | ledger L-10, owner A2, Stage 5 | — |
| S1-A2-7 note, S1-A2-8 remainder, S1-A2-12 remainder | — | **CLOSED** | ADR-0027 §1.3 (dormant owner); §4.3a new rows; R-17 narrowed; AT-1 1.3.3 stays [R] | — |

Ruling 7 of the first review (authority key log only with S1-A2-1 and S1-A2-2) is satisfied at design level, subject to C-13 and C-15.

## 2. New findings (introduced or exposed by revision 3)

Severity scale as before.

### S3-A2-1 — High — the device-add comparison code can be ground

- **Location:** ADR-0033 §4.1 items 1 and 5; DF-5; ADR-0023 §4 `device_added` row; ADR-0020 §8 (`authority-challenge` per account, no number).
- **Issue:** The code is a 20-bit value of (`env`, nonce, sorted `kids`), and every input is visible to AS-1.
  1. **Birthday attack.** AS-1 submits B's genuine entry E_B and a substituted entry E_X. It then requests many `keylog_device_added` challenges for each; nothing limits the number per entry. Because AS-1 can compute every code itself, it keeps one challenge for E_B and one for E_X whose codes are equal. B accepts its genuine challenge and shows that code, the person types it on A, and A signs over the E_X challenge. The authority's expected code for E_X matches. About 1 000 challenges per entry give an expected collision; each costs only one challenge-bulkhead `sign`.
  2. **Offline grinding.** §4.1 item 1 has the new keys sign a PoP over a `nonce` before the challenge exists, and the code uses "the challenge's nonce". If these are the same nonce, or any nonce AS-1 learns before E_X's keys are fixed, AS-1 generates attacker key sets offline until the code equals B's. That takes about 10^6 P-256 key generations, a matter of seconds.

  The "≤ 3 × 10^-6" bound in §4.1 item 5 holds only for a single challenge per entry with a nonce drawn after the keys are fixed. Neither condition is stated.
- **Required change** (normative text in ADR-0033 §4.1, ADR-0023 §4 and the Stage 2 authority contract):
  1. The comparison nonce is drawn by the authority **when the `keylog_device_added` challenge is created, after the entry and its `kids` are stored**. It is distinct from every PoP nonce. The PoP nonce for `device_added` is a separate, earlier authority nonce.
  2. **One challenge per entry.** A `device_added` entry gets exactly one `keylog_device_added` challenge in its lifetime. A failed, expired or cancelled challenge ends the entry, and B must start again with new keys. **At most one pending `device_added` entry per account**: a new one cancels the previous entry and its challenge. **At most 5 `device_added` entries per account per 24 h** at the authority, fail closed and audited, with an alert above 3.
  3. Restate the bound in §4.1 item 5 in these terms (≤ 5 × 10^-6 per account per day) and add **ST-REC-22 (A)**. A second challenge for the same entry is refused. A second pending entry cancels the first. The sixth entry in 24 h is refused. A PoP nonce is never accepted as a comparison nonce.

### S3-A2-2 — Medium — number collisions in a group are not bounded by Viadere

- **Location:** ADR-0022 §1 (the **business** generates `match_code`), §5.2 items 2 and 4; R-20.
- **Issue:** Revision 2's three-pending cap is gone, and the group size k now depends only on the business's trigger throttle and expiry. At k ≥ 45 open attacker requests, half of the victim's attempts collide. At about 90 (2-digit codes), every attempt collides, which is again an attacker-controlled lockout (§23). Viadere could prevent collisions outright, because it sees the group when each request is created.
- **Required change:**
  - At create, the api refuses a request whose `match_code` equals the code of any open request in the same group, with `409 match_code_in_use`. This is not a fatigue count. The SDKs redraw and retry transparently.
  - With that rule there are no collisions while k is below the size of the code space. State the remaining bound in R-20: a lockout needs about 89 (2-digit) or 899 (3-digit) concurrently open requests for one (tenant, subject).
  - Alert operators and the business when an open group exceeds 10.
  - S-MFA-15 then remains only as a defensive path.
  - Test **ST-MFA-11 (A)**: with 20 attacker requests open, the victim's request is created with a distinct code and is completable.

### S3-A2-3 — Medium — `recovery-seal` custody gaps

- **Location:** ADR-0034 §4.6, §5.1-§5.3; ADR-0028 `AUTH-STANDBY-ROLE`; TRUST_BOUNDARIES §4.2 (`id-viadere-authority-admin`: "no Key Vault role", no INSERT on `authority_seal_keys`); ST-AUTH-21.
- **Issue:**
  1. **Grants.** `seal-key create` needs `keys/read` on both KEKs and INSERT on `authority_seal_keys`. The admin identity has neither. Granting `keys/read` on `recovery-seal-kek-standby` would also trip `AUTH-STANDBY-ROLE`. One of these documents is wrong, and an implementer will "fix" it by widening a role.
  2. **Standby generated with the active key.** Both private keys are generated in one admin-job process, so a compromised admin-job image or run exposes the standby too. The standby's protection ("authority code execution before rollover cannot open envelopes") does not cover the admin path.
  3. **No targeted invalidation.** Verifier rows do not record which seal key carried the set. After an R-23 event, the operator cannot invalidate exactly the sets that key could have exposed.
  4. **No reconciliation test.** No test covers the per-start `unwrapKey` reconciliation. ST-AUTH-21 covers `sign` only.
- **Required change:**
  1. Name the creation identity and its exact grants in TRUST_BOUNDARIES §4.2 and ADR-0028. The KEK public halves should be supplied as attested inputs (thumbprints in the key inventory) rather than through a data-plane role on the standby KEK. Make `AUTH-STANDBY-ROLE` consistent with that.
  2. Generate the standby in a **separate** reviewer-gated run from the active key.
  3. Add `seal_kid` to `authority_recovery_codes`. Add a KEY-ROTATION.md procedure "seal key exposed": revoke the seal key (seal-family list), invalidate every set with that `seal_kid`, raise a head flag so the app prompts S-REC-05, and keep the account's grant capability. A forced code refresh is not a downgrade.
  4. Extend ST-AUTH-21, or add ST-AUTH-25, so that an injected unmatched `unwrapKey` alerts.

### S3-A2-4 — Low — key ids can appear in more than one account

- **Location:** ADR-0032 §1.2, §1.5 (retry with backoff); ADR-0023 §3 step 2 ("`kid` is in the key log").
- **Issue:** With retries, genesis can succeed at the authority while the consumer row is never created. A retry may then mint a second account with the same device keys. The design does not say that a `kid` resolves to exactly one account, and binding step 3a assumes it does. Orphaned minted accounts also accumulate.
- **Required change:** the authority refuses `genesis`, `device_added` and `recovery_started` when a submitted `kid` is in a non-revoked entry of **any** account (`409 key_in_use`). On retry, the app generates new keys. A minted account with no `enrollment_confirmed` within 24 h is closed, its keys revoked and the closure audited. Add both cases to ST-AUTH-15.

### S3-A2-5 — Low — the api can move integrity failures into the silent class

- **Location:** ADR-0031 §4 failure-class table.
- **Issue:** The clock-skew test uses the api's `Date` header. A "record `seq` lower than stored" is classified as availability, although it is evidence of a replayed record. AS-1 can therefore make a replayed or expired statement look like an outage, and the high-priority alert never fires. The URL is still never opened, so only detection is lost.
- **Required change:** classify a lower `seq` as `destination_mismatch`. Judge clock skew against the authority-signed `issued_at` of a fresh head or tenant record, not against the api's `Date` header. Keep client telemetry for every availability-class failure.

### S3-A2-6 — Low — `session_handle` derivation is only an example

- **Location:** ADR-0022 §5.2 item 1; ADR-0020 §2.
- **Issue:** Supersession is safe only while the handle is unguessable and tied to one session. A business that sends a constant value, or one derived from the subject, gives the attacker back the power to cancel the victim's prompt.
- **Required change:**
  - The SDK helper derives the handle as `HMAC(business_secret, initiating_session_id)`, and the documentation states the requirement as a MUST.
  - The api ignores a `session_handle` that it has seen on more than 3 distinct `request_id`s within 10 minutes for different initiating clients, if that is detectable. At minimum it alerts when one handle repeats across more than 20 requests per hour.
  - Add vectors and a sentence in the RP integration guide.

## 3. Ruling on residual R-23 (seal private key in authority memory)

**Facts.** Key Vault Standard and Premium offer no ECDH data-plane operation (ledger L-12 asks for a re-check). After one `unwrapKey` at start, the active HPKE private scalar lives in authority process memory. An authority **process** compromise can read it. Combined with envelopes that the api recorded at any time, that compromise opens every code set registered under that key since it became active.

The significant difference from the existing T-AUTH-12 exposure is **persistence**. A process compromise that reaches the signing builders ends when the process is cleaned. Codes taken from it remain valid afterwards, together with every code set that the api relayed in the past.

**Staging pilot (lean profile): acceptable.** Reasons:

- It needs the authority process itself, the most protected component, and that compromise is already a stop-ship event.
- Lean keys are software-protected anyway and are never reused (CLAUDE.md exceptions).
- The pilot population is small and known.
- A full set rotation is a cheap, non-downgrading remedy.

The conditions are in C-15: the S3-A2-3 fixes, a drilled mass-invalidation runbook, memory hygiene in the authority container, and pilot seal keys never reused.

**Production (standard profile): not acceptable as written.** R-23 currently says "removal: none planned". Before any production authority environment, one of these is required:

- (a) The seal private key never leaves an HSM boundary. Use a Managed HSM or Key Vault key-agreement operation if L-12 finds one. Otherwise use A3's alternative: an RSA-OAEP-256 hybrid envelope (a fresh AES-256-GCM key wrapped to a non-exportable `RSA-HSM` 3072 key), with one Key Vault `unwrapKey` or `decrypt` per envelope, inside a dedicated bulkhead.
- (b) An owner exception signed by A2 and A3 that names the compensating controls and a review date.

I recommend (a). The per-request Key Vault cost is small, because recovery events are rare. Record this as R-23's removal condition (C-16).

## 4. Conditions for Stages 2-6 and the pilot

C-1 to C-12 of the previous re-review **stand unchanged**. The C-1 test list now also includes ST-REC-22, ST-MFA-11 and ST-AUTH-25. New conditions:

| # | Condition | Gate |
|---|---|---|
| C-13 | S3-A2-1 fixed in ADR-0033 §4.1, ADR-0023 §4 and DF-5 (nonce drawn after the keys are fixed, one challenge per entry, one pending entry and 5 entries per account per 24 h, ST-REC-22). The Stage 2 authority OpenAPI encodes the limits. A2 checks the documents; no further review round | **before the Stage 2 authority contract is frozen** |
| C-14 | S3-A2-2 (`409 match_code_in_use`, SDK redraw, group alert, R-20 restated, ST-MFA-11) | Stage 2 contract for the `match_code` rule; ST-MFA-11 passing before the pilot |
| C-15 | R-23 in staging. Required: (i) S3-A2-3 items 1-4; (ii) KEY-ROTATION.md "seal key exposed" procedure, drilled once in staging; (iii) authority container with core dumps disabled, no debug or diagnostics endpoints, no shell in the runtime image, `ptrace` denied; (iv) seal keys are per environment, and pilot keys are never pinned in a production build; (v) unwrap reconciliation alerting drilled together with C-11 | before `RECOVERY_REFRESH_PROMPT_ENABLED` or any authority flag in the pilot |
| C-16 | R-23 gets a removal condition. Before any production authority environment, seal decryption stays inside an HSM boundary (§3 (a)), or an owner exception signed by A2 and A3 exists (§3 (b)). L-12 feeds this decision | production / standard profile |
| C-17 | S3-A2-4..-6 fixed or recorded | before Stage 7 |
| C-18 | OQ-8 (decision 16 wording) answered by the owner. Until then, ADR-0032 §1.5 governs and no api path creates a limited account (C-3) | pilot |

## Sign-off

A2 targeted check of Stage 1 revision 3 at `2eadc4e`. Verdict: **APPROVE WITH CONDITIONS**. S2-A2-1, S2-A2-2, S2-A2-4 to -10, S2-A2-11 and the S1-A2-2 and S1-A2-6 remainders are closed. S2-A2-3 is partially closed, pending new High finding S3-A2-1, which condition C-13 gates before the Stage 2 authority contract is frozen. New Mediums S3-A2-2 and -3 are due before the pilot (C-14, C-15). R-23 is accepted for the lean staging pilot only (C-15), and production requires C-16. Reviewer: A2 agent, 2026-11-02.

This is an agent review record produced for the Viadere multi-agent build process (spec §15, §27). It is **not a third-party certification**, penetration test or independent external security assessment, and it does not replace the external review that spec §13 requires before any production IdP.

## Revision 3.1 confirmation (A2, 2026-11-02)

| | |
|---|---|
| Baseline | `claude/inspiring-cannon-t5hxfw` at `3295db8`; deltas read with `git diff adee409..3295db8 -- docs/` |
| Read | `STAGE1_RESPONSE.md` "Revision 3.1"; ADR-0033 §4.1, §6; ADR-0023 §4 (`device_added` row, one account per key); TRUST_BOUNDARIES §4.2, DF-5; ADR-0022 §5.2 items 1, 4, 6, 7; ADR-0020 §2a; ADR-0034 §5, §8-§10; ADR-0028 `AUTH-ADMIN-NO-KV`, `AUTH-STANDBY-ROLE`; THREAT_MODEL T-REC-10, T-AUTH-6, T-AUTH-15, R-20, R-23, ST-REC-22, ST-REC-23, ST-MFA-11, ST-AUTH-25 |
| Method | Documents only; nothing built |

### Findings and gated conditions

| Item | Ruling | Basis / what remains |
|---|---|---|
| **S3-A2-1** (High) device-add grinding | **SATISFIED** | ADR-0033 §4.1 items 1-3, 7: separate earlier `keylog_pop` nonce; comparison nonce drawn at challenge creation after the entry and `kids` are stored, never a PoP nonce; one challenge per entry for life (failure ends the entry, new keys required); one pending entry per account; ≤ 5 entries per account per 24 h, `429 device_add_limit`, alerts from the fourth and on every refusal. The bound ≤ 5 × 10^-6 per account per day follows from these rules, and I agree with it. The rules are mirrored in ADR-0023 §4, DF-5, T-REC-10, and ST-REC-22 covers each rule |
| **C-13** (hard gate before the Stage 2 authority contract freezes) | **SATISFIED at document level** | The design gate is met, so Stage 2 may proceed. One part stays open until freeze: the Stage 2 authority OpenAPI must encode `409 challenge_exists`, `429 device_add_limit`, the `keylog_pop` purpose and the entry states `pending/abandoned/cancelled`. A2 checks that at freeze, with no further review round |
| **S3-A2-2** (Medium) collision lockout | **SATISFIED** | ADR-0022 §5.2 item 6 and ADR-0020 §2a (additive): business-keyed `match_tag`, so the api learns equality without learning codes; `409 match_code_in_use`; SDK redraw; group-pressure alert above 10; R-20 restated; ST-MFA-11. Two parts go further than I asked, and I accept both: prefix-freeness (it closes a real cross-length selection path), and 3 digits required from 30 open requests (more than about 600 open requests before exhaustion, critical alert). A business that sends inconsistent tags harms only its own customers, and S-MFA-15 stays as the defence |
| **Author deviation: no per-initiator caps at Viadere** | **ACCEPTED** | My S3-A2-2 change did not require per-initiator caps, so this is a design choice rather than a departure from the finding. The reasoning is correct. Viadere cannot see the initiator. A network identifier behind carrier-grade NAT would give a neighbour exactly the lockout lever that S2-A2-9 removed, and a cookie identifier costs the attacker nothing to rotate. Collision-freeness removes the lockout, and exhaustion is bounded and alerted, so a cap at Viadere would add risk without adding protection. Condition: the per-requester throttle guidance (≤ 3 open triggers per account and client network prefix) ships in the SDK helpers and the RP integration guide as a default, not only as prose (C-14) |
| **S3-A2-3** (Medium) seal-key custody | **SATISFIED** | (1) `id-viadere-authority-admin` keeps no Key Vault role (`AUTH-ADMIN-NO-KV`). The KEK public halves are attested inputs read once by the crypto-officer group, which keeps `AUTH-STANDBY-ROLE` consistent. A substituted KEK fails closed at the first unwrap. (2) Active and standby are created in separate executions, and a second create in one execution is refused. (3) Each set records `seal_kid`; the exposure procedure (ADR-0034 §8.2) invalidates exactly those sets, keeps grant capability, and is tested by ST-REC-23. (4) Reconciliation against a start or decrypt record, tested by ST-AUTH-25 |
| **C-15** (R-23, lean pilot) | **SATISFIED in design; delivery pending** | ADR-0034 §8, §10 specify items (i)-(v). Delivery remains: KEY-ROTATION.md written, the exposure procedure drilled once in staging, the container hygiene and route/image tests passing, reconciliation alerting drilled with C-11, all **before any authority flag in the pilot**. The 6-month seal-key lifetime cap is accepted |
| **C-16** (R-23, production) | **SATISFIED as a gate** | ADR-0034 §9: option (a), compact JWE `RSA-OAEP-256` + `A256GCM` to a non-exportable RSA-HSM 3072 key, `decrypt` only, the whole protected header used as AAD, strict pre-checks before Key Vault, at most one decrypt per challenge by CAS, generic error, reconciliation, MGF1-SHA-256 trap covered by a vector. Production stays **blocked** (ledger L-13) until §9 ships with its tests, or until an owner exception is countersigned by A2 and A3 with a lifetime of 90 days or less. I prefer that lean staging also move to §9 in Stage 6 (single code path) |
| S3-A2-4 (Low) `kid` in more than one account | **SATISFIED** | `409 key_in_use` on any non-revoked entry of any account; closure after 24 h with no enrollment confirmation; ST-AUTH-15 |
| S3-A2-5 (Low) failures moved into the silent class | **SATISFIED** | A lower `seq` is now `destination_mismatch`; skew is judged against an authority-signed `issued_at`; telemetry is kept |
| S3-A2-6 (Low) `session_handle` | **SATISFIED** | The HMAC derivation is a MUST, with vectors; a handle repeated on more than 3 requests in 10 minutes is ignored for supersession; alert above 20 per hour |

### New observation

- **S3.1-A2-1 (Low): duplicate test id.** THREAT_MODEL §6 now has two rows named `ST-MFA-11`: the new collision test and the existing push action-option test. T-MFA-10 cites the existing one. Rename the new test, for example to ST-MFA-16, in THREAT_MODEL, ADR-0022 §5.2 item 7 and the response/ledger references before the Stage 2 test catalog is frozen. This is editorial; nothing changes in the control.

### Final Stage 1 verdict: **APPROVE WITH CONDITIONS**

No Critical, High or Medium finding remains open at design level. C-13 is met, so this approval **does** extend to the Stage 2 authority contract. Conditions that remain for Stages 2-8:

| # | Condition | Gate |
|---|---|---|
| C-1 … C-12 | As in the previous re-review, unchanged. The C-1 test list includes ST-REC-22, ST-REC-23, ST-MFA-11 (renamed), ST-AUTH-25 and the extended ST-AUTH-15 and ST-ML-15 | as stated there |
| C-13 (remainder) | The Stage 2 authority OpenAPI encodes the device-add caps, states and error answers; A2 checks at freeze | Stage 2 contract freeze |
| C-14 | ADR-0020 §2a in the Stage 2 business contract; SDK redraw, plus the per-requester throttle shipped as the SDK default and stated in the RP guide; ST-MFA-11 (renamed) passing | contract in Stage 2; test before the pilot |
| C-15 | Delivery of ADR-0034 §8 and §10 with the drill | before any authority flag in the pilot |
| C-16 | §9 implemented and tested, or an owner exception countersigned by A2 and A3 | before any production authority environment |
| C-17 | S3-A2-4..-6 implemented with their tests | before Stage 7 |
| C-18 | OQ-8 answered by the owner (C-3 governs until then) | pilot |
| C-19 | S3.1-A2-1 test id renamed | before the Stage 2 test catalog is frozen |

Reviewer: A2 agent, 2026-11-02, at `3295db8`. This is an agent review record, not a third-party assessment (see the note above).
