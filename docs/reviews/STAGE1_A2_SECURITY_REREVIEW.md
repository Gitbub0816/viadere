# Stage 1 re-review by A2 (application security / threat model), 2026-11-02

| | |
|---|---|
| Reviewer role | A2. Independent of the Stage 1 author: did not write any reviewed artifact or the author response |
| Previous review | `docs/reviews/STAGE1_A2_SECURITY_REVIEW.md` (verdict BLOCK, baseline `0fab4ce`) |
| Baseline | `claude/inspiring-cannon-t5hxfw` at `bfa9ff6` |
| Read | `STAGE1_RESPONSE.md`; THREAT_MODEL §2-§8; TRUST_BOUNDARIES §4.1-§4.3a, §5, DF-1-DF-5, §7, §8; ADR-0019 §5, ADR-0020 §2, §3, §8, ADR-0021 §5, ADR-0022 §5, ADR-0023 (whole), ADR-0024 (whole), ADR-0025 §2.4, §3, ADR-0027 §1, ADR-0028 §2, §6, ADR-0031, ADR-0032, ADR-0033 (whole); `FLOW_MATRIX.md`; `AUTH-OWNER-DECISIONS.md` (1-16); `IMPLEMENTATION_LEDGER.md`; UX_COPY S-LINK-09, S-REC-04, S-SEC-01..03; SECURITY §2.26 (recovery-code format) and the vault "Adding a device" fingerprint comparison |
| Not re-read | Unchanged parts that the first review already accepted, per its scope note |

## Verdict: **BLOCK** (narrow)

The revision fixes what I asked for, and in most places it does so carefully. Five of the six blocking findings are **closed**: S1-A2-1, S1-A2-3 together with the R-07 ruling, S1-A2-4, S1-A2-5 and S1-A2-8. Every Medium and Low finding is closed or closed with a minor note. The new ADRs (0031, 0032, 0033) are the right shape. The authority now mints account identity, builds and signs what the person sees, checks account binding before any `sub` is computed, and anchors business-link integrity in a business key that the authority attests.

The revision still opens new paths in the same class as the original stop-ship. In each one, a compromised api (AS-1) gets **lasting, grant-capable** keys for a victim's account, and nothing stops it except the victim noticing:

- **S2-A2-1 (Critical).** Recovery codes travel through the api in plaintext when they are registered. That reopens S1-A2-2 for every code set registered while the api is compromised. The release plan makes this worse because it asks every person to register a new set. S1-A2-2 is therefore only **partially closed**.
- **S2-A2-2 (High).** A WebAuthn assertion made at an api-served origin is accepted as proof for `device_added` and `passkey_added`. Any passkey ceremony the victim performs can therefore be redirected to add the attacker's key.
- **S2-A2-3 (High).** `device_added` has no comparison code that binds the person's approval to the keys of the device they are actually holding.

All three fixes are local. They touch ADR-0032 §3, ADR-0023 §4, ADR-0033 §1 and §4, TRUST_BOUNDARIES §4.3a and the THREAT_MODEL rows named below. A re-review can be limited to those deltas plus S1-A2-6's remainder. When S2-A2-1 to -3 are fixed as specified, I expect to move to **APPROVE WITH CONDITIONS**, with the conditions in the last section.

## 1. Previous findings

| Finding | Sev. | Status | Evidence (where the fix is) | What remains |
|---|---|---|---|---|
| R-07 ruling (items 1-8) | — | **CLOSED** | ADR-0031 §1-§8 adopts the design word for word: admin-job-only `authority_tenant_keys` (§1.2, TRUST_BOUNDARIES §4.2 `id-viadere-authority-admin`); `viadere-tenant-keys+jws` with 15-min freshness (§2); `viadere-destination+jws` payload (§3); device checks in order, name and host taken from authority data (§4); fail closed with the pilot release check refusing `false` (§5); SDK `signAuthDestination` and vectors (§6); R-07' (§7, THREAT_MODEL §8); ST-ML-10..13, ST-AUTH-16 (§8, THREAT_MODEL §6). §7 row 3 cites them and drops the interpretation | Key choice `device-statement-signing` separated by `typ` is accepted from the A2 side, subject to S2-A2-5. Hardening notes in S2-A2-10 |
| S1-A2-1 | Critical | **CLOSED** | ADR-0032 §1.1 (no caller-chosen id, authority CSPRNG), §1.2 (synchronous, no outbox), §1.5 (outage ids refused permanently), §1.6 (import of every id, `imported_keyless` never grant-capable, single run with digest), §1.7 (`404 account_unknown`); ADR-0023 §4 genesis row; TRUST_BOUNDARIES §4.3a `keylog/entries` account id "not accepted"; ST-AUTH-15 with all four cases | S2-A2-4 (genesis confirmation should commit to the head) and S2-A2-8 (outage semantics) are hardening on top of a closed finding, not a reopening |
| S1-A2-2 | Critical | **PARTIALLY CLOSED** | ADR-0032 §3.1-§3.5: authority verifiers, `recovery_started_legacy` never grant-capable, S-SEC-01, rollout before any authority flag; ADR-0023 §4 rows; T-REC-2, T-GW-14; ST-REC-07..09, -11; AT-1 1.3.3 marked [R → C] | **S2-A2-1**: codes reach the authority through the api in plaintext ("The request carries the codes", ADR-0032 §3.1; TRUST_BOUNDARIES §4.3a "recovery code — person via api"). The recovery passkey at start can be swapped as well. Also S2-A2-7 (copy S-REC-04 contradicts §3.3) |
| S1-A2-3 | High | **CLOSED** | as the R-07 ruling row | — |
| S1-A2-4 | High | **CLOSED** | ADR-0033 §1 (authority builds displays; `POST challenges` takes references only), §2 (`viadere-challenge+jws` verified before the person acts), §4 (`return_url` in the factor JWS; opened only after acceptance, as a fragment); ADR-0023 §3 step 5; ADR-0021 §5.2-§5.3; TRUST_BOUNDARIES §4.3a display row; ST-LS-07, -08, ST-REC-10; ST-GW-07 rewritten (THREAT_MODEL line 400) | The `keylog_device_added` display I specified (thumbprints) is necessary but not sufficient. S2-A2-3 is my own omission in the first review, not an author defect |
| S1-A2-5 | High | **CLOSED** | ADR-0024 §2 (`private_key_jwt` only; RFC 9207 `iss`), §6 (assertion `aud` = issuer string only), §4 (R-17 text, `login_hint` fatigue-counted); THREAT_MODEL T-OIDC-11..13, AT-1 1.7, R-17; ST-OIDC-11..14, -16 | R-17 understates what an api-served WebAuthn origin allows: S2-A2-2 |
| S1-A2-6 | High | **PARTIALLY CLOSED** | ADR-0020 §8 (only `authdl-tenant` refuses with `429`; subject budgets limit alerting); ADR-0022 §5.1-§5.2 (silent inbox delivery); T-DO-8, T-MFA-6, AT-6, RT-9; ST-MFA-05 rewritten, ST-MFA-10, ST-DLV-09; R-20 | **Collapse remains an attacker lever.** A new request for the same (tenant, subject) supersedes the open one (ADR-0022 §5.2). An attacker who triggers sign-ins at the business's throttle rate keeps cancelling the victim's genuine prompt, and the victim's number then matches nothing. R-20 assigns the bound to the business alone. Required: S2-A2-9 |
| S1-A2-7 | Medium | **CLOSED** | ADR-0027 §1.3 "No immediate displacement" (`pending_transfer`, cool-down **and** in-app pull notice with "Keep my number"), §1.5 (UNLINK notified in app, 2 per 7 days / 1 per day caps, alerts), spoof indicator a hard fail; ST-PH-08..11 | Note: state that a transfer waits indefinitely when the existing account never fetches the notice (dormant owner), or name the bound. Either choice is acceptable once it is written down |
| S1-A2-8 | Medium | **CLOSED** | TRUST_BOUNDARIES §4.3a (per-field table and its rule); ADR-0020 §2 (`audience` and `tenant_id` refused; `aud`/`tid` from the client record); `Authority.Revocations` for the worker (§4.2, T-AUTH-14); ST-AUTH-17, -18 | The table has no rows yet for: new-device name, recovery passkey public key at `recovery_started`, `tenant-keys/{tenant_id}` path parameter, delivery id. Add them with S2-A2-1 and -3 |
| S1-A2-9 | Medium | **CLOSED** (honest residual) | ADR-0028 §6.4-§6.6 (SLSA provenance tied to protected `main`, named reviewers file, distinct agent identity + Prevent self-review, CODEOWNERS incl. `.github/CODEOWNERS`, single-owner R-21 with removal condition); ADR-0019 §5; ST-CI-08; decision 16 / OQ-3 (agents never push tags or deploy until the separate identity exists) | Inconsistent leftovers: T-GW-5 and T-AUTH-7 still say "two (GitHub) reviewers" (S2-A2-11). Condition C-5 |
| S1-A2-10 | Medium | **CLOSED** | Every named test exists in THREAT_MODEL §6 (checked by id: ST-AUTH-05a, -15..19, ST-REC-07..13, ST-LS-07/-08, ST-ML-10..14, ST-MFA-05/-10, ST-DLV-09, ST-OIDC-11..16, ST-WH-06, ST-PH-08/-09, ST-CI-08, ST-GW-07). §5 and §7 follow my mapping; ST-MFA-06 and ST-OIDC-16 count toward no row | New tests are required by S2-A2-1..-9 |
| S1-A2-11 | Medium | **CLOSED** | ADR-0025 §2.4 item 4 (retry horizon + 300 s from first receipt, ≥ 72 h, Core constant tied to the backoff table with a test); §3 M0 (`auth.*` and new `approve.*` v2-only, no `v1=`); ST-WH-06 | — |
| S1-A2-12 | Low | **CLOSED** | THREAT_MODEL §8: R-03 restated, R-07' replaces R-07, R-17..R-22 added; AT-1 1.3.2 and 1.3.3 marked open until ADR-0032 ships | R-17 must be widened or narrowed with S2-A2-2. AT-1 1.3.3 must stay [R] until S2-A2-1 ships |
| S1-A2-13 | Low | **CLOSED** | ADR-0032 §4 (`ACCOUNT_REF_KEY`, `RECOVERY_VERIFIER_KEY` separate); TRUST_BOUNDARIES §4.1; ADR-0020 §3 (request-signing key registration: passkey step-up + Owner notice) | — |

Decision list from the first review: rulings 2-10 stand. Ruling 7 ("authority key log … only with S1-A2-1 and S1-A2-2") is now conditional on S2-A2-1.

## 2. New findings

Severity scale as in the first review: **Critical** = a §27 stop-ship path open in the design; **High** = a §26 or §4.3 requirement not met; **Medium** = fix before the pilot gate; **Low** = fix or record before Stage 7.

### S2-A2-1 — Critical — recovery codes, and the recovery key binding, pass through the api in clear

- **Location:** ADR-0032 §3.1 ("The request carries the codes"), §3.2, §3.5 (the app asks every person to make new codes); ADR-0023 §4 `recovery_codes_set` / `recovery_started` rows; TRUST_BOUNDARIES §4.3a ("recovery code — person via api"); DF-5; decision 16 OQ-2 (code refresh offered before the pilot). Code format: SECURITY §2.26, 10 codes of 50 random bits each.
- **Issue:** Every device→authority request is relayed by the api (B4 → B5). There are two consequences.
  1. **Harvest at registration.** AS-1 records the plaintext codes of every set registered while it is present. Later it calls `recovery_started` with a genuine code, which the authority now verifies correctly, so the recovery is not marked legacy. It then suppresses notices (R-02) and waits 72 h. After that, `recovery_activated` makes the attacker's recovery passkey grant-capable. This is the dormant-account takeover of S1-A2-2, now with an authority-verified code. The only defense left is a trusted device seeing the head (S-SEC-01), which is the detection-only control the first review rejected. The pilot rollout of "Make new recovery codes" turns this into a bulk harvest. Hashing on the device does not fix it: 50-bit codes can be brute-forced from an unkeyed hash for a targeted account, and a hash relayed at start can simply be replayed.
  2. **Swap at start.** When a genuine victim recovers, the new device sends the code and the new passkey through the api. AS-1 can take the code (it is single use, but AS-1 uses it first) and pair it with its own passkey. The victim has by definition lost their devices, so nobody cancels.
- **Required change:**
  1. Add an authority **sealing key** `recovery-seal` (P-256 or X25519 for HPKE, RFC 9180 base mode, decrypt-only role for `id-viadere-authority`, in `kv-vdr-auth`). Its public key is pinned in the app next to `VIADERE_AUTHORITY_DEVICE_KEYS`, with active and standby keys and the same rollover rules (S2-A2-5).
  2. **Registration:** the device HPKE-seals `{v, account_ref, set_id, codes[]}` to `recovery-seal`, with `info = "VIADERE-RECOVERY-SET-V1\n{env}"` and AAD = the factor JWS `ach`. The factor JWS commits to `SHA-256(enc ‖ ciphertext)`. The api never sees a code. Require an `approvalBiometric` key of a D1-equivalent device, the same level as `device_added` (today it is any grant-capable key). A new set invalidates the account's previous authority set.
  3. **Start:** the recovering device HPKE-seals `{v, recovery_id, code, new_credential_public_key, nonce}` (authority nonce) to `recovery-seal`. The authority adds exactly that public key at activation and refuses any other. The new device verifies that the head lists exactly its key as the pending recovery key (`pending_recoveries[]` gains the `kid`).
  4. Until 1-3 ship, AT-1 1.3.3 stays **[R]** and the app must **not** prompt for the code refresh (OQ-2). Otherwise the refresh is the harvest.
  5. Tests:
     - ST-REC-14 (A): AS-1 records every byte the api relays during registration, then cannot start a non-legacy recovery;
     - ST-REC-15 (A): a start whose sealed key differs from the activated key is refused, and an api-substituted key never becomes active;
     - ST-REC-16 (A): a set registered with an `approvalUserPresence` key is refused.

### S2-A2-2 — High — passkey assertions at an api-served origin can add keys to the key log

- **Location:** ADR-0023 §4 `device_added` / `passkey_added` ("**or** a WebAuthn assertion by a logged passkey with UV"); ADR-0024 §4 item 1 (`rpId = RP_ID`, the existing RP id; origin `https://id.<domain>` served by the api); TRUST_BOUNDARIES DF-5; THREAT_MODEL T-REC-4, R-17.
- **Issue:** The authenticator signs `clientDataJSON` over an opaque challenge. It shows no purpose and no display, so the person sees only what the api-served page shows. AS-1 can take the authority nonce of a `keylog_device_added` or `keylog_passkey_added` challenge for the attacker's key and present it as the WebAuthn challenge of **any** passkey ceremony the victim performs for that RP id: an OIDC sign-in, a recovery-code regeneration step-up, or a dashboard step-up. The authority verifies a valid UV assertion and appends the attacker's key. After the 24/72 h cool-down that key is grant-capable for good. R-17 covers binding one genuine login to the attacker's session; it does not cover a lasting key addition. Detection depends on a trusted device viewing the head.
- **Required change:**
  1. Until the passkey origin leaves the ordinary tier (the R-17 removal condition), a WebAuthn assertion is accepted **only** for `oidc_login` and for the reduce-only `recovery_cancel`. It is never accepted for `device_added`, `passkey_added`, `recovery_codes_set` or `enrollment_confirmed`. Those take a factor JWS by a logged, grant-capable device key over an authority-signed display.
  2. A passkey-only person adds a device through recovery (S2-A2-1) or through an existing device. Say so in FLOW_MATRIX F10.
  3. The authority checks the assertion's `clientDataJSON.origin` against a per-purpose allow-list. Today that list is `https://id.<domain>` for `oidc_login` only.
  4. Restate R-17 so it is explicitly limited to single-session binding, and record that a lasting key addition is excluded by this rule.
  5. Test ST-REC-17 (A): a UV passkey assertion over a `keylog_device_added` or `keylog_passkey_added` nonce is refused, whatever its origin.

### S2-A2-3 — High — `device_added` approval is not bound to the device the person is holding

- **Location:** ADR-0033 §1 (`keylog_device_added` display: device name + thumbprints), §4 (PoP by the new key); ADR-0023 §4; DF-5 ("New device: enrolls at api …"); FLOW_MATRIX F10; T-REC-4, ST-REC-04, ST-REC-10.
- **Issue:** A person adds a real new device B. AS-1 submits the `device_added` entry with **its own** keys (its own PoP is valid) and copies B's name, "iPhone", into the request. The authority builds a correct display of the attacker's thumbprints, which nobody can check by eye, and old device A approves. The authority appends the attacker's key, and that key then sends its own `enrollment_confirmed`. B fails its head check and shows an error, but the attacker's key is already in the log. ST-REC-10 passes because the display is internally consistent. The signed display also lends the authority's signature to a name the attacker chose. The vault design in SECURITY already solves the same problem: B shows a fingerprint of its own keys and the person compares two screens.
- **Required change:**
  1. B fetches the signed `keylog_device_added` challenge, which carries its entry's key thumbprints. B refuses it unless those thumbprints are exactly its own keys. B then shows a **comparison code**: 6 decimal digits from `SHA-256("VIADERE-DEVICE-ADD-V1\n" ‖ nonce ‖ sorted kids)`.
  2. A's authority-built display shows the same code, computed by the authority from the entry. The person must type B's code on A; showing it is not enough, consistent with number matching. The typed code goes into the factor JWS `match` field and the authority checks it.
  3. Label the device name in the display "Name chosen on the new device" (A9).
  4. Test ST-REC-18 (A, K): AS-1 substitutes keys in a genuine add, and the code on B does not match the authority's code, so the evidence is refused and no key is appended.

### S2-A2-4 — Medium — enrollment confirmation does not commit to what the device verified

- **Location:** ADR-0032 §1.4; ADR-0023 §4 `enrollment_confirmed` row ("factor JWS by the new key after the app verified a head listing exactly its own keys").
- **Issue:** The authority cannot see what the device verified. At genesis, AS-1 can submit the victim device's keys, using a relayed PoP over the authority nonce, together with an attacker key. The attacker key then confirms itself. Today the victim device refuses the head, so the result is a stuck "Finishing security setup" (a DoS). That safety rests only on app behavior. For imported multi-device accounts, "exactly its own key ids" (§1.4) contradicts "contains" (ADR-0033 §2).
- **Required change:** the `enrollment_confirmed` factor JWS carries `head_hash` and `seq`. The authority refuses it unless they match the current head. For genesis, keys become grant-capable only when **every** genesis key has confirmed the same `head_hash`. For imported accounts, each key confirms itself, the app lists the other imported devices for the person, and an unconfirmed imported key stays non-grant-capable. Test ST-AUTH-23 (A).

### S2-A2-5 — Medium — the pinned-key revocation list can be turned against the standby key

- **Location:** ADR-0033 §3.2; R-22; ledger L-2.
- **Issue:** Nothing stops the **active** key from signing `viadere-device-keys-revocation+jws`. If the active key is compromised, which is the very case §3.2 handles, the holder can revoke the standby on every app it reaches first. A later genuine list signed by the now-revoked standby is then ignored, and the app is left trusting only the compromised key. The design also leaves undefined what happens when the two keys revoke each other, and how routine rotation works for apps that have not updated.
- **Required change:** revocation lists are signed **only** by a key other than the one they revoke, and only the standby may sign one. A list may name only the active `kid`. An app never revokes the last pinned key it has not seen revoked by the other key, and refuses any list naming the standby. Routine rotation (no compromise) goes through an app update that pins the new pair, plus a minimum-app-version gate for authority flows. KEY-ROTATION.md (L-2) states this before Stage 4 pins the keys. The same rules apply to `recovery-seal` (S2-A2-1). Test ST-REC-19 (K): a list signed by the active key, or one naming the standby, is ignored.

### S2-A2-6 — Medium — unauthenticated `/oidc/authorize` drives authority challenges, signatures and per-tenant budgets

- **Location:** ADR-0024 §4 (the api creates the authority challenge when the page renders); ADR-0033 §2 and Consequences (one Key Vault `sign` per challenge); ADR-0020 §8 (`authority-challenge` per tenant and per account).
- **Issue:** Anyone can load `/oidc/authorize?client_id=ocl_…` with a valid redirect URI. Each load creates and signs an authority challenge. This lets an external attacker exhaust a tenant's `authority-challenge` budget, so the relying party's real users cannot sign in. That is attacker-controlled lockout, the same class as S1-A2-6. It also loads `kv-vdr-auth` sign throughput, which heads, tenant records and grants share. Combined with S2-A2-8, an induced authority outage at sign-up permanently limits new accounts.
- **Required change:** create the authority challenge only after a user action on the page (method chosen), behind per-IP and per-client limits at the api edge. Bound authority challenge signing per tenant **separately** from heads, tenant records and grants, so a flood degrades only that tenant's OIDC. Over budget, the response is an error page, never a lockout of other flows. Tests ST-OIDC-17 (unauthenticated authorize loads create no authority challenge) and ST-AUTH-24 (a challenge flood for one tenant leaves heads and tenant records for others unaffected).

### S2-A2-7 — Medium — S-REC-04 promises a self-service path the ADR forbids

- **Location:** UX_COPY S-REC-04 ("stays off until you make new recovery codes on this device"); ADR-0032 §3.3 (grant capability returns only by a new authority-verified recovery or an admin-job decision); ADR-0023 §4 (`recovery_codes_set` needs a grant-capable key).
- **Issue:** After a legacy recovery, no key is grant-capable, so `recovery_codes_set` is impossible. If Stage 4 or 5 implements the copy, letting a legacy-recovered key register codes and become grant-capable, S1-A2-2 is fully reopened, because AS-1's legacy recovery could then upgrade itself.
- **Required change:** rewrite S-REC-04 to match §3.3 (A9 wording). Spell out in ADR-0032 §3.3 that a legacy-recovered account can only regain grant capability through the admin path, or through a fresh authority-verified recovery against a set registered **before** the legacy recovery. Test ST-REC-20 (A): a key added by a legacy recovery cannot register a code set.

### S2-A2-8 — Medium — "permanently limited" accounts: inconsistent with decision 16 and inducible by an attacker

- **Location:** ADR-0032 §1.5 ("every authority route refuses it permanently"; L-1 deferred to Stage 6); decision 16 OQ-4 ("stay limited **until re-bound**"); ADR-0023 Consequences.
- **Issue:** The owner record expects a re-binding path, and the ADR says none exists. Anyone who can make the authority unavailable (see S2-A2-6) when a person signs up permanently removes that person's sign-in features. That is attacker-controlled permanent limitation, which §23 asks the design to avoid. A hastily designed L-1 is also the most likely place for a re-binding that trusts the api.
- **Required change, one of:**
  - (a) In the pilot, onboarding does **not** create a consumer when genesis fails. The app retries with backoff and shows an outage message. Accounts never become permanently limited, and §1.5 then covers only a defensive refusal.
  - (b) L-1 is designed and reviewed by A2 and A3 before the pilot. A re-bind mints a **new** authority account id. It never attaches the old api id, and it rests only on fresh device evidence plus App Attest.

  (a) is my recommendation. Either way, align decision 16's wording through the owner.

### S2-A2-9 — Medium — collapse lets an attacker supersede the victim's genuine prompt (S1-A2-6 remainder)

- **Location:** ADR-0022 §5.1-§5.2; ADR-0020 §8; R-20.
- **Required change:** above the alert budget, a new request no longer supersedes the open one. Keep up to 3 pending per (tenant, subject), let the **number the person types select** the matching pending request, and drop the others only when one is approved or denied. Alternatively, supersede only when the business marks the new request with the same initiating-session handle (a business-side opaque value) as the open one. ST-MFA-10 is extended: with an attacker creating a request every N seconds at the business's throttle rate, the victim's own sign-in is still completable.

### S2-A2-10 — Medium — device-side destination verification failures are reported as user denials

- **Location:** ADR-0031 §4 (any failure → `POST …/deny {reason: destination_unverified}`, alerted); ADR-0022 §5.4 (pause after 3 denials); ADR-0031 Consequences (stale record when the authority is out for more than 15 min); T-AUTH-8 ("delivery-only … do not depend on the authority", no longer true for F1/F2).
- **Issue:** Some verification failures are integrity failures: a bad signature, a URL digest mismatch, a host outside `allowed_hosts`. Others are availability failures: the tenant record is stale because the authority is down, or the device clock is wrong. The design merges both into a deny. That can (a) count toward the per-business pause, (b) reach the business as `auth.delivery.denied`, which businesses may treat as a fraud signal, and (c) flood the operator alert during an outage and hide a real tampering event.
- **Required change:**
  - two reasons: `destination_mismatch` (integrity: alert at high priority) and `destination_unverifiable` (stale or absent record, clock: the delivery stays open and the person can retry, with no business event and no pause count);
  - neither counts toward the fatigue pause;
  - a clock-skew failure shows "Check your phone's date and time" (A9);
  - fix T-AUTH-8 and FLOW_MATRIX F1/F2 to state the dependency on the tenant record;
  - tenant-key hardening: a maximum `not_after` of 13 months; an admin-job revocation path that works without the api; when the weekly domain re-check (ADR-0021) fails, the host is removed from `allowed_hosts` automatically through `revocations`;
  - test ST-ML-15.

### S2-A2-11 — Low — consistency and small gaps

1. T-GW-5 and T-AUTH-7 still say "two (GitHub) reviewers". Align them with R-21.
2. ADR-0033 §2 says "refreshed **at most** every 5 minutes". It must say **at least**: a cached head older than 15 minutes is refused by the device.
3. `amr` for the app path when the key is **not** attested as hardware-bound is not defined. Use `["swk","mfa"]` or `["mfa"]`, and say which (ADR-0023 §5, ADR-0024 §5).
4. ADR-0033 §1 `keylog_device_added`: the approving device must check that the challenge's `account_ref` equals its own, and the authority must check that the proving key belongs to the entry's account. Add both to ST-REC-10.
5. R-07' can be removed rather than accepted. The authority already computes `subject_ref`, so it can sign the account's `subject_ref` for the delivery's tenant into a device statement bound to the head's `account_ref`. The device then checks `sub`. This is optional, owner A2, Stage 5.

## 3. §26 red-team scenarios against the revised design

| RT | Holds? | Basis / blocker |
|---|---|---|
| RT-1 gateway compromise | **No**, until S2-A2-1..-3 | Grant/token keys, raw sign, account identity, `sub` binding, display and `return_url` all hold (ST-GW-01, ST-AUTH-02, -05a, -15, -19, ST-LS-07). Lasting attacker keys via code harvest, passkey-assertion reuse or `device_added` substitution do not |
| RT-2 stolen webhook secret | Yes | ids-only v2 envelopes, fetch and verify (ST-WH-04, -06) |
| RT-3 replay | Yes | `ach` consumed after all checks, business replay guard, statement `jti` on the device (ST-AUTH-09, ST-MFA-03, ST-ML-11) |
| RT-4 destination swap / open redirect | Yes | ADR-0031 device verification; residual R-07' (login CSRF) and R-06. S2-A2-10 is hardening |
| RT-5 push interception | Yes | ids only (ST-PRIV-02) |
| RT-6 one tenant compromised | Yes | tenant from credential; `aud`/`tid`/business id from authority records (ST-TEN-*, ST-AUTH-17) |
| RT-7 ordinary admin | Yes, with R-21 | no console path; admin job; CODEOWNERS, provenance, Prevent self-review once OQ-3 is done (C-5) |
| RT-8 email/SMS recovery | **No**, until S2-A2-1 | no email/SMS route (ST-REC-01). Code recovery is authority-verified, but codes are harvestable at registration and the recovery key is swappable at start |
| RT-9 MFA flood | Partly | availability no longer refused (ST-MFA-10, ST-DLV-09); collapse remainder S2-A2-9; OIDC challenge flood S2-A2-6 |
| RT-10 crash | Yes | outbox, CAS, dedup ≥ 72 h (ST-DLV-01/02, ST-WH-05/06) |

## 4. §27 stop-ship rules against the revised design

| Rule | Cleared by the design? |
|---|---|
| Single ordinary service issues a grant | **Not yet**: S2-A2-1 (Critical), with S2-A2-2/-3 as the High paths that need one victim action. R-17 is a named staging exception for single-session OIDC binding only |
| Link token in push or logs | Yes (ids-only push, P-class ciphertext, log allow-list, Logpush without query strings) |
| Verified business domain bypassed | Yes (ADR-0031; R-07' only) |
| Cross-tenant access | Yes (ST-TEN-*, ST-AUTH-17, -19) |
| Critical keys exportable | Yes (custom sign-only role, `AUTH-KEY-BACKUP`, pinned versions). `recovery-seal` must get the same treatment |
| Recovery bypasses assurance | **Not yet**: S2-A2-1, S2-A2-7 |

## 5. Rulings on the three stricter choices flagged for confirmation

1. **Interruption level `active` only (A6/A7 finding 9 vs S1-A9-8): confirmed** for every auth and payment prompt. `timeSensitive` breaks through Focus and raises pressure to act at the Lock Screen, which helps fatigue attacks and bystanders more than it helps the person who started a sign-in and is already looking at their phone. One option, not a requirement: A6/A9 may use `timeSensitive` for **security-change notices** (recovery started, device added, number linked). Those carry no secret and no Approve, and seeing them promptly is part of the R-02 control. If adopted, it needs its own ST-PRIV-05 case.
2. **Token-endpoint URL never accepted as `private_key_jwt` `aud`, even in staging: confirmed.** Staging is where relying-party libraries get configured, so a lenient staging teaches the wrong value. The interoperability cost (libraries that default to the token endpoint) goes into the RP integration guide, and ST-OIDC-12 stays as written.
3. **No `pin` in `amr`: confirmed.** With an `approvalUserPresence` key the server cannot know whether a passcode or a biometric was used, and RFC 8176 `pin` asserts a knowledge factor that was not observed. `["hwk","mfa"]` claims what is known: a device-bound key plus device user verification. Close S2-A2-11 item 3 so the unattested case is defined too.

## 6. Conditions for Stages 2-6 (hold after the block is lifted)

| # | Condition | Gate |
|---|---|---|
| C-1 | `AUTH_LINK_SERVICE_ENABLED` and `AUTHORITY_OIDC_ENABLED` stay off for every account until ST-AUTH-05a, -15..-19, -23, ST-REC-07..-20, ST-LS-07/-08, ST-GW-07 pass **and** a mutation run shows that each one fails with its control removed (recorded in the Stage 7 report) | flag enable |
| C-2 | No `link_mode: "business"` delivery in the pilot until ST-ML-10..-15 pass on real iOS and Android devices, and the pilot release check refuses `AUTH_DESTINATION_SIGNATURE_REQUIRED=false` | pilot |
| C-3 | The R-16 import runs once, after ADR-0032 code is deployed, in the same window as the synchronous-genesis cutover. The snapshot digest is in the authority audit log. No api account creation path exists that skips genesis (or S2-A2-8 option (a) is in force) | Stage 6 |
| C-4 | The app does not prompt for a recovery-code refresh (OQ-2) before S2-A2-1 ships | Stage 4/5 |
| C-5 | Authority environments are not created until OQ-3 is done: distinct agent GitHub identity, Prevent self-review, branch protection, CODEOWNERS. ST-CI-08 passes | Stage 6 |
| C-6 | KEY-ROTATION.md (L-2) with the S2-A2-5 rules exists before Stage 4 pins `VIADERE_AUTHORITY_DEVICE_KEYS` and the `recovery-seal` keys. The first app release pins both active and standby | Stage 4 |
| C-7 | ST-GW-08 (zero active legacy-unsigned entitlements) is a pilot release gate | pilot |
| C-8 | ST-WH-06 and the Core retry-horizon constant test pass before any `auth.*` event is emitted | Stage 2/3 |
| C-9 | Stage 2 contracts: the internal authority OpenAPI has no `audience`, `tenant_id`, display text, account id at genesis, or plaintext recovery code member. Contract tests assert the absence | Stage 2 |
| C-10 | `OIDC_PROVIDER_ENABLED` stays staging-only, and R-17 (as narrowed by S2-A2-2) is re-reviewed before any production IdP, together with the §13 external review | Stage 9 |
| C-11 | The Key Vault `AuditEvent` reconciliation job and the independent JWKS monitor run, and have alerted at least once in a drill, before any authority flag is enabled | Stage 6 |
| C-12 | A9 reviews S-LINK-09, the new verification-failure strings (S2-A2-10), S-REC-04 (S2-A2-7) and the comparison-code screens (S2-A2-3) before the Stage 4 merge | Stage 4 |

## Sign-off

A2 security re-review of Stage 1 revision 2. Verdict: **BLOCK**, limited to S2-A2-1 (Critical), S2-A2-2 and S2-A2-3 (High), and the S1-A2-2 and S1-A2-6 remainders. A delta re-review of ADR-0032 §3, ADR-0023 §4, ADR-0033 §1, §3 and §4, ADR-0022 §5, TRUST_BOUNDARIES §4.3a and DF-5, and the matching THREAT_MODEL rows is sufficient. Medium findings S2-A2-4..-10 are due before the pilot gate, and S2-A2-11 before Stage 7. Reviewer: A2 agent, 2026-11-02.

This is an agent review record produced for the Viadere multi-agent build process (spec §15, §27). It is **not a third-party certification**, penetration test or independent external security assessment, and it does not replace the external review that spec §13 requires before any production IdP.
