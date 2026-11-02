# ADR-0032: Authority-minted account identity, account binding before `sub`, and authority-verified recovery

- **Status:** proposed (2026-11-02, Stage 1 revision 2); revision 3 (2026-11-02): sealed, key-bound recovery codes in a set the api cannot hash (S2-A2-1, S1-A3-R01; ADR-0034), enrollment confirmation commits to the head (S2-A2-4), no account without genesis (S2-A2-8 option (a)), legacy-recovered accounts (S2-A2-7), `account_ref` encoding (S1-A3-R06)
- **Spec reference:** §4.3 invariants 1 and 5, §13 (formal metric), §23, §26 (gateway compromise, recovery), §27 stop-ship 1 and 6
- **Related:** ADR-0023 §3-§5 (factor JWS, key log, grant), ADR-0024 §6 (OIDC `sub`), ADR-0028 §1, §4 (keys, recovery verifiers), ADR-0033 (signed heads), ADR-0034 (sealed recovery envelopes); SECURITY §2.26 (recovery), §2.30 (`subject_ref`); reviews S1-A2-1, S1-A2-2, S1-A3-02, S1-A3-03, S1-A3-04, S1-A2-13, S1-A3-13; re-reviews S2-A2-1, -4, -7, -8, S1-A3-R01, -R06
- **Review:** A2 and A3 (both required), A1, A6 (app states), A9 (copy)

## Context

Revision 1 let the authority learn an account's identity from the api: `genesis` derived `account_ref` from an api-supplied consumer id and was "refused if the authority has ever seen the account", grants and OIDC `sub` were computed from an api-supplied `accountId`, and `recovery_started` was "the api's statement". Reviews A2 and A3 showed three takeovers by a compromised api alone:

1. a forged `genesis` for a victim id the authority had not yet seen (outage retry, post-snapshot accounts, keyless accounts) with the attacker's keys (S1-A2-1, S1-A3-03);
2. valid evidence from the attacker's own account paired with the victim's `accountId` (S1-A3-04);
3. a forged recovery start, notices suppressed, a 72 h wait, then attacker keys grant-capable (S1-A2-2, S1-A3-02).

Revision 2 fixed (1) and (2) and moved code verification into the authority. The re-reviews showed that the codes still crossed the api in plaintext, were the same codes the api hashes, and were not bound to the recovery key (S2-A2-1, S1-A3-R01); revision 3 fixes that in §3 and ADR-0034.

## Decision

### 1. The authority allocates account identity

1. `POST keylog/entries {type: "genesis"}` takes **no caller-chosen account id**. The authority mints `account_id` (UUIDv4, lowercase, from its own CSPRNG), computes `account_ref = "acct_" ‖ lowercase_hex(first 16 bytes of HMAC-SHA256(ACCOUNT_REF_KEY, "account-ref\n" ‖ account_id))` (128 bits, 32 hex characters; every binding check recomputes the same truncation and compares all 32 characters in constant time, S1-A3-R06 item 1), inserts `authority_accounts {account_ref, origin: "minted", grant_capable: false, created_at}`, appends the genesis entry, and returns `{account_id, account_ref, head}` where `head` is the signed key-log head (ADR-0033).
2. The api creates the consumer row **with the returned `account_id`** as its consumer id, in the same request as onboarding. From cutover, account creation calls genesis **synchronously**; there is no outbox deferral for genesis.
3. Genesis proof: proof-of-possession signature by each key over `VIADERE-KEYLOG-V1\n{env}\ngenesis\n{kid}\n{nonce}` (the nonce is a fresh authority challenge, so the proof cannot be replayed) plus the device's App Attest assertion over the same challenge wherever App Attest mode is not `off`.
4. **Enrollment completes only on the device, and the confirmation commits to the head it verified (S2-A2-4).** The device is not grant-capable, and the app shows a blocking "Finishing security setup" state (S-SEC-02), until it has verified a head (ADR-0033 §2) whose `genesis` or `device_added` entry lists **exactly** its own key ids, no more and no fewer. Only then does the app call `POST keylog/entries {type: "enrollment_confirmed"}` with a factor JWS (`purpose: enrollment_confirmed`, members `head_hash` and `seq` of that head) by its `approvalBiometric` or `approvalUserPresence` key, plus a PoP by **each** of the entry's keys over `VIADERE-KEYLOG-V1\n{env}\nenrollment_confirmed\n{kid}\n{head_hash}`. The authority refuses the confirmation unless `head_hash` and `seq` equal the account's current head, and sets `grant_capable = true` only when **every** key of that entry has confirmed the same `head_hash`. An attacker key added beside the victim's keys at genesis therefore never becomes grant-capable: the victim's device refuses the head and never confirms, and the attacker key cannot confirm on behalf of the victim's keys.
   - **Imported accounts** (§1.6, possibly several devices per account): each device confirms its own keys (the head must *contain* them, ADR-0033 §2). The app lists the account's other imported devices by name and "added" date (UX_COPY S-SEC-05) so the person can remove one they do not recognize; an imported key that never confirms stays non-grant-capable.
5. **Authority outage at account creation (S2-A2-8, option (a)).** From the synchronous-genesis cutover, onboarding **does not create a consumer** when genesis fails. The app keeps the person on the onboarding screen with UX_COPY S-SEC-04 and retries with backoff (30 s, 2 min, 10 min, then on every app open). No api code path creates a consumer row without an authority-minted id (condition C-3; ST-AUTH-15). Permanently limited accounts therefore do not arise, and §1.7 is only a defensive refusal. Messaging and business-verified approvals for **existing** accounts keep working during an outage (ADR-0019); only sign-up waits. Revision 2's ledger item L-1 (re-binding outage accounts) is closed as not needed. Decision 16 OQ-4's wording ("stay limited until re-bound") no longer describes the design; owner question OQ-8 asks the owner to align it.
6. **One-time import (R-16)** covers **every** consumer id that exists at cutover:
   - accounts with keys: entries marked `imported`, `origin: "imported"`, grant-capable only after the app verifies a head containing its own keys and confirms them (§1.4);
   - accounts without keys: `origin: "imported_keyless"`, **never grant-capable** (there is no logged key that could prove anything, and authority-verified recovery needs a registered code set, §3);
   - the import job refuses to run twice (a row in `authority_keylog_imports` with the snapshot SHA-256 digest; a second run with any digest is refused), records the digest in the authority audit log, and is followed immediately by the synchronous-genesis cutover.
7. Any authority request that names an account id the authority neither minted nor imported is refused (`404 account_unknown`, audited).

### 2. Binding `accountId` to the verified key before any `sub` is computed

1. Every derivation that takes an account id (`subject_ref` for grants, pairwise OIDC `sub`) takes it **only after** the authority has checked, in constant time, that the `account_ref` recomputed from `accountId` (§1.1) equals the `account_ref` of the key-log entry whose key signed the evidence (or of the passkey that asserted). A mismatch is `evidence_invalid` plus an audit event `account_binding_mismatch` (alerted).
2. The business id used for `subject_ref` (SECURITY §2.30) and the grant `tid`/`aud` come from the authority's link-client or OIDC-client record, never from the request.
3. This is step 3a in the ADR-0023 §3 verification order.
4. Test ST-AUTH-05a: valid evidence from account A with `accountId = V` is refused.

### 3. Authority-verified recovery with sealed, key-bound codes (before any authority-backed flag)

1. **Registration.** The device generates a new set of 10 codes locally (ADR-0034 §2). It obtains an authority challenge (`purpose: recovery_codes_set`; the authority-built display shows the set id and the count, ADR-0033 §1), seals `{v, purpose, account_ref, set_id, nonce, codes}` to the active `recovery-seal` key (ADR-0034), and submits the envelope with a `viadere-factor+jws` (`purpose: recovery_codes_set`, member `envelope_digest`) by a logged, grant-capable **`approvalBiometric`** key whose `usable_from` has passed. This is the authority's "D1-equivalent" rule, the same as for `device_added` (ADR-0023 §4); an `approvalUserPresence` key is refused (ST-REC-16). The authority opens the envelope, stores only keyed verifiers (ADR-0034 §4), invalidates the account's previous authority set in the same transaction, and appends `recovery_codes_set {set_id, count}` to the key log. **The api never receives a code** and holds no hash of one. The app then asks the api to invalidate the api's own legacy set for the account (ADR-0034 §3), so the person holds one set.
2. **Start.** The recovering device calls the api's `POST /v1/recovery/begin {recoveryId}`; the api resolves the account and asks the authority for a challenge (`purpose: recovery_started`). The device creates every key the recovery will add (its new passkey and its new app keys `request`, `approvalUserPresence`, `approvalBiometric`), seals `{v, purpose, recovery_id, nonce, code, new_kids}` to the active `recovery-seal` key, and submits the envelope with a PoP by **each** new key over `VIADERE-KEYLOG-V1\n{env}\nrecovery_started\n{kid}\n{nonce}\n{envelope_digest}`. For the passkey, the PoP is a WebAuthn assertion made in the app right after registration whose challenge is the SHA-256 of that string: it proves possession of a key being added under a sealed code and authorizes nothing by itself, so it is not one of the assertions ADR-0023 §3a restricts. The authority opens the envelope, verifies the code (single use; at most 5 failed attempts per account per 24 h and 20 per recovery id; failures audited), and requires the set of PoP keys to equal `new_kids` exactly. It records `recovery_started {recovery_id, kids: new_kids}`; the head lists it under `pending_recoveries[]` with those `kids`. The recovering device continues only after verifying a head whose pending recovery lists **exactly** its own `new_kids` (ADR-0033 §2).
   - A start without a sealed, authority-verified code (an api-verified legacy set) is recorded as `recovery_started_legacy`. It is **refused** for an account that has an active authority set: such a person has no legacy codes left (§3.1), so only AS-1 could send one, and refusing it removes a revoke-every-key lever.
3. **Activation.** `recovery_activated` (≥ 72 h after start, no `recovery_cancel` by any logged key or logged passkey, ADR-0023 §3a) adds **exactly** the keys in the start's `kids` and no other key, and revokes all earlier keys. Keys added by an authority-verified start are grant-capable from activation (`usable_from` = activation time). Keys added after a `recovery_started_legacy` are **never grant-capable**; link service and OIDC refuse the account.
   - **Legacy-recovered accounts (S2-A2-7).** A key added by a legacy recovery cannot register a code set (`recovery_codes_set` requires a grant-capable key; ST-REC-20). The account regains grant capability **only** through (a) a fresh authority-verified recovery against an authority set registered **before** the legacy recovery (an authority set survives a legacy recovery), or (b) an admin-job decision with a written reason, recorded as a controlled downgrade (spec §4.3 invariant 5). There is no self-service path; UX_COPY S-REC-04 says so.
4. **Head visibility.** The app shows a persistent "We couldn't check your account's security" state (UX_COPY S-SEC-01) when it has been online for more than one hour without obtaining a valid head fresher than 15 minutes, and never treats an absent head as "no pending recovery". Deny and Report never wait for a head check.
5. **Rollout order and the code-refresh prompt (condition C-4).** §3.1-§3.3 and ADR-0034 ship before `AUTH_LINK_SERVICE_ENABLED`, `OIDC_PROVIDER_ENABLED` or `AUTHORITY_OIDC_ENABLED` is enabled for any account. The app **does not** prompt for a code refresh ("Make new recovery codes", S-REC-05; decision 16 OQ-2) in any build that lacks ADR-0034 sealing and the pinned seal keys, and the prompt flag `RECOVERY_REFRESH_PROMPT_ENABLED` stays off until ST-REC-14, -15, -16 and -21 pass. Until then AT-1 1.3.3 stays **[R]**.

This satisfies A2's and A3's required changes: sealing to a pinned authority key, a separate set the api cannot hash, binding of the code to the new keys at start, and a stronger key for registration. Revision 1's option (a) (importing api verifiers and a copy of `SERVER_PEPPER`) stays rejected: it would import, on trust, code sets an api could already have rewritten, and put the general server pepper into the authority vault.

### 4. Separate HMAC keys

`ACCOUNT_REF_KEY` (32 bytes, `kv-vdr-auth` secret, authority only) derives `account_ref`; `OIDC_PAIRWISE_KEY` derives only the pairwise OIDC `sub`; `RECOVERY_VERIFIER_KEY` only recovery verifiers. Rotating one never re-keys the others.

### 5. Tests (all A unless noted)

- ST-AUTH-15: genesis naming any account id → refused (no such field); a request naming an imported id or an id the authority did not mint → refused; during a simulated authority outage onboarding creates no consumer row (no api path creates one without a minted id); concurrent forged genesis versus real enrollment cannot attach keys to the real account.
- ST-AUTH-23: `enrollment_confirmed` with a `head_hash` or `seq` other than the current head is refused; a genesis entry with the victim's keys plus an attacker key makes no key grant-capable unless every key confirmed the same head; an unconfirmed imported key stays non-grant-capable.
- ST-AUTH-05a (above).
- ST-REC-07: simulated AS-1 starts a recovery with no authority-verified code; after 72 h with no cancel, the authority issues no grant and no id_token for the account.
- ST-REC-08: a legacy-code recovery yields keys the authority marks non-grant-capable.
- ST-REC-09 (K, D): the app shows S-SEC-01 when heads are withheld for over one hour while online.
- ST-REC-11: authority recovery-code attempt limits; a code used once is refused.
- ST-REC-14, ST-REC-15, ST-REC-21: ADR-0034 §7.
- ST-REC-16: a `recovery_codes_set` by an `approvalUserPresence` key, or by a key still in cool-down, is refused.
- ST-REC-20: a key added by a legacy recovery cannot register a code set; a legacy start for an account with an active authority set is refused.

## Consequences

- Sign-up depends on the authority being reachable; during an outage new people wait (S-SEC-04) instead of getting a limited account (OQ-8).
- People with legacy recovery codes keep a working recovery until they register an authority set, but it never restores grant capability. Registering an authority set retires the api's legacy set.
- The refresh prompt (OQ-2) waits for ADR-0034.
- `account_ref` no longer depends on `OIDC_PAIRWISE_KEY`.

## Threat assumptions changed

- AS-1 can no longer choose which account a key belongs to or which account a `sub` names, and it can no longer learn, search or swap authority recovery codes or the keys they authorize. AT-1 leaves 1.3.2 and 1.3.3 become [C] once this ADR and ADR-0034 ship with their tests passing, and stay [R] (open) until then.
- Residuals: R-16 (one-time import on trust; keyless and unconfirmed imported keys never grant-capable); R-23 (ADR-0034: an authority process compromise reads the in-memory seal key).

## Reviewers required

A2 and A3 (both), A1 (grant capability semantics), A6 (app states), A9 (copy).
