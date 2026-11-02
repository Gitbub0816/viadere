# ADR-0032: Authority-minted account identity, account binding before `sub`, and authority-verified recovery

- **Status:** proposed (2026-11-02, Stage 1 revision 2)
- **Spec reference:** §4.3 invariants 1 and 5, §13 (formal metric), §23, §26 (gateway compromise, recovery), §27 stop-ship 1 and 6
- **Related:** ADR-0023 §3-§5 (factor JWS, key log, grant), ADR-0024 §6 (OIDC `sub`), ADR-0028 §1, §4 (keys, recovery verifiers), ADR-0033 (signed heads); SECURITY §2.26 (recovery), §2.30 (`subject_ref`); reviews S1-A2-1, S1-A2-2, S1-A3-02, S1-A3-03, S1-A3-04, S1-A2-13, S1-A3-13
- **Review:** A2 and A3 (both required), A1, A6 (app states), A9 (copy)

## Context

Revision 1 let the authority learn an account's identity from the api: `genesis` derived `account_ref` from an api-supplied consumer id and was "refused if the authority has ever seen the account", grants and OIDC `sub` were computed from an api-supplied `accountId`, and `recovery_started` was "the api's statement". Reviews A2 and A3 showed three takeovers by a compromised api alone:

1. a forged `genesis` for a victim id the authority had not yet seen (outage retry, post-snapshot accounts, keyless accounts) with the attacker's keys (S1-A2-1, S1-A3-03);
2. valid evidence from the attacker's own account paired with the victim's `accountId` (S1-A3-04);
3. a forged recovery start, notices suppressed, a 72 h wait, then attacker keys grant-capable (S1-A2-2, S1-A3-02).

## Decision

### 1. The authority allocates account identity

1. `POST keylog/entries {type: "genesis"}` takes **no caller-chosen account id**. The authority mints `account_id` (UUIDv4, lowercase, from its own CSPRNG), computes `account_ref = "acct_" ‖ hex32(HMAC-SHA256(ACCOUNT_REF_KEY, "account-ref\n" ‖ account_id))`, inserts `authority_accounts {account_ref, origin: "minted", grant_capable: false, created_at}`, appends the genesis entry, and returns `{account_id, account_ref, head}` where `head` is the signed key-log head (ADR-0033).
2. The api creates the consumer row **with the returned `account_id`** as its consumer id, in the same request as onboarding. From cutover, account creation calls genesis **synchronously**; there is no outbox deferral for genesis.
3. Genesis proof: proof-of-possession signature by each key over `VIADERE-KEYLOG-V1\n{env}\ngenesis\n{kid}\n{nonce}` (the nonce is a fresh authority challenge, so the proof cannot be replayed) plus the device's App Attest assertion over the same challenge wherever App Attest mode is not `off`.
4. **Enrollment completes only on the device.** The device is not grant-capable, and the app shows a blocking "Finishing security setup" state, until it has verified a head (ADR-0033 §2) whose genesis or `device_added` entry lists exactly its own key ids. Only then does the app call `POST keylog/entries {type: "enrollment_confirmed"}` with a factor JWS by the new key; the authority sets `grant_capable = true` for that key.
5. **Authority outage at account creation.** If genesis fails, the api may still create a consumer row (messaging and business-verified approvals do not depend on the authority, ADR-0019), but with an api-chosen id. The authority never minted or imported that id, so **every authority route refuses it permanently** (link service, OIDC, recovery, key log). No outbox retry turns it into an authority account. The app shows "Some sign-in features aren't available for this account" in Settings (UX_COPY S-SEC-03). An upgrade path for such accounts is not designed here; any future one must rest on authority-verified evidence (ledger item L-1, owner A2, Stage 6). Owner question OQ-4 records the product cost.
6. **One-time import (R-16)** covers **every** consumer id that exists at cutover:
   - accounts with keys: entries marked `imported`, `origin: "imported"`, grant-capable only after the app verifies a head listing its own keys and sends `enrollment_confirmed` (§1.4);
   - accounts without keys: `origin: "imported_keyless"`, **never grant-capable** (there is no logged key that could prove anything, and authority-verified recovery needs a registered code set, §3);
   - the import job refuses to run twice (a row in `authority_keylog_imports` with the snapshot SHA-256 digest; a second run with any digest is refused), records the digest in the authority audit log, and is followed immediately by the synchronous-genesis cutover.
7. Any authority request that names an account id the authority neither minted nor imported is refused (`404 account_unknown`, audited).

### 2. Binding `accountId` to the verified key before any `sub` is computed

1. Every derivation that takes an account id (`subject_ref` for grants, pairwise OIDC `sub`) takes it **only after** the authority has checked, in constant time, `HMAC-SHA256(ACCOUNT_REF_KEY, "account-ref\n" ‖ accountId) == account_ref` of the key-log entry whose key signed the evidence (or of the passkey that asserted). A mismatch is `evidence_invalid` plus an audit event `account_binding_mismatch` (alerted).
2. The business id used for `subject_ref` (SECURITY §2.30) and the grant `tid`/`aud` come from the authority's link-client or OIDC-client record, never from the request.
3. This is a new step 3a in the ADR-0023 §3 verification order.
4. Test ST-AUTH-05a: valid evidence from account A with `accountId = V` is refused.

### 3. Authority-verified recovery (before any authority-backed flag is enabled)

1. **Registration.** When a trusted device creates or regenerates a recovery-code set, it generates the codes locally and submits a `viadere-factor+jws` (new purpose `recovery_codes_set`) by a logged, grant-capable key. The authority-built display (ADR-0033 §1) shows the set id and the count. The request carries the codes; the authority stores only `HMAC-SHA256(RECOVERY_VERIFIER_KEY, "recovery-code\n" ‖ account_ref ‖ "\n" ‖ code)` per code and the set id, and appends `recovery_codes_set` to the key log. The api keeps its own hashes for the existing flow (SECURITY §2.26), which it continues to run.
2. **Start.** `recovery_started` is accepted only with a code the authority verifies itself: single use, at most 5 failed attempts per account per 24 h at the authority and 20 per recovery id, failures audited. A start without such a code (a legacy, api-verified code set) is recorded as `recovery_started_legacy`.
3. **Activation.** `recovery_activated` (≥ 72 h after start, no `recovery_cancel` by any logged key) adds the recovery passkey and revokes earlier keys as before. Keys added after a `recovery_started_legacy` are **never grant-capable**: link service and OIDC refuse the account. The account regains grant capability only by a later authority-verified path: a new recovery against an authority-registered code set, or an admin-job decision with a written reason recorded as a controlled downgrade (§4.3). The app says so (UX_COPY S-REC-04).
4. **Head visibility.** The app shows a persistent "We couldn't check your account's security" state (UX_COPY S-SEC-01) when it has been online for more than one hour without obtaining a valid head fresher than 15 minutes, and never treats an absent head as "no pending recovery". Deny and Report never wait for a head check.
5. **Rollout order.** §3.1-§3.3 ship before `AUTH_LINK_SERVICE_ENABLED` or `AUTHORITY_OIDC_ENABLED` is enabled for any account (Stage 6's recovery plan in ADR-0028 §4 moves before the pilot). After release the app asks each person to create a new code set ("Make new recovery codes"), which registers them with the authority.

This satisfies A2's required change and A3's option (b). A3's option (a) (importing the existing peppered verifiers and a copy of `SERVER_PEPPER`) is **not** adopted: it would import, on trust, code sets an api could already have rewritten, and put the general server pepper into the authority vault.

### 4. Separate HMAC keys

`ACCOUNT_REF_KEY` (32 bytes, `kv-vdr-auth` secret, authority only) derives `account_ref`; `OIDC_PAIRWISE_KEY` derives only the pairwise OIDC `sub`; `RECOVERY_VERIFIER_KEY` only recovery verifiers. Rotating one never re-keys the others.

### 5. Tests (all A unless noted)

- ST-AUTH-15: genesis naming any account id → refused (no such field); a request naming an imported id or an id the authority did not mint → refused; an account created during a simulated authority outage never yields a grant, even after retries; concurrent forged genesis versus real enrollment cannot attach keys to the real account.
- ST-AUTH-05a (above).
- ST-REC-07: simulated AS-1 starts a recovery with no authority-verified code; after 72 h with no cancel, the authority issues no grant and no id_token for the account.
- ST-REC-08: a legacy-code recovery yields keys the authority marks non-grant-capable.
- ST-REC-09 (K, D): the app shows S-SEC-01 when heads are withheld for over one hour while online.
- ST-REC-11: authority recovery-code attempt limits; a code used once is refused.

## Consequences

- Account creation depends on the authority being reachable for full capability; outages create permanently limited accounts (OQ-4).
- People with legacy recovery codes keep a working recovery, but it no longer restores grant capability until they register new codes.
- `account_ref` no longer depends on `OIDC_PAIRWISE_KEY`.

## Threat assumptions changed

- AS-1 can no longer choose which account a key belongs to, which account a `sub` names, or start a recovery that ends in grant-capable keys. AT-1 leaves 1.3.2 and 1.3.3 become [C] once this ADR ships, and stay [R] (open) until then.
- New residual: none beyond R-16 (one-time import on trust), which now excludes keyless accounts from grant capability.

## Reviewers required

A2 and A3 (both), A1 (grant capability semantics), A6 (app states), A9 (copy).
