# ADR-0033: Authority-built displays, authority-signed device statements (challenges, key-log heads, tenant records) and pinned-key rollover

- **Status:** proposed (2026-11-02, Stage 1 revision 2); revision 3 (2026-11-02): device-add comparison code (S2-A2-3), defined and role-restricted revocation of pinned keys for both key families (S2-A2-5, S1-A3-R02), statement checks and cadence (S1-A3-R05, S2-A2-11 items 2 and 4), challenge-signing bulkhead (S2-A2-6)
- **Spec reference:** §4.3, §7 (no deceptive state), §9.3, §26 (gateway compromise)
- **Related:** ADR-0021 §5 (link service), ADR-0023 (factor JWS, key log), ADR-0024 §4, §8 (OIDC display, consent), ADR-0028 §2 (versions, roles), ADR-0031 (tenant records), ADR-0032 (account binding, recovery), ADR-0034 (seal keys); reviews S1-A2-4, S1-A3-03, S1-A3-06, S1-A3-17, S1-A3-20; re-reviews S2-A2-3, -5, -6, -11, S1-A3-R02, -R05, -R07
- **Review:** A2, A3, A6/A7, A9

## Context

In revision 1 the display object behind `display_digest` and the link-service `return_url` came from the api, so the authority's step "digest equals the stored display" proved only that the device saw what the api chose (S1-A2-4, S1-A3-06). The key-log head did not tell the device whose account it described or which keys were in it (S1-A3-03), and the single pinned `keylog-signing` key had no rollover path (S1-A3-17). Revision 2 fixed those. The re-reviews found that (a) a correct, signed display of key thumbprints does not bind the person's approval to the device they are holding (S2-A2-3); (b) the revocation statement was undefined and could be signed by the very key it should revoke, so a compromised active key could revoke the standby (S2-A2-5, S1-A3-R02); (c) unauthenticated OIDC page loads could exhaust challenge signing that other statements share (S2-A2-6).

## Decision

### 1. The authority builds every display it signs for

`POST challenges` takes only references: purpose, `link_client_id` or `oidc_client_id`, the requested `return_url`/`redirect_uri` (checked byte for byte against the registration and refused otherwise), the delivery id, and for key-log purposes the entry being proved. The authority builds the display object from its own records:

| Purpose | Display members |
|---|---|
| `link_open` | tenant `display_name` and link-client `display_name` (both reviewed at registration), exact `return_url` and its host, purpose, `match_digits` (cross-device) |
| `oidc_login` | OIDC client `display_name` (reviewed at registration), exact `redirect_uri` and its host, `match_digits` (app path) |
| `keylog_device_added` | `reported_name` (the name the new device sent: bounded to 40 characters, NFC, no control, bidi or zero-width characters; **reported text, not authority-sourced**, rendered as "Name chosen on the new device: {name}"), `kids` (every key in the entry, checked equal to the entry), `match_digits: 6` (the comparison code of §4.1; the code itself is never in the display) |
| `keylog_passkey_added` | `kids` (the new passkey's `kid`), the fixed label "New passkey on this phone" (allowed only from the app on the device that created it, ADR-0023 §4) |
| `recovery_cancel` | recovery start time and planned activation time |
| `recovery_codes_set` | set id and code count |
| `recovery_started` | `activates_after_hours: 72` (no person-facing prompt; the recovering device shows UX_COPY S-REC-01) |
| `enrollment_confirmed` | `account_ref`, the confirming device's own `kids`, `head_hash`, `seq` (no person-facing prompt; S-SEC-02 progress) |

Every purpose has a display object, so `display_digest` is defined for every factor-JWS purpose (S1-A3-R05 item 5). Fields the authority cannot source are either absent or marked as reported text, as `reported_name` is (S1-A3-R05 item 4). The api never supplies display text; it relays the object unchanged.

### 2. Authority-signed device statements

All are compact JWS under the JOSE profile of ADR-0023 §2, signed by the **`device-statement-signing`** key (EC P-256, ES256, `kv-vdr-auth`), `aud = "urn:viadere:device"`, `iss = "urn:viadere:authority:<env>"`, separated by `typ`. Exactly the listed members, total ≤ 4096 bytes. **Every** device check below begins with: signature by a pinned, non-revoked statement key (§3; `kid` in the JOSE header only), the exact `typ`, `iss = urn:viadere:authority:<build env>`, `aud`, and `env` = the build's environment (S1-A3-R05 item 1). One Core verifier takes the expected `typ` as a non-optional parameter and checks the member set per `typ`; a cross-`typ` vector shows each of the four refused when presented as any of the others (S1-A3-R07).

| `typ` | Payload | Device check (in addition to the common checks) |
|---|---|---|
| `viadere-challenge+jws` | `{v, iss, aud, env, ach, nonce, purpose, display, account_ref?, kids?, return_url?/redirect_uri?, match_required, exp, iat}` | `exp` (±60 s); before the person acts. The app renders exactly `display`; for `link_open` it will open only `return_url` from this statement. Key-log purposes: an approving device requires `account_ref` to equal its own (S2-A2-11 item 4); a new device requires `kids` to be exactly its own keys (§4.1) |
| `viadere-keylog-head+jws` | `{v, iss, aud, env, account_ref, seq, head_hash, keys:[{kid, purpose, usable_from, entry_type, imported, grant_capable}], pending_recoveries:[{recovery_id, started_at, activates_at, legacy, kids}], issued_at}` (`kid_header` of revision 2 removed: the `kid` belongs in the JOSE header, S1-A3-R05 item 2) | `issued_at` ≤ 15 min old; `seq` ≥ the highest `seq` the app has accepted (stored; lower refused); `keys` **contains** this device's current key ids (else refused as "not my account"). Two stricter uses: the enrollment check requires the confirmed entry to list **exactly** this device's keys (ADR-0032 §1.4), and a recovering device requires a pending recovery whose `kids` are **exactly** its own new keys (ADR-0032 §3.2) |
| `viadere-tenant-keys+jws` | ADR-0031 §2 | ADR-0031 §4 |
| `viadere-device-keys-revocation+jws` | `{v:1, iss, aud, env, revoked:[{key_family: "device-statement" \| "recovery-seal", kid}], issued_at}` | §3.3 rules |

**Signing cadence (S1-A3-R05 item 3, S2-A2-11 item 2).** Heads and tenant records are signed on change and cached; a cached statement is **re-signed whenever it is older than 5 minutes at the time it is served**, so a served statement is never older than 5 minutes plus relay time, well inside the device's 15-minute limit. `GET head` is not a Key Vault `sign` per request.

**Challenge-signing bulkhead (S2-A2-6).** Challenge signing has its own per-tenant budget and its own concurrency pool at the authority, separate from heads, tenant records, revocation lists and grants, which keep reserved capacity. A flood of challenges for one tenant degrades only that tenant's challenges (`429 challenge_budget` for those), never another tenant's challenges or anyone's heads, tenant records or grants (ST-AUTH-24). OIDC creates challenges only after a user action (ADR-0024 §4).

### 3. Pinned keys, roles and revocation (both key families)

1. **Pins.** The app pins two ordered lists per environment as Core constants: `VIADERE_AUTHORITY_DEVICE_KEYS = [active, standby]` (statement signing) and `VIADERE_AUTHORITY_SEAL_KEYS = [active, standby]` (ADR-0034). Index 0 is the active key, index 1 the standby. Every statement header carries `kid` (RFC 7638 thumbprint).
2. **Separate key objects (S1-A3-R02 item 3).** The statement standby is a separate Key Vault key `device-statement-signing-standby`, created disabled, on which `id-viadere-authority` has **no role** until rollover; the seal standby is wrapped under the separate `recovery-seal-kek-standby` (ADR-0034 §5). The rollover role grant goes through `id-gh-infra-auth-apply-<env>` (reviewer-gated). Authority code execution before rollover therefore cannot sign as, or open envelopes for, a standby. The standby protects against both key-material exposure and authority code execution that happened before the rollover.
3. **Revocation statement rules (S2-A2-5, S1-A3-R02).** The app accepts a `viadere-device-keys-revocation+jws` only under these rules, and ignores (and reports to telemetry) any other:
   - `key_family: "device-statement"`: signed **only** by the pinned **standby** statement key, and naming **only** the active (index 0) statement `kid`. A list signed by the active key, or naming the standby, is refused. Consequently no list can ever revoke the standby, and the app never revokes its last pinned statement key.
   - `key_family: "recovery-seal"`: signed by a pinned statement key that is not revoked, and naming **only** the active (index 0) seal `kid`. Allowing the active statement key here is deliberate: revoking the active seal key only moves sealing to the standby seal key, which a holder of the statement key does not control; the worst abuse is that sealing waits until the standby is enabled (availability, alerted). No list can revoke the seal standby.
   - Revocations are **sticky**: stored by the app, never expire, and are undone only by an app update that pins a new list. `issued_at` may not be more than 60 s in the future; there is no freshness limit, so a revocation is valid whenever it arrives.
   - After the app verifies a statement-family revocation, it accepts only statements signed by the standby. After a seal-family revocation, it seals only to the seal standby.
   - The latest revocation list is returned with every head and every tenant record response (the api relays it unchanged). An app that never receives it keeps trusting the revoked key: residual R-22.
4. **Compromise of an active key.** The authority admin path grants the role on the standby (reviewer-gated), switches the explicit version pin (ADR-0028 §2), signs the revocation list with the standby, and disables the compromised key. The next app release pins `[old standby, new standby]`.
5. **Routine rotation (no compromise).** An app release pins `[current, next]` at least one release cycle before the switch. The authority switches only after the minimum supported app version for authority-backed flows (`AUTHORITY_MIN_APP_VERSION`, enforced by the api for link service, OIDC app approval and recovery registration) pins the next key. A retired seal private key is destroyed once no supported version pins it (ADR-0034 §5).
6. **Loss of both keys of a family (S1-A3-R02 item 4).** Statement keys: every head, challenge, tenant record and revocation list fails closed; link service, the OIDC app path and business-mode links stop, and the app shows S-SEC-01 and E-01; recovery is an app release pinning a new pair. Seal keys: new code sets and sealed recovery starts fail closed until an app release pins a new pair; existing verifiers keep working. Both are residual R-22 (owner A3) and runbook items in KEY-ROTATION.md.
7. **Reference set for the startup check (S1-A3-R02 item 6).** For these two families the authority's ADR-0028 §2 startup check compares the configured version's thumbprint with the **app-pinned constants** for its environment, not with JWKS.
8. **Runbook timing (condition C-6).** `docs/ops/KEY-ROTATION.md` states these rules, the compromise and loss-of-both procedures and the routine sequence **before Stage 4 pins any key** (ledger L-2 moved from Stage 6 to Stage 4). The first app release pins active and standby for both families.

### 4. Factor JWS commits to what was shown and opened

- `display_digest = lowercase hex SHA-256("VIADERE-DISPLAY-V1\n" ‖ canonical(display))` over the display member of the verified challenge statement; the authority recomputes it from its own stored display (step 5 of ADR-0023 §3 compares against an authority-built object).
- For `link_open` the factor JWS also carries `return_url` (exact string); the authority compares it byte for byte with the client registration and the challenge. The device opens **only** that URL, with the code appended as a fragment (`#vdr_code=`; ADR-0021 §5.3), and only after the authority has accepted the evidence. If AS-1 fakes the acceptance, no code hash is registered and the opened code is useless.

#### 4.1 `device_added`: comparison code bound to the new device's keys (S2-A2-3)

1. New device B enrolls at the api, creates its keys and submits the `device_added` entry with a PoP by each new key over `VIADERE-KEYLOG-V1\n{env}\ndevice_added\n{kid}\n{nonce}`. The api asks the authority for a `keylog_device_added` challenge for that entry.
2. **B** fetches the signed challenge and refuses it unless its `kids` are **exactly** B's own keys. It then shows the comparison code (UX_COPY S-DEV-03):
   `code = decimal6(SHA-256("VIADERE-DEVICE-ADD-V1\n" ‖ env ‖ "\n" ‖ nonce ‖ "\n" ‖ join("\n", sorted kids)))`, where `nonce` is the challenge's base64url nonce, `kids` are sorted in ascending byte order, and `decimal6(h)` = the big-endian unsigned integer of the first 8 bytes of `h`, modulo 1 000 000, written with 6 digits (leading zeros kept; bias < 2^-44). Vectors in `docs/protocol/vectors/keylog-v1.json`.
3. **A** (an existing device with a logged, grant-capable `approvalBiometric` key whose `usable_from` has passed) verifies the same challenge, checks `account_ref` equals its own, renders the display (reported name labelled as such, the number of keys) and asks for **the number shown on the new device** (UX_COPY S-DEV-04). A **never shows the code**: showing it on A would let the person copy A's own screen and would prove nothing. The typed digits go into the factor JWS `match` member. (A2's text says A's display "shows the same code, computed by the authority"; we read it as "the authority computes the expected code", which is what makes the typed entry a check. Flagged for A2 to confirm.)
4. The **authority** computes the expected code from its stored entry's `kids` and the challenge nonce and compares it with `match` in constant time; wrong entries follow ADR-0023 §3 step 6 (3 failures fail the challenge and count toward the pause). It also checks that the approving key belongs to the entry's account (S2-A2-11 item 4) and verifies every new key's PoP.
5. If AS-1 substitutes its own keys in the entry, the signed challenge lists the attacker's `kids`, so B refuses it and shows no code (S-DEV-05). If AS-1 runs two challenges (a genuine one that B accepts and a substituted one sent to A), the code B shows is computed over a different nonce and different `kids` than the authority expects for the substituted entry, so A's evidence is refused (probability of a lucky match ≤ 3 × 10^-6). Then B confirms its own enrollment (ADR-0032 §1.4).

### 5. Key-log hash chain (S1-A3-20)

`entry_hash = SHA-256("VIADERE-KEYLOG-ENTRY-V1\n" ‖ canonical(entry without entry_hash))`; `prev_hash` of genesis = 32 zero bytes; `head_hash` = `entry_hash` of entry `seq`. Vectors in `docs/protocol/vectors/keylog-v1.json`.

### 6. Tests

- ST-LS-07 (substituted `return_url` → evidence refused, no code registered), ST-LS-08 (api-modified display → refused before the person acts and at the authority).
- ST-REC-10 (A, K): a `device_added` display whose `kids` differ from the entry, a missing PoP by a new key, an approving device whose `account_ref` differs from the challenge's, or an approving key that does not belong to the entry's account → refused.
- ST-REC-12 (K, V): head for another account, lower `seq`, stale, wrong `typ`, wrong `iss` or `env` → refused.
- ST-REC-13 (K): statements signed by a `kid` in a verified revocation list are refused, and the revocation is sticky across restarts and reinstall-free updates.
- ST-REC-18 (A, K): AS-1 substitutes keys in a genuine add; the code on B does not match the authority's expected code, the evidence is refused and no key is appended.
- ST-REC-19 (K, V): a statement-family revocation signed by the active key, or naming the standby, is ignored; a seal-family list naming the seal standby is ignored; a valid list moves verification or sealing to the standby.
- ST-AUTH-24 (A): a challenge flood for one tenant leaves heads, tenant records, revocation lists, grants and other tenants' challenges unaffected.
- ST-GW-07 is rewritten so that it fails without §1: the api submits a challenge with its own display text and the authority ignores it.

## Consequences

- One Key Vault `sign` per authority challenge, inside the challenge bulkhead.
- The app needs both pinned lists, the revocation store and the comparison-code screens in Stage 4; KEY-ROTATION.md moves before Stage 4.
- `keylog-signing` is renamed `device-statement-signing` in ADR-0023, ADR-0028 and TRUST_BOUNDARIES; the standby is a separate key object.

## Threat assumptions changed

- AS-1 can no longer choose what the person sees in an authority-backed prompt, where the device sends a link code, which account's head the device trusts, or which keys a person's device-add approval admits.
- A compromised active statement key can no longer revoke the standby; a compromised active seal key cannot block sealing to the standby for longer than the rollover.

## Reviewers required

A2, A3 (formats, key separation by `typ`, rollover, comparison code), A6/A7 (verification and storage of `seq` and revocations; comparison screens), A9 (rendered display and comparison copy).
