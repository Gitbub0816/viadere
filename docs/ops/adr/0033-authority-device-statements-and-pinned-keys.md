# ADR-0033: Authority-built displays, authority-signed device statements (challenges, key-log heads, tenant records) and pinned-key rollover

- **Status:** proposed (2026-11-02, Stage 1 revision 2)
- **Spec reference:** §4.3, §7 (no deceptive state), §9.3, §26 (gateway compromise)
- **Related:** ADR-0021 §5 (link service), ADR-0023 (factor JWS, key log), ADR-0024 §4, §8 (OIDC display, consent), ADR-0031 (tenant records), ADR-0032 (account binding); reviews S1-A2-4, S1-A3-03, S1-A3-06, S1-A3-17, S1-A3-20
- **Review:** A2, A3, A6/A7, A9

## Context

In revision 1 the display object behind `display_digest` and the link-service `return_url` came from the api, so the authority's step "digest equals the stored display" proved only that the device saw what the api chose (S1-A2-4, S1-A3-06). The key-log head did not tell the device whose account it described or which keys were in it (S1-A3-03), and the single pinned `keylog-signing` key had no rollover path (S1-A3-17).

## Decision

### 1. The authority builds every display it signs for

`POST challenges` takes only references: purpose, `link_client_id` or `oidc_client_id`, the requested `return_url`/`redirect_uri` (checked byte for byte against the registration and refused otherwise), the delivery id, and for key-log purposes the entry being proved. The authority builds the display object from its own records:

| Purpose | Display members (all authority-sourced) |
|---|---|
| `link_open` | tenant `display_name` and link-client `display_name` (both reviewed at registration), exact `return_url` and its host, purpose, `match_digits` (cross-device) |
| `oidc_login` | OIDC client `display_name` (reviewed at registration), exact `redirect_uri` and its host, `match_digits` (app path) |
| `keylog_device_added`, `keylog_passkey_added` | new device name (bounded, NFC, no control/bidi characters), thumbprint (`kid`) of every key in the entry, checked equal to the entry's keys |
| `recovery_cancel` | recovery start time and planned activation time |
| `recovery_codes_set` | set id and code count |

Fields the authority cannot source are not in the object. The api never supplies display text; it relays the object unchanged.

### 2. Authority-signed device statements

All are compact JWS under the JOSE profile of ADR-0023 §2, signed by the **`device-statement-signing`** key (EC P-256, ES256, `kv-vdr-auth`, replacing revision 1's `keylog-signing`), `aud = "urn:viadere:device"`, `iss = "urn:viadere:authority:<env>"`, and separated by `typ`:

| `typ` | Payload | Device check |
|---|---|---|
| `viadere-challenge+jws` | `{v, iss, aud, env, ach, nonce, purpose, display, return_url?/redirect_uri?, match_required, exp, iat}` | before the person acts: signature, `typ`, `aud`, `exp`; the app renders exactly `display` and, for `link_open`, will open only `return_url` from this statement |
| `viadere-keylog-head+jws` | `{v, iss, aud, env, kid_header, account_ref, seq, head_hash, keys:[{kid, purpose, usable_from, entry_type, imported, grant_capable}], pending_recoveries:[{started_at, activates_at, legacy}], issued_at}` | signature, `typ`, `aud`, `env`, `issued_at` ≤ 15 min old, **the list contains this device's own current key ids** (else refused as "not my account"), `seq` ≥ the highest `seq` the app has accepted (stored; lower refused) |
| `viadere-tenant-keys+jws` | ADR-0031 §2 | ADR-0031 §4 |

Signing load: challenges are signed per challenge (rate-limited per tenant and per account at the authority, ADR-0020 §8); heads and tenant records are signed on change and refreshed at most every 5 minutes, then cached, so `GET head` is not a Key Vault `sign` per request (S1-A3-20).

### 3. Pinned keys and rollover

1. The app pins **two** `device-statement-signing` public keys from day one (`VIADERE_AUTHORITY_DEVICE_KEYS`): the active version and a pre-created standby version, held disabled and unpublished until needed. Every statement header carries `kid` (RFC 7638 thumbprint of the authority key).
2. Compromise of the active key: the authority switches to the standby (explicit version pin, ADR-0028 §2) and signs a `viadere-device-keys-revocation+jws` with the standby that lists the revoked `kid`. The app fetches this list with every head; once it has verified a revocation signed by a pinned key, it refuses statements signed by the revoked `kid`. An app update then pins a new standby. An attacker who holds the compromised key can withhold the revocation from an app that never reaches the real list; this is residual R-22 (owner A3).

### 4. Factor JWS commits to what was shown and opened

- `display_digest = lowercase hex SHA-256("VIADERE-DISPLAY-V1\n" ‖ canonical(display))` over the display member of the verified challenge statement; the authority recomputes it from its own stored display (step 5 of ADR-0023 §3 now compares against an authority-built object).
- For `link_open` the factor JWS also carries `return_url` (exact string); the authority compares it byte for byte with the client registration and the challenge. The device opens **only** that URL, with the code appended as a fragment (`#vdr_code=`; ADR-0021 §5.3), and only after the authority has accepted the evidence. If AS-1 fakes the acceptance, no code hash is registered and the opened code is useless.
- For `keylog_device_added` the authority checks the display thumbprints equal the entry's keys and requires a proof-of-possession by the **new** key over `VIADERE-KEYLOG-V1\n{env}\ndevice_added\n{kid}\n{nonce}` (S1-A3-20).

### 5. Key-log hash chain (S1-A3-20)

`entry_hash = SHA-256("VIADERE-KEYLOG-ENTRY-V1\n" ‖ canonical(entry without entry_hash))`; `prev_hash` of genesis = 32 zero bytes; `head_hash` = `entry_hash` of entry `seq`. Vectors in `docs/protocol/vectors/keylog-v1.json`.

### 6. Tests

ST-LS-07 (substituted `return_url` → evidence refused, no code registered), ST-LS-08 (api-modified display → refused before the person acts and at the authority), ST-REC-10 (`device_added` display thumbprints differ from the entry → refused), ST-REC-12 (K: head for another account, lower `seq`, stale, or wrong `typ` → refused), ST-REC-13 (K: statements signed by a revoked `kid` refused after a verified revocation list). ST-GW-07 is rewritten so that it fails without §1: the api submits a challenge with its own display text and the authority ignores it.

## Consequences

- One Key Vault `sign` per authority challenge; the authority's challenge budget bounds it.
- The app needs the pinned key set and the revocation fetch path in Stage 4.
- `keylog-signing` is renamed `device-statement-signing` in ADR-0023, ADR-0028 and TRUST_BOUNDARIES.

## Threat assumptions changed

- AS-1 can no longer choose what the person sees in an authority-backed prompt, where the device sends a link code, or which account's head the device trusts.

## Reviewers required

A2, A3 (formats, key separation by `typ`, rollover), A6/A7 (verification and storage of `seq` and revocations), A9 (rendered display).
