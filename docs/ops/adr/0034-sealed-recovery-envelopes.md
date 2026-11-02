# ADR-0034: Sealed recovery envelopes to the authority (`recovery-seal`, HPKE)

- **Status:** proposed (2026-11-02, Stage 1 revision 3)
- **Spec reference:** §4.3 invariants 1 and 5, §23, §26 (gateway compromise, recovery), §27 stop-ship 1 and 6
- **Related:** ADR-0007 (HPKE suite and Core implementation), ADR-0023 §2-§4 (JOSE profile, factor JWS, key log), ADR-0028 §1-§2, §5 (custody, roles, policy rules), ADR-0032 §3 (recovery flow that uses these envelopes), ADR-0033 §3 (pinned keys and revocation); SECURITY §2.2 (canonical JSON), §2.26 (code alphabet); reviews S2-A2-1, S1-A3-R01, S2-A2-5, S1-A3-R02
- **Review:** A3 and A2 (both required), A6/A7 (device sealing), A11 (custody runbook)

## Context

Every device → authority request is relayed by the api (B4 → B5). Revision 2 sent recovery codes to the authority in that relay as plaintext, both when a set was registered and when a recovery started, and the authority set was the same set the api hashes with `SERVER_PEPPER`. A compromised api (AS-1) could therefore record codes at registration, search them offline from its own database, or swap the new key at recovery start. In each case it ends with an authority-verified recovery and grant-capable keys (S2-A2-1 Critical, S1-A3-R01 High). Both reviewers require the codes and the new recovery keys to be confidential to the authority and bound to each other, with a code set the api cannot hash.

## Decision

### 1. Construction

- **HPKE, RFC 9180, mode_base, single-shot.** Suite: **KEM `DHKEM(P-256, HKDF-SHA256)` (0x0010), KDF `HKDF-SHA256` (0x0001), AEAD `AES-256-GCM` (0x0002)**. This is the ADR-0007 suite (CryptoKit `HPKE.Ciphersuite.P256_SHA256_AES_GCM_256`; swift-crypto's HPKE on Linux), so the app and the authority reuse one Core implementation and its RFC 9180 test vectors. No new primitive (F-23).
- `info` is fixed per purpose: `"VIADERE-RECOVERY-SET-V1\n" ‖ env` and `"VIADERE-RECOVERY-START-V1\n" ‖ env` (`env` = `stg` or `prod`). An envelope sealed for one purpose or environment cannot be opened as another.
- `aad` = the ASCII bytes of `ach ‖ "\n" ‖ nonce` of the authority challenge that the envelope answers (both from the authority-signed `viadere-challenge+jws`, ADR-0033 §2). The authority opens an envelope only with the `aad` of the challenge named in the request; a replay against another challenge fails AEAD authentication.
- **Wire form** (JSON, strict, ≤ 4096 bytes): `{"v":1, "kid":<RFC 7638 thumbprint of the seal public key>, "enc":<base64url, 65 bytes uncompressed point>, "ct":<base64url>}`. Nothing else.
- **Commitment.** `envelope_digest = base64url(SHA-256(enc ‖ ct))` (no padding). The device puts it into the signed object that authorizes the envelope (the factor JWS for a set, every new key's PoP for a start; ADR-0032 §3). The api cannot replace an envelope without breaking a device signature.

### 2. Plaintexts (canonical JSON, SECURITY §2.2; exact member sets; duplicates refused)

| Purpose | Members |
|---|---|
| `recovery_codes_set` | `v` (1), `purpose`, `account_ref`, `set_id` (`rcs_` + 22 base64url, device CSPRNG), `nonce`, `codes` (exactly 10 normalized codes, pairwise distinct) |
| `recovery_started` | `v` (1), `purpose`, `recovery_id` (the api recovery id the start answers), `nonce`, `code` (one normalized code), `new_kids` (the `kid` of **every** key the recovery will add, ADR-0023 §2 device-key definition, sorted ascending, no duplicates, 1-4 entries) |

**Codes (A3 item 4).** Generated **on the device** by the platform CSPRNG, 10 per set, each 10 symbols of the Crockford alphabet of SECURITY §2.26 (50 bits). Normalization before sealing and before hashing: upper-case; remove spaces and `-`; map `I`, `L` → `1` and `O` → `0`; refuse anything else or any length other than 10. The device shows codes as `XXXXX-XXXXX`.

### 3. Separate code sets (A3 item 1)

The authority set is **not** the api's set. It is generated on the device and leaves it only inside an envelope. The api never receives a code, a hash of a code, or any value derived from a code in a form it can test. When the authority confirms a registered set (signed head entry `recovery_codes_set`), the app calls the api to **invalidate the api's legacy set** for the account (`recovery_codes` → `invalidated`), so the person holds one set. The recovery **ID** stays an api locator (SECURITY §2.26); it names an account but is not a secret against AS-1, and nothing at the authority depends on it being secret.

### 4. Authority processing

1. Refuse unless `kid` is the active seal key the authority holds (§5) and the request names a pending challenge of the matching purpose.
2. Open with the purpose's `info` and the challenge's `aad`; any HPKE failure is `401 evidence_invalid` and counts as a failed attempt for that account (start) or is refused without effect (set).
3. Strict parse; exact members; `nonce` equals the challenge nonce; `purpose` equals the challenge purpose; for a set, `account_ref` equals the account of the authorizing key.
4. Recompute `envelope_digest` and require it to equal the value in the authorizing device signature.
5. Use the plaintext only in memory: compute verifiers (set) or verify one code (start, ADR-0032 §3.2), then overwrite the buffers (best effort). Plaintext and envelopes are **never stored or logged**; the authority's log allow-list contains no envelope member. Envelopes are not retained (they are processed in the request; nothing to classify under ADR-0026).
6. **Verifier** = `HMAC-SHA256(RECOVERY_VERIFIER_KEY, "recovery-code-v2\n" ‖ account_ref ‖ "\n" ‖ set_id ‖ "\n" ‖ normalized_code)`, stored in `authority_recovery_codes {account_ref, set_id, verifier (unique per account_ref), state}`. Verification computes the HMAC of the presented code and looks it up by value; the lookup, the attempt counter and the transition `active → used` are one transaction (compare-and-swap). Argon2id is not needed: the key lives only in `kv-vdr-auth` and the codes are uniformly random (A3 item 4).

### 5. `recovery-seal` keys and custody

Key Vault has no ECDH (key-agreement) data-plane operation, so an HPKE KEM private key cannot stay inside Key Vault. Custody is therefore:

1. **Creation** by the authority admin job (`ViadereAuthority admin seal-key create`, reviewer-gated, ADR-0019 §5): it generates the P-256 KEM key pair in memory, wraps the private scalar **locally** with the public half of a dedicated non-exportable Key Vault key `recovery-seal-kek` (RSA 3072, RSA-OAEP-256; key operations `wrapKey`/`unwrapKey` only), stores `{kid, public_jwk, wrapped_private, role: active|standby, created_at}` in `authority_seal_keys`, prints the public JWK and thumbprint into the attested key inventory (ADR-0024 §7.3), and discards the private key.
2. **Use.** At startup the authority unwraps the **active** seal key with Key Vault (`keys/unwrapKey/action`) and holds it only in process memory. Key Vault `AuditEvent` reconciliation (ADR-0028 §2) expects exactly one `unwrapKey` per authority replica start; any other unwrap alerts.
3. **Standby.** A second seal key pair is created at the same time and wrapped under a **separate** Key Vault key `recovery-seal-kek-standby`, on which `id-viadere-authority` has **no role** until rollover; the role is granted through `id-gh-infra-auth-apply-<env>` (reviewer-gated). Authority code execution before rollover therefore cannot open envelopes sealed to the standby (same pattern as ADR-0033 §3 for signing keys, S1-A3-R02 item 3).
4. **Pinning.** The app pins both public keys, `VIADERE_AUTHORITY_SEAL_KEYS = [active, standby]`, next to `VIADERE_AUTHORITY_DEVICE_KEYS`, as constants in Core for each environment. The device seals only to the active entry unless a verified revocation has retired it (ADR-0033 §3), then to the standby. Seal keys are never fetched from the network: no statement can substitute them.
5. **Rotation and revocation** follow ADR-0033 §3 (same list, `key_family: "recovery-seal"`). A retired seal private key is destroyed (wrapped blob deleted, KEK version disabled) once no supported app version pins it, so recorded envelopes cannot be opened afterwards, even by a later authority compromise.

Roles and policy: `id-viadere-authority` gets the custom role "Viadere Authority Unwrapper" (`keys/read`, `keys/unwrapKey/action`) on `recovery-seal-kek` only; `AUTH-SIGNER-ROLE` (ADR-0028 §5) allows exactly that addition, and the new rule `AUTH-STANDBY-ROLE` fails while any identity other than the authority crypto-officer group holds a data role on `recovery-seal-kek-standby` (or `device-statement-signing-standby`) outside a recorded rollover.

### 6. What the api still sees

Ciphertext, `kid`, `enc`, the recovery id, the new keys' public halves and PoPs (all public), and timing. It cannot: learn a code (HPKE confidentiality under the pinned key), search one offline (it holds no hash of an authority code), substitute its own key at start (the code is sealed together with `new_kids`, and every new key's PoP commits to `envelope_digest`), or replay a set or start against another challenge or account (`aad`, `nonce`, `account_ref`).

### 7. Vectors and tests

- Vectors `docs/protocol/vectors/recovery-seal-v1.json`: RFC 9180 suite vectors re-run in Core; valid set and start envelopes with fixed ephemeral keys; wrong `info` (env, purpose); wrong `aad`; tampered `ct`; extra or missing plaintext members; non-normalized code; `envelope_digest` mismatch.
- ST-REC-14 (A, A2 and A3): AS-1 records every byte relayed at registration and start (simulated api with full DB and `SERVER_PEPPER`); it then cannot start a non-legacy recovery: a replayed envelope against another challenge or account, or with a substituted nonce or `new_kids`, is refused.
- ST-REC-15 (A): a start whose PoP keys differ from the sealed `new_kids` is refused; an api-substituted key never becomes active.
- ST-REC-21 (S, A): after registration, the api database and `SERVER_PEPPER` contain no value that verifies an authority code (the api's legacy rows for the account are `invalidated`; no authority code or derivative appears in any api table or log).
- ST-REC-19 (K) covers the seal-key revocation rules with the device-statement rules (ADR-0033 §6).

## Consequences

- The app needs the seal key pair constants and a Core HPKE call before it may offer "Make new recovery codes" (decision 16 OQ-2 is gated on this ADR; ADR-0032 §3.5).
- One Key Vault `unwrapKey` per authority start; no per-request Key Vault call for recovery.
- The api's legacy set disappears for every account that registers an authority set; legacy recovery remains only for accounts that never registered one, and it is never grant-capable (ADR-0032 §3.3).

## Threat assumptions changed

- AS-1 can no longer harvest, search or swap authority recovery codes or the keys they authorize. AT-1 1.3.3 becomes [C] when this ADR and ADR-0032 §3 ship and ST-REC-14, -15, -16, -21 pass.
- New residual **R-23** (owner A3): authority **process** compromise (T-AUTH-12 class) can read the in-memory active seal private key and open envelopes recorded since that key became active, until it is retired. Bounded by retiring and destroying seal keys with each pinned-key rotation, by the unwrap reconciliation, and by the fact that the same compromise already reaches the signing builders. Removal: none planned in staging; re-assessed if a Key Vault or Managed HSM key-agreement operation becomes available (A3, Stage 6 re-check).

## Reviewers required

A3 and A2 (both), A6/A7 (Core HPKE on device), A11 (custody runbook in KEY-ROTATION.md).
