# Key rotation (ops gap G-8)

**Status:** v1, 2026-10-28. Tooling: `Server/Sources/ViadereServerKit/Operations/KeyRotation.swift`; tests: `WP6RotationTests`. All four server secrets can be rotated without
downtime. Rotation is a routine operation (do it on a schedule and after any suspected exposure), not an incident-only tool. A KMS envelope (ADR-03) will make the data key
routine too; until then these procedures apply. Back up every old key until the step that says it may be removed.

| Secret | Env | Id / epoch | Previous values | Rotation effect |
|---|---|---|---|---|
| Field encryption | `DATA_ENCRYPTION_KEY` | `DATA_ENCRYPTION_KEY_ID` (1-16 chars of letters, digits, dash; default `k1`) | `DATA_ENCRYPTION_KEYS_PREVIOUS="k1:<base64url>,k2:<base64url>"` | New writes use the current key; old values still open until re-encrypted |
| Pepper | `SERVER_PEPPER` | `SERVER_PEPPER_ID` (default `p1`) | `SERVER_PEPPERS_PREVIOUS="p1:<base64url>"` | Versioned hashes keep verifying; see section 3 for the older lookup hashes |
| Audit chain | `AUDIT_CHAIN_KEY` | `AUDIT_CHAIN_KEY_EPOCH` (integer, default 1) | `AUDIT_CHAIN_KEYS_PREVIOUS="1:<base64url>,2:<base64url>"` (every earlier epoch) | New events MAC under the new epoch; the chain verifies end to end |
| Connect links | `CONNECT_LINK_SIGNING_KEY` | `CONNECT_LINK_SIGNING_KEY_ID` (default `c1`) | `CONNECT_LINK_SIGNING_KEYS_PREVIOUS="c1:<base64url>"` | New links name the new key; issued links verify until they expire |

Generate a key: `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`. Previous keys are **secrets** (`Infra/fly/secrets.txt`); the ids are plain values. The server refuses to start
if a previous list repeats the current id, an id is malformed, a previous key is shorter than 32 bytes, or the audit epochs are not contiguous.

## 1. Order of operations (all four)

1. Take a backup/snapshot (Neon) and generate the new key. Store old and new in escrow.
2. Set the old value in the matching `*_PREVIOUS` list **and** the new value plus its id in **one** `fly secrets set` (one restart). Machines restart one by one; during the roll an instance that has not restarted yet can still read everything the new instances wrote only if it knows the new key, so for the data key do the roll in two steps when you cannot tolerate a few read errors: first add only `DATA_ENCRYPTION_KEYS_PREVIOUS="k1:<old>,k2:<new>"` (everyone can read both), then switch the current key.
3. Run the re-encryption or verification step of the section below.
4. Only after verification, remove the old key from `*_PREVIOUS` and restart.

## 2. Data encryption key (`DATA_ENCRYPTION_KEY`)

Ciphertexts name their key: `v2.` (row-bound, legacy id `k1`), `v3.<id>.` (row-bound with a key id) and the oldest column-bound `v1.`.

```bash
# 1. add the new key; keep the old one as "previous" (both secrets), set the new id
fly secrets set --app viadere-server DATA_ENCRYPTION_KEY=<new> DATA_ENCRYPTION_KEYS_PREVIOUS="k1:<old>" 
fly deploy ...   # or wait for the secrets restart; the plain value DATA_ENCRYPTION_KEY_ID=k2 is set in fly.production.toml [env]
# 2. re-encrypt every sealed column under the new key (idempotent, batched by primary key, safe while serving,
#    compare-and-swap on the old value so a concurrent writer is never overwritten)
fly ssh console --app viadere-server -C "/app/ViadereServer rotate-data-key"
# 3. prove nothing is left under another key or format
fly ssh console --app viadere-server -C "/app/ViadereServer verify-data-key --require-current"
# 4. remove DATA_ENCRYPTION_KEYS_PREVIOUS; restart; run verify-data-key again
```

`rotate-data-key` prints how many values it found under each key id, how many it rewrote and which columns failed to open; it exits non-zero (and rewrites nothing it could not
read) if any value does not open with the configured keys: that means a previous key is missing; restore it before going on. The registry of sealed columns is
`SealedColumns.all`; a test fails when a new `context:` string appears in the source without an entry, so a new encrypted column cannot be forgotten. `webhook_deliveries.body`
and `dashboard_ceremonies.payload_json` may hold unsealed values (older plaintext); those are skipped and counted. Wallet and vault keys are separate (`WALLET_ENCRYPTION_KEY_WRAPPED`, device keys).

## 3. Pepper (`SERVER_PEPPER`)

The pepper keys two kinds of hash.

* **Versioned** hashes (`<pepper id>:<hex>`; `Hasher256.versionedHex` / `verifyVersioned`) name the pepper that made them and keep verifying while that pepper is in `SERVER_PEPPERS_PREVIOUS`. Used today
  by contract acceptance (address and agent hash) and the API-key last-used address. Use `versionedHex` for every new stored hash that must survive a rotation.
* **Lookup** hashes (`hmacHex`) are single-valued indexes made with the **current** pepper: phone-number hashes and OTP hashes, the dashboard e-mail hash and e-mail-code hash, recovery id and code hashes,
  reward redemption and delegation invitation hashes, RCS postback and Wallet authentication hashes, Approve enrollment code hashes, Verify idempotency and result references, the CSRF derivation. There is
  **no automatic re-hash**: after a rotation these no longer match what is stored. The visible effects: phone links must be re-verified, dashboard users cannot sign in by e-mail until their hash is
  rewritten (an operator re-issues the e-mail hash from the sealed e-mail with a one-off script, which does not exist yet), recovery codes must be re-issued, open codes and invitations expire.

So: **rotating `SERVER_PEPPER` is a planned, user-visible maintenance event**, justified only by a suspected exposure of the pepper together with a database copy (the pepper's job is to stop offline
guessing from a database leak alone). Until the lookup hashes are migrated to `versionedHex` with multi-pepper lookup (tracked as residual risk in SECURITY.md section 2.80) do not rotate it
casually. `SUBJECT_REF_KEY` has its own re-derivation (clear `relationships.subject_ref`; the job re-derives; businesses re-fetch references).

### Residual risk: what a pepper rotation cannot do (platform gate C3)

State this precisely before anyone decides to rotate; there is no code that makes it safe today.

* **Lookup hashes are single-pepper.** Every `hmacHex` value stored in the database was computed with the pepper in force when it was written and is looked up by recomputing it with the current
  pepper. There is no second lookup under `SERVER_PEPPERS_PREVIOUS`, so the moment `SERVER_PEPPER` changes every stored lookup hash (list in the bullet above) stops matching. Nothing is re-hashed in the
  background, and for several of them the plaintext is gone (phone numbers, OTPs, recovery codes are stored only as hashes), so they **cannot** be re-derived: the person must re-verify or be re-issued.
* **Identifiers that are derived from the pepper change too.** The webhook `tenantId` (`ten_...`, sent in every v2 envelope) is `HMAC(pepper, "tenant-id" || business id)`, and the CSRF token derivation uses
  the pepper. After a rotation every tenant id changes (receivers that stored the old one to route events break until updated; existing deliveries in flight carry the old value), and every open dashboard
  form and session CSRF token is invalid until the page is reloaded. Wallet pass authentication tokens (`HMAC(pepper, id || salt)`) change, so installed passes stop updating until re-downloaded.
* **Rotation therefore does not contain a leak retroactively.** A copy of the database plus the old pepper still lets the holder test guesses against every hash that existed before the rotation; rotating
  only protects hashes created afterwards. Treat pepper exposure as "assume the old hashes are guessable" and handle the affected populations (phone-number space, e-mail addresses) accordingly.
* **A rotation is an availability event, not a routine control.** Run it only for a suspected pepper exposure together with a database copy, in a maintenance window, with the support and business
  communication prepared, and with the re-verification and tenant-id change announced to integrators in advance.
* **Open work (not scheduled):** migrate lookup hashes to `versionedHex` with multi-pepper lookup and lazy re-hash on use, and derive `tenantId` and CSRF from a separate, independently rotatable key. Until
  then this stays a recorded residual risk (RISK-REGISTER R-043, SECURITY.md 2.80 item 1).

## 4. Audit chain key (`AUDIT_CHAIN_KEY`)

Events written under epoch N record N inside the MAC (chain version 3); epoch 1 keeps the version-2 form. `verifyChain` requires epochs never to decrease along the chain, so an attacker
who holds a later key cannot re-label history as an older epoch, and a head exported before the rotation still verifies with the epoch-1 key.

1. Choose `N = current epoch + 1`. Set `AUDIT_CHAIN_KEY=<new>`, `AUDIT_CHAIN_KEY_EPOCH=N` and `AUDIT_CHAIN_KEYS_PREVIOUS="1:<k1>,...,N-1:<k(N-1)>"` (all earlier epochs: the server refuses to start with a gap).
2. After the restart: `ViadereServer audit-verify` must report the whole chain valid; then `ViadereServer audit-export --force` writes a head under the new epoch.
3. **Never delete an old epoch key** while events written under it exist. The retention job can purge them (after the head export), after which the old key may be retired by removing it from the list once `audit-verify` still passes.
4. After a *compromise* of an epoch key: events written under it are trusted only if they match a head exported to write-once storage before the compromise window; rotate to a new epoch at once.

## 5. Connect link signing key (`CONNECT_LINK_SIGNING_KEY`)

Links carry `keyId` inside the signed context. The id only selects the key; the signature (which covers the id) decides, so a link re-labelled with another id fails. Rotate by setting a new key and id and
listing the old one in `CONNECT_LINK_SIGNING_KEYS_PREVIOUS`; links issued before keep working until their own expiry (campaign links usually carry one), then drop the previous key. A link issued before key ids existed has no id and is verified with the key
whose id is `c1`; keep the very first key as `c1` in the previous list until printed material using it is retired.

## 6. Verification checklist

* `ViadereServer verify-data-key --require-current` exits 0.
* `ViadereServer audit-verify` reports the chain valid and `audit-export --force` writes a head naming the new epoch.
* A connect link from before the rotation still resolves; a new one names the new key id.
* The old values are removed from Fly secrets **and** from escrow only after the retention period of backups that contain data sealed under them (Neon PITR window plus snapshots, RESILIENCE.md): restoring such a backup needs the old key.
