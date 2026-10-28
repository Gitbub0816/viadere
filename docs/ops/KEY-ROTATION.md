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
2. `fly secrets set` the new value, the new id, and the old value into the matching `*_PREVIOUS` list **in one command** (machines restart one by one; during the roll both versions run, and both can read each other's data because every instance has the old key in its previous list **after** the first restart - set the previous list first when you cannot restart all at once: step 2a `*_PREVIOUS`, step 2b the new key).
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

The pepper keys two kinds of hash. **Versioned** hashes (`<pepper id>:<hex>`, `Hasher256.versionedHex` / `verifyVersioned`: contract acceptance address/agent, API-key last-used address) survive a
rotation while the old pepper is in `SERVER_PEPPERS_PREVIOUS`. The **original lookup** hashes (`hmacHex`: phone-number hashes, dashboard e-mail hashes, recovery hashes, OTP hashes, pairwise
references) are single-valued indexes: after a rotation they no longer match, so a rotation of `SERVER_PEPPER` must be planned with the matching re-issue steps: phone links re-verify, dashboard
users sign in again with their e-mail (the hash is re-derived on the next successful sign-in), recovery codes are re-issued, SMS contexts reset. Treat a pepper rotation as a **planned
maintenance event** with user-visible re-verification, not a background job, and prefer rotating only after a suspected exposure. `SUBJECT_REF_KEY` has its own re-derivation (clear
`relationships.subject_ref`; the job re-derives; businesses re-fetch references).

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
