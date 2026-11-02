# Key rotation (ops gap G-8)

**Status:** v2, 2026-11-02 (Azure; authority keys added in sections 7 to 11). Tooling: `Server/Sources/ViadereServerKit/Operations/KeyRotation.swift`; tests: `WP6RotationTests`. All four server secrets can be rotated without
downtime. Rotation is a routine operation (do it on a schedule and after any suspected exposure), not an incident-only tool. A KMS envelope (ADR-03) will make the data key
routine too; until then these procedures apply. Back up every old key until the step that says it may be removed.

| Secret | Env | Id / epoch | Previous values | Rotation effect |
|---|---|---|---|---|
| Field encryption | `DATA_ENCRYPTION_KEY` | `DATA_ENCRYPTION_KEY_ID` (1-16 chars of letters, digits, dash; default `k1`) | `DATA_ENCRYPTION_KEYS_PREVIOUS="k1:<base64url>,k2:<base64url>"` | New writes use the current key; old values still open until re-encrypted |
| Pepper | `SERVER_PEPPER` | `SERVER_PEPPER_ID` (default `p1`) | `SERVER_PEPPERS_PREVIOUS="p1:<base64url>"` | Versioned hashes keep verifying; see section 3 for the older lookup hashes |
| Audit chain | `AUDIT_CHAIN_KEY` | `AUDIT_CHAIN_KEY_EPOCH` (integer, default 1) | `AUDIT_CHAIN_KEYS_PREVIOUS="1:<base64url>,2:<base64url>"` (every earlier epoch) | New events MAC under the new epoch; the chain verifies end to end |
| Connect links | `CONNECT_LINK_SIGNING_KEY` | `CONNECT_LINK_SIGNING_KEY_ID` (default `c1`) | `CONNECT_LINK_SIGNING_KEYS_PREVIOUS="c1:<base64url>"` | New links name the new key; issued links verify until they expire |

Generate a key: `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`. Previous keys are **secrets** (Key Vault `kv-vdr-<env>`, set with `Infra/azure/kv_tool.py put`, names in `Infra/azure/variables.tf` `app_secret_env`); the ids are plain `app_env` values. The server refuses to start
if a previous list repeats the current id, an id is malformed, a previous key is shorter than 32 bytes, or the audit epochs are not contiguous.

## 1. Order of operations (all four)

1. Note the PostgreSQL restore point (Flexible Server PITR, RESILIENCE.md) and generate the new key (`Infra/azure/generate_secrets.py` or the command above). Store old and new in escrow.
2. Set the old value in the matching `*_PREVIOUS` secret **and** the new value plus its id (`app_env`) in **one** change, then create ONE new revision (`az containerapp update --revision-suffix ...`). Replicas restart one by one; during the roll an instance that has not restarted yet can still read everything the new instances wrote only if it knows the new key, so for the data key do the roll in two steps when you cannot tolerate a few read errors: first add only `DATA_ENCRYPTION_KEYS_PREVIOUS="k1:<old>,k2:<new>"` (everyone can read both), then switch the current key.
3. Run the re-encryption or verification step of the section below.
4. Only after verification, remove the old key from `*_PREVIOUS` and restart.

## 2. Data encryption key (`DATA_ENCRYPTION_KEY`)

Ciphertexts name their key: `v2.` (row-bound, legacy id `k1`), `v3.<id>.` (row-bound with a key id) and the oldest column-bound `v1.`.

```bash
# 1. add the new key; keep the old one as "previous": new Key Vault secret versions (kv_tool.py put), the plain id in app_env
#    (DATA_ENCRYPTION_KEY_ID=k2), `tofu apply` or `az containerapp update`, one new revision.
# 2. re-encrypt every sealed column under the new key (idempotent, batched by primary key, safe while serving, compare-and-swap on
#    the old value so a concurrent writer is never overwritten): a one-off execution of the maintenance job image with arguments
az containerapp job start --name job-viadere-maintenance --resource-group rg-viadere-<env>-app --args rotate-data-key --env production
# 3. prove nothing is left under another key or format
az containerapp job start --name job-viadere-maintenance --resource-group rg-viadere-<env>-app --args verify-data-key --require-current --env production
# 4. remove DATA_ENCRYPTION_KEYS_PREVIOUS; new revision; run verify-data-key again
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
* The old values are removed from Key Vault (disable the old secret versions) **and** from escrow only after the retention period of backups that contain data sealed under them (Flexible Server PITR window, RESILIENCE.md): restoring such a backup needs the old key.

---

# Authority keys (ADR-0028, ADR-0033 section 3, ADR-0034 sections 5, 8 to 10)

**Condition C-6 / ledger L-2:** this part exists before any app release pins `VIADERE_AUTHORITY_DEVICE_KEYS` or the `recovery-seal` keys. Everything below is
done in the authority tier (`kv-vdr-auth-<env>`, `Infra/azure-authority`); nothing of it is ever done with an ordinary identity. Which key is held by whom:
`docs/architecture/TRUST_BOUNDARIES.md` section 4.1. Staging has one human, the owner: every reviewer-gated step below is **a single owner approval** (R-21).
Production needs two reviewers, neither the requester.

## 7. Principles

1. **Explicit versions.** The authority signs with `name/version` pinned by the admin job, never with "latest". A new Key Vault version becomes current at once, so a
   new version is created with `nbf` set to the planned activation time and is not used until the pin changes (`key-version-pin`).
2. **Standby keys are separate objects**, created disabled, with no role for any identity until a recorded rollover (`AUTH-STANDBY-ROLE`): `device-statement-signing-standby`,
   `recovery-seal-kek-standby` (lean) or `recovery-seal-rsa-standby` (JWE construction, standard).
3. **Nothing is exportable.** Only the authority crypto-officer group (PIM, time-bound) holds backup rights (`AUTH-KEY-BACKUP`); a backup is a runbook action with a ticket.
4. **Key operations are evidence.** Key Vault `AuditEvent` goes to the authority workspace; the reconciliation job (C-11) matches every `sign` to a grant or statement record
   and every `unwrap`/`decrypt` to a start or decrypt record. Any unmatched operation pages the owner (section 11).
5. The data action for unwrapping is `Microsoft.KeyVault/vaults/keys/unwrap/action` (checked on Microsoft Learn 2026-11-02; ADR-0028 wrote `unwrapKey/action`).

## 8. Routine rotation of a signing key (`grant-signing`, `oidc-signing-*`, `device-statement-signing`): yearly or on suspicion

1. A crypto officer (PIM activation) creates the new version in `kv-vdr-auth` with `nbf` = planned activation (>= 24 h ahead).
2. Run `authority-admin.yml` with command `key-inventory` (change file names the key and version): the job prints the public JWK; the workflow attests the inventory.
3. Commit the new JWK to `Site/content/id/**` (CODEOWNERS review) and run `authority-publish.yml` with that inventory run id. The new key is published **at least 24 h**
   before activation. For `device-statement-signing` the new public key is instead pinned in the next app release (Core constants, `[active, standby]`), and
   `AUTHORITY_MIN_APP_VERSION` follows (ADR-0033 section 3.5): routine rotation of this family is an app-release cadence, not a server toggle.
4. After 24 h run `authority-admin.yml` with `key-version-pin` (change file: key name, version). The authority checks the RFC 7638 thumbprint against the published list and fails closed
   when it is not there.
5. After another 24 h disable the old version (not delete: verification of old evidence needs it) and remove it from the JWKS in a further `authority-publish` run.
6. Record the run ids in `docs/reviews/IMPLEMENTATION_LEDGER.md`.

**Emergency rollover** (signing key suspected exposed): publish the new key, switch the pin at once, remove the old key from the JWKS, disable the old version. Relying
parties refetch on an unknown `kid`; the maximum exposure is the cache TTL plus the token lifetime (<= 3600 s + 300 s, ADR-0024 section 7.5). For
`device-statement-signing` use the standby: a statement-family revocation list signed only by the standby (ADR-0033 section 3.3), then the rollover grant of section 10.

## 9. Seal keys (`recovery-seal`)

* **Lifetime:** at most **6 months** active (90 days under an owner exception, ADR-0034 section 8.1). The authority alerts 30 days before `not_after` and refuses to open
  envelopes for a key past it. The pinned set is `[current, next]` one app release ahead.
* **Creation (lean HPKE construction):** two **separate** `authority-admin.yml` runs, each from its own change-file commit: `seal-key create --role active`, later
  `seal-key create --role standby`. The change file carries the attested KEK **public** half (read once by the officer group, `GetKey` appears in `AuditEvent` and is
  reconciled); the admin identity holds no Key Vault role (`AUTH-ADMIN-NO-KV`). The job logs only the public JWK, thumbprint, KEK name/version and row id.
* **Production (JWE-RSA construction):** `recovery-seal-rsa` (RSA-HSM 3072, `decrypt` only) and its standby; no KEK, no blob, no unwrap role. Production is blocked until this
  ships with its tests or an owner exception exists (C-16, ledger L-13). Staging may move to it with `seal_construction = "jwe-rsa"` (A3 delta check).
* **Retirement:** destroy a retired seal key (delete the wrapped blob, disable the KEK version) once no supported app version pins it.

## 10. Standby rollover (reviewer-gated)

1. Publish a revocation list naming the active key (`key_family`), signed by the standby (statement family) or by the active statement key (seal family).
2. Add the standby key to `rollover_standby_grants` and a reviewed `rollover_change_file` in `Infra/azure-authority` and run `authority-infra.yml` with apply = true
   (environment `azure-infra-authority-staging`, reviewer approval; the plan passes `policy_check.py` only with a recorded change file).
3. Enable the standby key version (the officer group, PIM), run `key-version-pin`, confirm the app shows the new `kid`.
4. Create a **new** standby for the next cycle (section 9 for seal keys); remove the grant of the retired key; keep it disabled for evidence verification (statements) or destroy it (seal keys).

## 11. Seal key exposed (condition C-15; drill ONCE in staging before any authority flag)

Triggers: suspected authority process or memory compromise; an unmatched `unwrap`/`decrypt` alert; a crash dump or diagnostic capture of the authority found anywhere; a suspected
leak of a wrapped blob together with KEK access. In this order (`ViadereAuthority admin seal-key exposed <kid>`, change file, reviewer approval):

1. Sign a seal-family revocation list naming the exposed active key; grant the authority its role on the standby KEK/RSA key through the section 10 rollover; sealing switches to the standby.
2. In ONE transaction set `state = invalidated` on every `authority_recovery_codes` row whose `seal_kid` is the exposed key (and only those) and flag each account head
   `recovery_set: invalidated`; one audit event per account.
3. The app shows S-REC-05 as a required step on the next head; the account **keeps its grant capability** (a forced refresh is not a downgrade).
4. Destroy the exposed seal key at once (blob deleted, KEK version disabled), without waiting for app releases.
5. A person with no device left and only codes of an invalidated set uses the admin-job support path (ADR-0032 section 3.3 (b)); support wording: S-REC-04.
6. Measure the time of the invalidation transaction on the pilot data set and record it. **Drill record (to fill):** date ____ , actor ____ , rows invalidated ____ , time ____ , reconciliation alert raised ____ .

## 12. Other authority-tier secrets and shared keys

* `OIDC_PAIRWISE_KEY`, `ACCOUNT_REF_KEY`, `RECOVERY_VERIFIER_KEY`: secrets of `kv-vdr-auth` only; the api never holds them. Rotation of `ACCOUNT_REF_KEY` or `OIDC_PAIRWISE_KEY` changes every
  derived identifier (pairwise `sub`, `account_ref`): treat as a migration with its own ADR, not a routine rotation. `RECOVERY_VERIFIER_KEY` rotation invalidates all recovery sets (same effect as section 11 step 2).
* `SUBJECT_REF_KEY` exists in two copies (api and authority, ADR-0028 section 3). Rotate both in one coordinated change, record it here, and re-derive `relationships.subject_ref` (section 3).
* The ordinary tier's pull credential (`ghcr-pull-credential`, dedicated, read:packages on the Viadere packages only; replaces the owner's PAT, decision 14) is rotated at least every
  90 days and on any suspicion: create the new credential, `kv_tool.py put` it into `kv-vdr-<env>`, create a new revision, revoke the old one. The authority never pulls from GHCR.
* Cloudflare tokens: the site token and the `id.` host token (authority-publish) are separate; rotate each in its GitHub environment.
