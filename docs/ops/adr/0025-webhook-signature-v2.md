# ADR-0025: Webhook signature v2 (method, path, host, timestamp, body digest, event id, tenant, key id)

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02): per-MAC key binding and field charsets (S1-A3-07), dedup horizon from first receipt (S1-A2-11, S1-A3-18), `auth.*` v2-only from M0 (S1-A2-11)
- **Spec reference:** §6.3, §19 (`/v1/webhooks/test`), §26 (stolen webhook secret, crash during callback); fixes F-04 and F-22
- **Related:** SECURITY §2.6 (v1 signature), §2.56 (opaque v2 envelope), §2.73 (endpoint ownership); ADR-0020, ADR-0030
- **Review:** A3 (MAC construction), A8 (SDK migration), A2

## Context

v1 is `HMAC-SHA256(secret, "{t}." + body)` (`Packages/ViadereCore/Sources/ViadereCore/Security/WebhookSignature.swift`, verified). It does not bind method, path, event id or tenant; event id and tenant travel as unsigned headers (inside the signed body only for the v2 envelope). Receiver dedup ships in memory only (F-22). The spec requires signing over method, path, timestamp, body digest, event id and tenant, a short freshness window, persisted event ids and idempotent at-least-once delivery.

## Decision

### 1. Signature scheme `v2` (HMAC-SHA256, per-subscription secret)

Headers on every v2 delivery:

| Header | Value |
|---|---|
| `Viadere-Signature` | `t=<unix seconds>,v2=<kid>:<base64url HMAC>[,v2=<kid>:<base64url HMAC>…][,v1=<hex>]` — exactly one `t=`; each MAC is bound to its key id in the entry itself, so during rotation each `v2=` entry verifies with its own secret; a duplicate `kid` is malformed (S1-A3-07) |
| `Viadere-Event-Id` | the event id `evt_…` (stable across retries; in v1 this header carried the delivery id, SECURITY §2.6) |
| `Viadere-Delivery-Id` | delivery series id (existing) |
| `Viadere-Tenant` | tenant id (the business id as known to the business) |
| `Content-Digest` | `sha-256=:<base64 of SHA-256(body)>:` (RFC 9530) |
| `Viadere-Webhook-Version` | envelope version (existing) |

String to sign (UTF-8, LF-separated, no trailing LF):

```
VIADERE-WEBHOOK-V2
{METHOD}                          always POST
{host}                            lowercase host of the registered endpoint URL (port only if non-default)
{path?query}                      exactly as in the registered endpoint URL
{t}
{event id}
{tenant id}
{kid}
{lowercase hex SHA-256 of the exact body bytes}
```

`v2 = base64url(HMAC-SHA256(key = UTF-8(secret), message))`, 43 characters. `kid = whk_<subscription prefix>_v<secret version>` (existing key-id form), charset `[a-z0-9_]{1,64}`; the `{kid}` line of the string to sign is the `kid` of the entry being verified.

**Field charsets (no LF possible in any field; the verifier refuses inputs outside them):** method token `[A-Z]{1,16}`; host = lowercase A-label host with optional `:port` (port only if non-default); `path?query` = RFC 3986 `pchar`, `/`, `?` and `%HH` only; `t` = decimal, 1-12 digits; event id `evt_[A-Za-z0-9_-]{1,64}`; tenant id `[A-Za-z0-9_-]{1,64}`; `kid` as above; digest = 64 lowercase hex. Receivers compute the body digest from the bytes they received and only **compare** it with `Content-Digest`; they never copy the header into the string to sign. Vectors cover rotation (two entries), a non-default port and a query string.

Why HMAC and not an asymmetric signature: receivers already hold per-subscription secrets; non-repudiation is not needed because webhooks never carry authentication results (§5); an asymmetric webhook key would be another api-held signing key (F-01 direction). An asymmetric `v2a` (ES256, JWKS-published) remains possible later through a new ADR.

### 2. Receiver rules (SDK and documentation)

1. Recompute the string from the request as received and the endpoint URL **the receiver registered** (not from proxy-rewritten values), once per `v2=<kid>:<mac>` entry whose `kid` the receiver holds, and compare in constant time.
2. `|now − t| ≤ 300 s`.
3. `Viadere-Tenant` must equal the receiver's own tenant id; `Content-Digest` must match the body.
4. Persist `event id` with an atomic insert (unique constraint) for **the retry horizon plus 300 s, measured from first receipt**: today's schedule (`WebhookService.swift`: 8 attempts, 30 s … 24 h) spans about 43 h, so the documented minimum is **72 h**. The horizon is a constant derived in Core from the same backoff table the sender uses (`WebhookRetrySchedule.maxHorizon + 300 s`), and a Core test fails if the table changes without the constant (S1-A2-11, S1-A3-18). The SDKs ship a `WebhookReplayStore` protocol/interface with an in-memory implementation for tests and documented SQL for PostgreSQL/MySQL (fixes F-22). A repeated event id is acknowledged `200` without reprocessing.
5. Unknown schemes are ignored; a v2 verifier never accepts `v1=` alone.

### 3. Migration from v1

| Phase | Behavior |
|---|---|
| M0 (Stage 2 release) | Core implements v2 signing and verification with vectors (`docs/protocol/vectors/webhook-v2.json`); SDKs gain `verifyV2`. Subscriptions gain `signature_version` (`v1` default for existing rows). **`auth.*` and new `approve.*` event types are v2-only from M0** and never carry a `v1=` entry, including during M1 dual signing (they did not exist before v2) (S1-A2-11). |
| M1 | New subscriptions default to `v2`. Existing subscriptions can switch in the console or by `PATCH /v1/business/webhooks/{id} {signature_version: "v2"}` (idempotency required). While switching, deliveries carry both `v1=` and `v2=` in `Viadere-Signature` for 30 days so receivers can deploy the new verifier first. |
| M2 | Existing `approve.*` event types also become deliverable **only** to v2 subscriptions (`422 signature_version_required` on subscribe). |
| M3 (v1 sunset) | 180 days after M1: v1-only subscriptions are paused with a console notice; sunset date announced with `Deprecation`/`Sunset` headers on the subscription API (RFC 9745, RFC 8594). |

`docs/SECURITY.md` §2.6 gains the v2 format as normative text in the Stage 2 change (Core and SDK in the same change, CLAUDE.md rule).

### 4. Test endpoint

`POST /v1/business/webhooks/test {webhook_id, type}` (test keys only) sends a signed sample event of any `auth.*` type with fixed sample ids, so partners can validate signature, tenant, digest and dedup handling (spec §6.1, §19).

### 5. What webhooks never contain

Opaque v2 envelopes only (SECURITY §2.56 pattern): ids, type, version, tenant, occurred_at, `result_ref`/delivery id. Never a magic link, code, TOTP seed, JWS, grant, subject reference or personal data. Results are fetched and verified: push MFA → the device JWS (business verifies against its enrolled key); link service → the authority grant (verified against the static grant JWKS). **A stolen webhook secret therefore cannot create a grant or impersonate the issuer** (spec §26): the worst case is a forged "something happened" signal that leads the business to fetch and verify a result that does not verify.

Tests: ST-WH-06 (an event re-delivered at the final retry offset is deduplicated), ST-WH-07 (two `v2=` entries with different `kid`s each verify with their own secret; duplicate `kid`, two `t=`, LF in any field → malformed).

## Consequences

- Receivers behind proxies that rewrite paths must verify against their registered URL; documentation covers it.
- Dual signing during migration doubles MAC cost only (negligible).
- Durable dedup is now the receiver's responsibility with a provided interface.

## Threat assumptions changed

- Cross-endpoint and cross-tenant replay of a captured delivery (same secret reused by a business for two endpoints) is now detected (path, host, tenant bound).
- Webhook secret theft is explicitly non-escalating to authentication.

## Reviewers required

A3 (construction, encoding), A8 (SDKs and migration), A2 (replay window and dedup).
