# Viadere Security

Security is the top priority. This document has two parts:
1. A STRIDE threat model for each component.
2. The **normative wire formats**. The server (Vapor) and the app (ViadereKit) must implement them byte-for-byte. ViadereCore is the reference implementation.

## 1. Threat model (STRIDE)

| Component | Threat | Mitigation |
|---|---|---|
| **Business identity / registry** | S: impersonating a merchant with a look-alike handle or code | Handles are ASCII-only. Reserved words and reserved-word confusables are blocked. The server rejects any new handle whose `confusableSkeleton` matches an existing one. Codes are unique on `canonical` (I→1, O→0) and never reassigned. Only `verified` businesses appear in discovery or routing, and verification is re-checked when routing starts. |
| | T: altered QR or link | `ConnectLink` parsing is strict: https only, exact hosts, no userinfo, port, fragment or extra query. The context is HMAC-bound to the code. |
| | E: buying priority | `Interaction.effectivePriority` clamps it: marketing and rewards are at most normal, and only `security` may be urgent. |
| **Consumer app / devices** | S: stolen bearer token | Every sensitive route is `deviceSignedBearer`: it needs the bearer token **and** a Secure Enclave signature. Devices can be revoked. |
| | T: modified request | `VIADERE-SIG-V1` covers the method, path and query, timestamp, nonce, and body hash. |
| | R: "I never approved that" | Decisions are device-signed canonical JSON that includes the challenge, and the signed decision is returned to the business. Audit events are append-only. |
| | E: weak approval for a high-risk action | `AssurancePolicy` requires a biometric-gated key (`approvalBiometric`, `.biometryCurrentSet`) for high and critical authorize or authenticate. A passkey or passcode is not enough. |
| **Approvals (MFA / authorize)** | Replay or staleness | Each interaction has a single-use `ChallengeNonce`, consumed through `ReplayGuard` (`decision:{interactionId}`). Also enforced: `expiresAt` (≤ 15 min for security kinds), `signedAt` age ≤ 300 s, and future skew ≤ 60 s. |
| | Phishing via SMS YES/NO | Never allowed. Security kinds cannot be satisfied over SMS, RCS or AMB, and `ChannelRenderer` renders a secure handoff with no transaction details. Copy states that Viadere never asks for approval by text. |
| | I: lock-screen disclosure | Notification content is single-lined, length-capped and spoof-stripped. The app decides whether to show previews. |
| **SMS gateway** | S: sender ID is not identity | The phone number is treated as a routing identifier only. Linking requires passkey sign-in plus explicit confirmation of the phone. Unlinked numbers cannot route. |
| | T: stale or duplicate provider webhooks | Provider signatures are verified. The server dedups by provider message id, and the engine is also idempotent (`recentProviderMessageIds`). Menus are versioned, expire, and are checked against `receivedAt` versus `issuedAt`. The context is persisted with CAS on `revision`. |
| | I: cross-tenant leakage | Each business has its own `SessionID`. `deliverBusinessMessage` renders only the active session (business id **and** session id must match); everything else is held. A switch never forwards to the previous business. |
| | D: spam or floods | Per-phone and per-business rate limits (server). Dedup memory is capped. |
| | Carrier compliance | STOP-family keywords and HELP/INFO work in every state and cannot be escaped. START, UNSTOP and YES opt back in only from `OPTED_OUT`. Opted-out numbers receive nothing except HELP replies and START handling. |
| **Account-link and handoff tokens** | Replay, guessing, open redirect | 256-bit tokens. Only `SHA-256` is stored. Tokens are single-use, have a short TTL (15 min link, 10 min handoff), and are bound to phone + conversation. Fixed paths `/l/{token}` and `/h/{token}`, with no redirect parameters. |
| **Business API** | S/E: tenant crossover | API key → businessId. Every query is tenant-scoped. Idempotency keys are required on POSTs. |
| **Webhooks** | S/T: forged or modified events | `Viadere-Signature: t=…,v1=HMAC`, 300 s tolerance, constant-time compare, multi-secret rotation. |
| **RCS channel** | S/T: forged or replayed provider events | `X-RCS-Signature: t=…,v1=HMAC-SHA256("{t}." + body)`, 300 s window, constant-time compare; one `403` for every failure; provider event ids de-duplicated (§2.11). |
| | E: approving a sensitive request by tapping a suggestion | Suggestion taps are *unauthenticated replies*: `AssurancePolicy` never lets them satisfy `authenticate`, `authorize`, unknown kinds or `high`/`critical`, and deny/report are refused on a channel. Sensitive interactions are rendered as a secure handoff link, never as chips. |
| | S/R: forged, replayed, forwarded or stale postbacks | Postback data is an opaque, MAC-signed, single-use token (never an id); bound to the phone it was sent to; valid only while its menu version is the phone's active one and within the menu TTL (the SMS rules); consumed by compare-and-swap together with the decision. |
| | Silent downgrade | The same interaction falls back to SMS when the phone is not RCS-capable or the provider fails; a sensitive one becomes a handoff link on both channels. |
| **Apple Messages for Business** | Unapproved multi-merchant brokerage | The adapter is an inert placeholder behind a flag that defaults off: it never sends, never reports capability and rejects every inbound webhook. |
| **Business dashboard** | S: credential phishing, password reuse | Passkeys only (user verification required); separate credential store and RP-scoped origin; no passwords to steal. |
| | S/E: cookie theft or fixation, cross-site requests | `__Host-` cookie (Secure, HttpOnly, SameSite=Strict, no Domain), only the SHA-256 stored, a new session on every sign-in, idle + absolute timeouts, per-session CSRF token and Origin check on every state change (§2.12). |
| | E: a stolen session minting credentials | Passkey re-authentication (≤ 5 min old) for creating API keys or webhooks, rotating secrets, adding an owner and every operator mutation. |
| | E: role abuse and tenant crossover | Least-privilege roles checked server-side on every request against the *current* membership; every query scoped to the session's organization; admins cannot touch owners; the last owner cannot leave. |
| | I: leaking customer data to the business | Analytics and consent views are aggregates; webhook payloads are redacted in the delivery log; business views carry per-business pseudonyms. |
| | Script injection, exfiltration | CSP `default-src 'none'` with hash-pinned stylesheet (and one hash-pinned script on sign-in pages only), no inline event handlers or styles, no third-party assets, `frame-ancestors 'none'`; all output HTML-escaped. |
| **Operator console** | E: insider abuse | Separate realm and passkeys, shorter timeouts, re-authentication for every mutation, every action audited with actor kind `operator`; overrides can only restrict (throttle, suspend, downward priority ceiling) and never read the billing tier. |
| **Abuse by a business** | Spam, “I don't recognize this”, pestering | Per-business complaint and opt-out rates with automatic throttling; suspension takes effect on the next request and cancels pending interactions; operators review before any handle or code is issued. |
| **Embeddable button** | Third-party script risk | Immutable versioned files with SRI, no network access, cookies, storage or iframes; it can only link to `https://viadere.com/c/{CODE}`; the label is set as text, never markup. |
| **Server data** | I: database leak | Tokens and API keys are stored hashed. Phones are masked in logs. Audit `metadata` must be redacted. No message bodies in telemetry. |
| | D: unbounded input | Max lengths on every field (`InteractionValidation.Limits`). Payloads are capped (decision ≤ 8 KiB). |

**Residual risks:**
- Malware on a device that is unlocked and biometric-enrolled can still approve.
- Delegation can never approve authenticate or authorize.
- Account recovery is out of scope for v1.

## 2. Normative wire formats

### 2.1 Common encodings
- **base64url**: RFC 4648 §5 alphabet with **no padding**. Decoders reject `+` and `/`.
- **hex**: lowercase on output. Input is case-insensitive.
- **Dates (JSON)**: `YYYY-MM-DDTHH:MM:SS.sssZ` (UTC, exactly 3 fractional digits). Parsers accept any fractional precision (truncated to ms) and `±HH:MM` offsets.
- **IDs**: lowercase canonical UUID strings.
- **Money**: `{"value":"285.28","currency":"USD"}`. The value is a decimal string with the currency's minor units, never a float.
- **ECDSA signatures**: P-256 / SHA-256, encoded as **raw `r‖s` (64 bytes)**, then base64url (86 chars). DER is rejected.
- **Public keys**: base64url of X9.63 uncompressed (65 bytes, `0x04‖x‖y`). Parsers also accept raw 64-byte `x‖y`.

### 2.2 Canonical JSON (used for signed decisions and link context)
- UTF-8, no whitespace.
- Object keys sorted by UTF-16 code units (equivalent to byte order for the ASCII keys we use).
- String escapes:
  - `"` → `\"` and `\` → `\\`
  - `\b`, `\t`, `\n`, `\f`, `\r`
  - other U+0000–U+001F → `\u00xx` (lowercase hex)
  - everything else is literal, including `/` and non-ASCII
- Integers in shortest form. **No floating point.** Absent optionals are omitted, never written as `null`.

### 2.3 Device request signing (`VIADERE-SIG-V1`)
Headers:

| Header | Value |
|---|---|
| `Viadere-Device` | device id (lowercase UUID) |
| `Viadere-Timestamp` | unix seconds, decimal |
| `Viadere-Nonce` | base64url, 16–64 chars (clients send 16 random bytes → 22 chars) |
| `Viadere-Signature` | base64url(raw r‖s) |

String to sign (LF-separated, no trailing LF):
```
VIADERE-SIG-V1
{METHOD uppercase}
{path?query exactly as on the request line, e.g. /v1/interactions?limit=20}
{timestamp}
{nonce}
{lowercase hex SHA-256 of the exact body bytes; empty body → e3b0c442…b855}
```
The signature is ECDSA P-256/SHA-256 over the UTF-8 bytes, made with the device's `request` key.

The server verifies the following and rejects the request otherwise:
1. The nonce is well-formed.
2. `|now − timestamp| ≤ 300 s`.
3. The signature verifies against the registered, non-revoked device key.
4. The nonce is fresh in `ReplayGuard` scope `req:{deviceId}` (TTL 600 s).
5. For `deviceSignedBearer`, the device belongs to the bearer's consumer.

### 2.4 Signed decisions (`VIADERE-DECISION-V1`)
`DecisionPayload` canonical JSON members (optionals omitted):
`assurance` (`none|devicePasscode|biometric`), `businessId`, `challenge`, `decision` (`approve|deny|confirm|decline|select|reply|acknowledge|report`), `deviceId`, `interactionId`, `reply`?, `selectedOptionIds`?, `signedAt`, `v` (=1).

- Signed bytes: `"VIADERE-DECISION-V1\n"` followed by the canonical JSON.
- Key used: the device key with purpose `DeviceKeyPurpose.required(for: assurance)`:
  - `none` → `request`
  - `devicePasscode` → `approvalUserPresence`
  - `biometric` → `approvalBiometric`
- Wire format: `{"payload":"<base64url canonical JSON>","signature":"<base64url raw r‖s>"}`, sent in `DecideInteractionRequest.signedDecision`.

The server re-encodes the decoded payload and rejects it unless the bytes are identical. Then it checks all of the following:
- The interaction id, business id and device id match.
- The challenge matches, compared in constant time.
- The interaction has not expired.
- `signedAt` is no more than 60 s in the future and no more than 300 s old.
- The decision is allowed for the kind.
- `AssurancePolicy.canSatisfy`.
- `choose` selections are valid.
- The challenge is consumed once (`decision:{interactionId}`).

### 2.5 Device enrollment proof
Each key in `DeviceEnrollRequest.keys` carries `proof` = base64url(raw r‖s), signed by that key over:
```
VIADERE-ENROLL-V1\n{consumerId}\n{challenge}\n{purpose}\n{base64url X9.63 public key}
```
`challenge` comes from `POST /v1/devices/enroll/begin`. It is single-use and short-lived.

### 2.6 Webhooks (Viadere → business)
```
Viadere-Signature: t={unix seconds},v1={hex HMAC-SHA256(key = UTF-8(secret), message = "{t}." + raw body)}
Viadere-Event-Id: {delivery id}
Viadere-Event-Type: {type}
```
- Secrets are `whsec_` + base64url(32 bytes).
- During rotation the header carries several `v1=` entries, and a match on any of them is accepted.
- Unknown schemes such as `v0=` are ignored.
- Receivers reject the event when `|now − t| > 300 s`, and must compare in constant time.
- Body: `WebhookEvent` (`id`, `type`, `createdAt`, `businessId`, `apiVersion`, `data`).

### 2.7 Connect links
- Form: `https://viadere.com/c/{CANONICAL_CODE}[?ctx={base64url canonical JSON}&sig={base64url HMAC}]`.
- `ctx` keys: `iat` (required), `cmp`, `act`, `exp` (all strings, dates in ISO form).
- Signature: `sig = HMAC-SHA256(serverKey, "VIADERE-CTX-V1\n{CODE}\n{ctx}")` (43 chars).
- `ctx` and `sig` must both be present or both absent.
- `ctx` is at most 512 chars, and no other query parameters are allowed.
- An expired or invalid context is ignored. The plain code still resolves.

### 2.8 Tokens
- `SecureToken.generate()` returns base64url(32 CSPRNG bytes), 43 chars.
- Stored value: `SecureToken.hash` = lowercase hex SHA-256 of the token's UTF-8 bytes.
- Comparison: constant time (`SecureToken.matches`).
- Account-link URL: `https://viadere.com/l/{token}`, 15 min, single use, bound to phone + conversation revision. Redeemed via `POST /v1/sms/link-tokens/redeem` after passkey sign-in, with the last 4 digits of the phone confirmed.
- Secure handoff URL: `https://viadere.com/h/{token}`, 10 min, single use.

### 2.9 Business codes and handles
- **Codes:**
  - Normalization: trim ASCII whitespace, strip `space - . _ / tab`, uppercase, map `I→1` and `O→0`, then require exactly 6 of `[0-9A-Z]`. `L` stays distinct.
  - Display form: `AF-2345`.
  - Issuance alphabet: `0-9` plus `A-Z` without `I`, `L`, `O`, generated with a CSPRNG. The server retries on collision of `canonical`.
- **Handles:**
  - ASCII only, lowercase, `[a-z0-9_]{3,30}`, starting with a letter, no trailing `_` and no `__`.
  - Registration additionally rejects reserved words, anything containing `viadere`, and confusables of reserved words. The skeleton maps `0→o`, `1/i/|→l`, `5→s`, `3→e`, `8→b`, `rn→m`, `vv→w`, `cl→d` and drops `_`.

### 2.10 SMS keywords
Matching is on the whole message after trimming, removing trailing `.`/`!`, and uppercasing:

| Keywords | Behavior |
|---|---|
| `STOP STOPALL UNSUBSCRIBE CANCEL END QUIT OPTOUT REVOKE` | Opt out in every state. Cannot be escaped (`\STOP` still opts out). |
| `HELP INFO` | Help text in every state, including OPTED_OUT (no re-subscribe). Cannot be escaped. |
| `START UNSTOP YES` | Opt back in, only from `OPTED_OUT`. Otherwise ordinary content. |
| `MENU`, `BACK` | Gateway controls. Send `\MENU` or `\BACK` to pass the word to the connected business. |

### 2.11 RCS provider webhooks and postback tokens

Inbound (provider → Viadere), `POST /v1/providers/rcs/inbound`:
```
X-RCS-Signature: t={unix seconds},v1={hex HMAC-SHA256(key = UTF-8(secret), message = "{t}." + raw body)}
```
The secret is `RCS_WEBHOOK_SECRET` (base64url, ≥ 32 bytes; the HMAC key is the UTF-8 of its base64url text). Verification, tolerance (300 s) and constant-time
comparison are exactly §2.6. Unconfigured, unsigned, badly signed and stale deliveries are the same `403`. Events: free text, `suggestionResponse.postbackData`,
and `DELIVERED` / `READ` / `FAILED` receipts. Provider message ids are de-duplicated.

Postback token (Viadere → provider → Viadere), carried as `postbackData`:
```
vrp1.{base64url(32 CSPRNG bytes)}.{first 32 hex of HMAC-SHA256(serverPepper, "rcs-postback\n" + random part)}
```
* Opaque: it contains no interaction id, option id or decision; the server keeps `(interaction, target, phone, menu version, expiry)` keyed by the SHA-256 of the whole token.
* Structure and MAC are checked before any lookup; comparison is constant time.
* Single use: consuming it is a compare-and-swap in the same transaction that records the decision.
* Bound to the phone it was sent to, to the phone's **active menu version** (a newer menu supersedes older ones) and to the menu TTL.
* Authenticates nothing about the person: a reply on RCS is `ProvidedAssurance.unauthenticatedReply`.

### 2.12 Dashboard sessions and CSRF

* Session cookie: `__Host-vd_session` (operators `__Host-vd_operator`) = `vds_` + base64url(32 CSPRNG bytes); `Secure; HttpOnly; SameSite=Strict; Path=/`, no `Domain`. Stored: SHA-256 only.
* Created on every successful passkey assertion (a presented old session is revoked). Idle timeout 30 min / absolute 12 h (operators 15 min / 8 h). `reauthAt` is set at sign-in and by a re-authentication ceremony.
* CSRF token: first 43 hex characters of `HMAC-SHA256(serverPepper, "dashboard-csrf\n" + cookie value)`, sent as hidden field `_csrf` or header `X-CSRF-Token` on every non-`GET`; constant-time compare. A request with an `Origin` header must carry one of the configured origins.
* Passkey ceremonies use the dashboard's own credential table and a single-use ceremony row (5 min); registration and assertion require user verification.

