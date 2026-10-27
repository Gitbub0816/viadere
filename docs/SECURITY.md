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
| **Consumer app / devices** | S: stolen bearer token | Every sensitive route is `deviceSignedBearer`: it needs the bearer token **and** a Secure Enclave signature. Devices can be revoked. A session (token family) is **bound to the device it enrolled**: its bearer token is refused with any other device's key. |
| | E: a stolen bearer or refresh token enrolls a new device whose key approves payments (or re-enrollment after a thief re-registers biometrics) | A bearer token alone never creates a device. `POST /v1/devices` needs a fresh, user-verified **passkey assertion over the enrollment challenge** (§2.5), or the single use of a session a passkey ceremony created less than 5 minutes ago. Revoking a device revokes the sessions bound to it, and refresh-token reuse revokes the family **and** the devices enrolled through it. `hardwareBacked` is a client claim: keys are stored `attested = false` until an App Attest verifier is configured. |
| | E: the new (attacker) device approves high-risk requests at once | New-device **cool-down**: a device enrolled while the account already has a trusted device cannot approve `high`/`critical` requests for 24 h unless another trusted device confirms it with a user-verified signature (§2.17). Other devices get a "new device" push. Deny and report always work. |
| | E: App Clip enrolls a full device that is never cleaned up | `clientKind: appClip` devices get a request key only, live 7 days (session capped to match), and **can never decide** an interaction. |
| | T: modified request | `VIADERE-SIG-V1` covers the method, path and query, timestamp, nonce, and body hash. |
| | R: "I never approved that" | Decisions are device-signed canonical JSON that includes the challenge **and a digest of the context that was shown** (v2, §2.4), and Viadere stores the signed decision. Businesses receive a per-business device pseudonym and the server's attestation, never the raw signed decision (it names the global device id); Viadere exports it for a dispute (`export-dispute`). Audit events are append-only and chained with a keyed MAC (§2.22). |
| | T: the approval screen shows one thing and the device signs another / hostile business text on the screen | A v2 decision carries `contextDigest = SHA-256` of the canonical `{businessId, kind, payload, expiresAt}`; the server recomputes it from the stored interaction and refuses a mismatch (`409 context_mismatch`), and refuses an approve/confirm/select/reply without one (`400 context_digest_required`). The server rejects business text with bidi, zero-width, control or line-separator characters, over-long (graphemes, scalars, UTF-8 bytes) text, and text that starts with or (for names) mentions "Viadere" (§2.19); clients sanitise again before display. |
| | E: weak approval for a high-risk action | `AssurancePolicy` requires a biometric-gated key (`approvalBiometric`, `.biometryCurrentSet`) for high and critical authorize or authenticate. A passkey or passcode is not enough. |
| **Approvals (MFA / authorize)** | Replay or staleness | Each interaction has a single-use `ChallengeNonce`, consumed through `ReplayGuard` (`decision:{interactionId}`). Also enforced: `expiresAt` (≤ 15 min for security kinds), `signedAt` age ≤ 300 s, and future skew ≤ 60 s. |
| | Phishing via SMS YES/NO | Never allowed. Security kinds cannot be satisfied over SMS, RCS or AMB, and `ChannelRenderer` renders a secure handoff with no transaction details. Copy states that Viadere never asks for approval by text. |
| | I: lock-screen disclosure | Notification content is single-lined, length-capped and spoof-stripped. The app decides whether to show previews. |
| **SMS gateway** | S: sender ID is not identity | The phone number is treated as a routing identifier only. Linking requires the signed-in **device** and explicit confirmation of the masked number shown by a read-only preview. Unlinked numbers cannot route. |
| | S/E: account-link fixation (an attacker texts Viadere, then lures the victim into redeeming the attacker's link) | `GET /v1/sms/link-tokens/{token}/preview` (device-signed, rate-limited, does not consume) shows the full masked number; redeem is device-signed, echoes the confirmation, checks the live thread (contextRevision, not opted out), notifies the account's other devices, and the new link is **not an interaction target or RCS/SMS decider for 24 h** unless a trusted device confirms it (§2.8). |
| | E: OTP toll fraud / SMS pumping | Destination-country allowlist (default US, CA; Caribbean +1 regions separate), a platform-wide and a per-prefix verification-SMS budget with alert-level logging, per-consumer/per-phone limits, and an App Attest/DeviceCheck hook (stub until Apple credentials exist). |
| | I/E: one business's text answered by another business | The SMS thread is shared. While it is connected to business B, an interaction SMS from business A is replaced by a content-free notice, so the person's reply is never forwarded to B as an answer to A. Business-originated text is a single line (§2.10), so it cannot forge `Viadere:` lines, menus or other attributions. |
| | T: stale or duplicate provider webhooks | Provider signatures are verified. The server dedups by provider message id, and the engine is also idempotent (`recentProviderMessageIds`). Menus are versioned, expire, and are checked against `receivedAt` versus `issuedAt`. The context is persisted with CAS on `revision`. |
| | I: cross-tenant leakage | Each business has its own `SessionID`. `deliverBusinessMessage` renders only the active session (business id **and** session id must match); everything else is held. A switch never forwards to the previous business. |
| | D: spam or floods | Per-phone and per-business rate limits (server). Dedup memory is capped. The in-memory limiter keys IPv6 clients by /64, sweeps idle buckets on an interval and **fails closed** for new keys when full (§2.23). |
| | T: a digit meant for the previous menu is applied to the new one | A digit within a few seconds of a menu change re-shows the menu instead (SMS has no sender timestamp); RCS uses the provider timestamp. |
| | Carrier compliance | STOP-family keywords and HELP/INFO work in every state and cannot be escaped. START, UNSTOP and YES opt back in only from `OPTED_OUT`. Opted-out numbers receive nothing except HELP replies and START handling. |
| **Account-link and handoff tokens** | Replay, guessing, open redirect | 256-bit tokens. Only `SHA-256` is stored. Tokens are single-use, have a short TTL (15 min link, 10 min handoff), and are bound to phone + conversation. Fixed paths `/l/{token}` and `/h/{token}`, with no redirect parameters. |
| **Business API** | S/E: tenant crossover | API key → businessId. Every query is tenant-scoped. Idempotency keys are required on POSTs. |
| | E: test-mode keys reach real people, bypass quota/abuse/billing | A test key can address only **sandbox** relationships (consumers with status `sandbox`: no passkey, device or phone); a live key cannot address one. Consumer routes only ever show live interactions. Test traffic never pushes, texts or counts. |
| **Webhooks** | S/T: forged or modified events | `Viadere-Signature: t=…,v1=HMAC`, 300 s tolerance, constant-time compare, multi-secret rotation. |
| | S: SSRF through a business-supplied URL, DNS rebinding | https + public host only; the host is resolved **once**, every address is vetted (including IPv4 embedded in IPv4-mapped, NAT64 and 6to4 addresses, CGNAT, TEST-NETs, multicast, reserved) and the connection is pinned to the vetted address (`dnsOverride`) while TLS and `Host` keep the original name; redirects are never followed. |
| | I: message text kept in plaintext in the delivery queue | Delivery bodies are encrypted at rest (AES-GCM, row-bound), delivered and dead deliveries are purged after 30 days, and bodies mentioning a deleted consumer are scrubbed. |
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
| **Rewards and redemption codes (P3)** | S/T: a client claims it is eligible, or reshapes the rules | Eligibility (`eligible`, `notToday`, `limitReached`, `notYetValid`, `insufficientPoints`, `redeemed`, `expired`, `revoked`) is computed **only** on the server from its own clock, the reward's rules in the business's time zone (DST-aware) and its own records. `redeem` re-checks it inside the reservation transaction (§2.13). |
| | R/E: double redemption, or racing past a per-day limit | A code reserves its slot and points when issued: unique `(reward, consumer, window, slot)` decides concurrent attempts, a compare-and-swap debits points, and an unused code's reservation is released when it expires. The business consumes a code with a single compare-and-swap (`issued → consumed`), so exactly one of any number of concurrent validations succeeds. |
| | S: guessing or reusing codes | 50-bit random codes valid ~2 minutes, stored only as a pepper-keyed HMAC, looked up within the calling business only (another business's code is the same `404` as an unknown one), validation rate-limited per business, and never logged or audited in clear. |
| **Wallet passes (P3)** | S/T: a forged or altered pass | The server signs passes (`manifest.json` SHA-1 per Apple's format, detached PKCS#7 with the Pass Type ID certificate and the WWDR intermediate; §2.14). Certificates and keys come from the environment, are validated at startup (parseable, matching key, unexpired) and never committed. |
| | S/E: reading or hijacking a pass's update channel | The PassKit web service needs the per-pass `authenticationToken`, derived as `HMAC(pepper, id ‖ salt)`, stored only as a keyed hash and compared in constant time; wrong token, wrong type and unknown serial are one `401`, and failures are rate-limited. A pass is bound to one consumer and one subject (loyalty account, reward or ticket). |
| | I: personal data in passes | Passes carry only what the person's own card shows (points, offer title, event details). No phone, email, name, member number or redemption code is embedded. |
| **Live Activities (P3)** | Unwanted or promotional activities | Pushes are sent only for `status` interactions whose purpose `LiveActivityPolicy` allows (`transactional`, `accountService`, `support`), never marketing, rewards or security; test-mode keys never reach devices; the start alert is generic. Tokens are per device, bound to a business the person is connected to, and dropped when APNs reports them invalid. |
| **Household / delegation (P3)** | S/E: granting access without the delegate's consent, or guessing a code | A grant exists only after the delegate accepts a single-use, 24-hour, pepper-hashed code in their own app; lookups are rate-limited per consumer and globally, and an invitation locks after 10 attempts (§2.15). |
| | E: a stolen session widening access | Sensitive scopes (security, account service) need a fresh `approvalBiometric` signature bound to the exact scope, device and time; each proof is single-use; such grants last at most 30 days. Sensitivity is recomputed from the purposes, never taken from the client flag. |
| | E: a delegate approving a sign-in or payment | Server-enforced: delegates can never decide `authenticate` or `authorize`; viewers decide nothing; managers may only confirm, decline and choose. Out-of-scope interactions are a plain `404`. Every use, denial, grant, acceptance, revocation and expiry is in the hash-chained audit and the grantor's household feed. |
| **Server data** | I: database leak | Tokens and API keys are stored hashed. Phones are masked in logs. Audit `metadata` must be redacted. No message bodies in telemetry. Personal fields are AES-GCM encrypted with **row-bound** additional data (a ciphertext cannot be moved to another row or column, §2.21). |
| | T: rewriting the audit log with database access | Version 2 events are `HMAC-SHA256(AUDIT_CHAIN_KEY, …)` with the row id hashed; the key is not in the database; legacy unkeyed events are accepted only up to an operator-declared sequence; the chain head is exported to write-once storage (§2.22). |
| | I: personal data survives account deletion | Deletion also erases device names, signed free-text replies (the one permitted edit of the append-only `decisions` table), outbound SMS/channel rows and link tokens by phone, SMS thread state (an opt-out is kept as suppression only), delegation labels, stored outcome replies and webhook bodies; finished outbound rows, link tokens and deliveries are purged on a retention schedule. |
| | S: weak configuration in production | `ENVIRONMENT` is required (`development`, `test`, `staging`, `production`; no silent default). `staging` uses production rules. Any `DATABASE_URL` forbids ephemeral secrets. `RP_ORIGIN` must be an https origin of `RP_ID` outside development. Production secrets must be distinct values. |
| | D: unbounded input | Max lengths on every field (`InteractionValidation.Limits`). Payloads are capped (decision ≤ 8 KiB). |

**Residual risks:**
- Until App Attest is configured, `hardwareBacked` is only a claim and a software key can be enrolled by anyone who completes the passkey assertion; the passkey assertion, the new-device cool-down and the device-bound session are what protect approvals today.
- A passkey that syncs (iCloud Keychain) is only as safe as that account; a thief holding it can enroll a device, but its high/critical approvals wait 24 h and the user's other devices are notified. A user with a single device has nobody to notify.
- The first device of an account has no cool-down (nobody to confirm it).
- The in-memory rate limiter is per instance; multi-instance deployments must supply a shared store.
- DNS pinning for webhooks needs the vetted address to stay valid for the request; an address that is public at resolution and re-pointed afterwards is not an issue, but a malicious *public* endpoint is by definition reachable.
- A database writer who also holds `AUDIT_CHAIN_KEY` can forge the audit chain; only the exported heads in write-once storage detect that. Events before `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` are protected only by the unkeyed legacy hash.
- Erasing a deleted account's decisions keeps the signature and ids but not the signed payload, so a deleted account's old decisions can no longer be re-verified.
- Malware on a device that is unlocked and biometric-enrolled can still approve.
- Delegation can never approve authenticate or authorize (enforced by the server, §2.15).
- Wallet passes are reachable offline once added; voiding takes effect when the device next refreshes the pass.
- A redemption code shown on a screen can be photographed within its 2-minute life.
- Account recovery is out of scope for v1.

## 2. Normative wire formats

### 2.1 Common encodings
- **base64url**: RFC 4648 §5 alphabet with **no padding**. Decoders reject `+` and `/`.
- **hex**: lowercase on output. Input is case-insensitive.
- **Dates (JSON)**: `YYYY-MM-DDTHH:MM:SS.sssZ` (UTC, exactly 3 fractional digits). Parsers accept any fractional precision (truncated to ms) and `±HH:MM` offsets.
- **IDs**: lowercase canonical UUID strings.
- **Money**: `{"value":"285.28","currency":"USD"}`. The value is a decimal string with the currency's minor units, never a float.
- **ECDSA signatures**: P-256 / SHA-256, encoded as **raw `r‖s` (64 bytes)**, then base64url (86 chars). DER is rejected. Signatures are **canonical low-S**: `(r, s)` and `(r, n − s)` are both valid ECDSA signatures, and Secure Enclave output may use either, so encoders and decoders normalise `s` to `s ≤ n/2` (`ViadereSignatureEncoding`). Every verifier therefore accepts both encodings and sees one canonical byte string, and **no replay guard is ever keyed on a signature string**: request signatures use the nonce, decisions the challenge, enrollment the single-use challenge, step-up and confirmation proofs a hash of their signed content.
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
`assurance` (`none|devicePasscode|biometric`), `businessId`, `challenge`, `contextDigest`? (v2 only), `decision` (`approve|deny|confirm|decline|select|reply|acknowledge|report`), `deviceId`, `interactionId`, `reply`?, `selectedOptionIds`?, `signedAt`, `v` (`1` without `contextDigest`, `2` with it; the version is implied by the digest, and the two must agree).

**Context digest (v2).** `contextDigest` = lowercase hex of `SHA-256("VIADERE-CONTEXT-V1\n" ‖ canonicalJSON)` where `canonicalJSON` is the canonical JSON (§2.2) of `{"businessId", "expiresAt", "kind", "payload"}`: `payload` is the interaction payload exactly as on the wire (absent optionals omitted; a non-integer number becomes the string `"n:<shortest decimal>"`), `expiresAt` ISO-8601 UTC with milliseconds, `kind` the kind's raw value. It excludes everything the person never sees or that differs between app and business views (challenge, consumer reference, priority, channels, idempotency key). `Interaction.displayContextDigest()` in ViadereCore is the single definition: the app computes it over the interaction **as it displayed it**, the server recomputes it from the stored interaction. **v2 is required** for `approve`, `confirm`, `select` and `reply` on `authenticate`, `authorize`, `confirm` and `choose` (`400 context_digest_required` otherwise); v1 is still accepted for everything else (deny, report, decline, acknowledge, …). A digest that does not equal the stored interaction's is `409 context_mismatch`.

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
- The context digest is present where required and equals the stored interaction's (above).
- The signing device is an `app` device (App Clip devices can never decide), is not inside its new-device cool-down for a `high`/`critical` approval (deny, report and decline always work), and the interaction is a live (not test) one.
- `choose` selections are valid.
- The challenge is consumed once (`decision:{interactionId}`).

**What a business receives.** The business API and the `interaction.decided` webhook carry `deviceRef` = first 32 hex of `HMAC-SHA256(serverPepper, "device-ref\n" ‖ businessId ‖ "\n" ‖ deviceId)` (stable per business, unlinkable across businesses) and `verification {verified, keyPurpose, contextBound, verifiedAt, evidenceRef}` where `evidenceRef` = first 32 hex of `HMAC-SHA256(serverPepper, "decision-evidence\n" ‖ decisionId)`. The raw `signedDecision` is never sent to a business; the consumer's own `POST …/decision` response still returns it. For a dispute Viadere runs `ViadereServer export-dispute --interaction <id>` (audited `dispute.exported`), which prints the signed payload, signature, global device id and the device's public keys.

### 2.5 Device enrollment
Each key in `DeviceEnrollRequest.keys` carries `proof` = base64url(raw r‖s), signed by that key over:
```
VIADERE-ENROLL-V1\n{consumerId}\n{challenge}\n{purpose}\n{base64url X9.63 public key}
```
`challenge` comes from `POST /v1/devices/enroll/begin`. It is single-use, short-lived (5 min), and good only for the session (token family) that asked for it.

**Passkey-bound enrollment.** A bearer token alone never creates a device.
1. `POST /v1/devices/enroll/begin` (bearer) returns `{challenge, expiresAt, assertion, assertionOptional}`. `assertion` is `PasskeyAssertionOptions` whose `challenge` **equals** `challenge` (the same base64url string; the authenticator signs its bytes), `userVerification: "required"`, `allowCredentialIds` = the account's passkeys, `ceremonyId` = the enrollment challenge row.
2. The app performs the assertion and sends `POST /v1/devices` (bearer) with `{name, platform, challenge, keys, assertion, clientKind?, clipDevice?, appAttest?}`. The server verifies the assertion with WebAuthn (user verification required, RP id, origin, sign count) over `challenge`, with a credential owned by the calling consumer, then consumes the challenge.
3. **Exception.** `assertionOptional == true` when the session was minted by `register/finish` or `login/finish` less than 5 minutes ago, is not revoked and has not enrolled yet; then `assertion` may be omitted, **once**: enrolling binds the session to the device with a compare-and-swap on `device_id IS NULL`. Otherwise a missing or invalid assertion is `401 passkey_assertion_required`.
4. A re-enrollment (for example "Set up again" after the biometric key was invalidated) is an ordinary enrollment: it needs the assertion.

**Session ↔ device binding.** Enrolling records the device on the token family. `deviceSignedBearer` requires the signing device to be the family's device (`403` otherwise); a family not yet bound binds to the first device that signs with it. Revoking a device revokes the families bound to it (`401 signature_invalid "This device has been revoked."` is still what a revoked device is told, so the app wipes its keys); revoking or detecting reuse on a family revokes the devices enrolled through it.

**`clientKind`** (`app` default, or `appClip`; the app may instead send `clipDevice: true`). An `appClip` device registers a **request key only** (`422` otherwise), expires 7 days after enrollment (its session is capped to the same instant; the retention sweep revokes it), appears in `GET /v1/devices` with `clipDevice: true`, and the server refuses every decision from it.

**Attestation.** `appAttest {keyId, attestation}` (App Attest over `SHA-256(challenge)`) is passed to the `DeviceIntegrityVerifier`; the shipped verifier is a stub, so every key is stored `attested = false` (`DeviceKey.attested`). `hardwareBacked` remains the client's claim.

**Cool-down.** A device with approval keys enrolled while another active `app` device exists gets `approvalsLockedUntil = now + 24 h`; the other devices receive a "new device" push; see §2.17 to lift it.

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
- Account-link URL: `https://viadere.com/l/{token}`, 15 min, single use, bound to phone + conversation revision. The app (never the web page) handles it with two **device-signed** calls: `GET /v1/sms/link-tokens/{token}/preview` → `{maskedPhone, expiresAt}` (rate-limited; does not consume; the app shows the whole masked number with "This is my phone" and a warning) and `POST /v1/sms/link-tokens/redeem` with `{token, confirmPhoneLast4, confirmMaskedPhone?}`. Redeem checks the confirmation (a few wrong tries burn the token), that the live SMS thread still exists, has not been reset (`revision ≥` the token's) and has not opted out, consumes the token, links the phone, and notifies the account's other devices.
- **Linked-phone cool-down.** A phone linked from a token (or from an OTP started on a device that is itself cooling down) has `usableFrom`; before it (24 h) the phone is not an interaction delivery target and cannot answer an RCS postback, unless `POST /v1/phone-links/{id}/confirm` carries a `ConfirmationProof` (§2.17) from a trusted device. `PhoneLink.usableFrom == nil` means usable.
- Phone verification by SMS code (`phone-links/start`) is limited to the allowed destination regions (`OTP_ALLOWED_COUNTRIES`, default US, CA), a platform-wide and a per-prefix budget (alert-level log + audit `phone_link.budget_exhausted`), and the integrity hook.
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

**Business text in SMS/RCS.** Business-originated text (`message` payloads and business replies) is rendered after `[Business Name]: ` as **one line**: LF, CR, NEL, U+2028/2029, VT, FF and tab become spaces, spoofing and control characters are removed, whitespace is collapsed, a leading `[` becomes `(` and a leading "Viadere" (after width/case/homoglyph/punctuation normalisation) gets a `- ` prefix (`SMSEncoding.businessLine`). **Menu race.** A digit received less than `SMS_MENU_RACE_SECONDS` (default 3) after a menu was shown is not acted on; the menu is shown again (`gateway.menu_race`). **Carrier opt-out** (provider error 21610) is written through the revision-checked thread context as well as the `opted_out` column.
**Shared thread.** If the thread is `CONNECTED`/`SESSION_MENU` to business B, an interaction SMS from business A is not sent; a content-free notice naming A and B (`GatewayCopy.newMessageNotice`) is sent instead.

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

### 2.13 Reward eligibility and redemption codes
* **Eligibility** is returned as `RewardEligibility {state, nextAction, checkedAt, nextEligibleAt?, pointsShortfall?}` and computed only by the server. Evaluation order: `revoked` → `redeemed` (single-use reward already consumed) → `expired` (`now ≥ validUntil`) → `notYetValid` → `notToday` (ISO weekday in the reward's IANA zone) → `limitReached` → `insufficientPoints` → `eligible` (`nextAction` is `claim` for coupons and offers not yet claimed, otherwise `redeem`). Day boundaries use the zone's calendar, so DST days of 23 or 25 hours are single days.
* **Limits:** recurring rewards allow `perDayLimit` redemptions per local day per consumer; coupons, offers and perks without recurrence allow one per consumer; points rewards are limited by balance only.
* **Redemption code:** `XXXXX-XXXXX` over `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (50 random bits). Input is normalised by upper-casing, removing spaces and dashes and mapping `I`,`L`→`1`, `O`→`0`. Stored as `HMAC-SHA256(serverPepper, "reward-redemption\n" + normalizedCode)`; valid 120 s (`RewardRedemption.validForSeconds`, `serverTime`, `expiresAt`).
* **Reservation:** issuing a code takes a slot in unique `(rewardId, consumerId, windowKey, slot)` (`windowKey` is the local `YYYY-MM-DD`, `once` or `open`) and debits points by compare-and-swap. Expiry (`issued → expired`) clears the slot and returns the points.
* **Consumption:** `POST /v1/business/redemptions/consume` flips `issued → consumed` with one compare-and-swap, scoped to the calling business. Results: `200` receipt, `404` unknown/malformed/other business, `409` already used, `410` expired or reward withdrawn, `429` rate limit.

### 2.14 Wallet passes (`.pkpass`)
* Content type `application/vnd.apple.pkpass`, a ZIP of `pass.json`, `icon.png`/`@2x`/`@3x`, `manifest.json` and `signature` (stored entries, flat names, fixed timestamps, < 5 MB).
* `manifest.json`: JSON object mapping each file name (all except `manifest.json` and `signature`) to its lowercase hex **SHA-1**, keys sorted.
* `signature`: DER **PKCS#7 / CMS `SignedData`**, detached (no `eContent`), digest SHA-256, `signedAttrs` = content type, signing time, message digest of `manifest.json`; the certificate set holds the Pass Type ID certificate and the WWDR intermediate. Equivalent to `openssl smime -binary -sign -signer pass.pem -inkey key.pem -certfile wwdr.pem -in manifest.json -outform DER`.
* `pass.json`: `formatVersion` 1; `passTypeIdentifier`, `serialNumber` (`VP-…`), `teamIdentifier` equal the issued `WalletPassMetadata`; `webServiceURL` = `{PUBLIC_BASE_URL}/wallet`; `authenticationToken` (43 base64url chars); `voided: true` once voided. Style key by kind: `storeCard`, `coupon`, `eventTicket`, `boardingPass`, `generic`.
* **Authentication token:** `base64url(HMAC-SHA256(serverPepper, "wallet-auth-v1\n" + passId + "\n" + salt))`; the database keeps the per-pass random `salt` and `HMAC(pepper, "wallet-auth-hash\n" + token)`. Wallet echoes it as `Authorization: ApplePass {token}`.
* **PassKit web service** under `/wallet/v1` (Apple's protocol): `POST|DELETE /devices/{device}/registrations/{passType}/{serial}` (token; body `{"pushToken"}`; `201` new, `200` repeat), `GET /devices/{device}/registrations/{passType}?passesUpdatedSince={tag}` (`200 {"serialNumbers","lastUpdated"}` or `204`), `GET /passes/{passType}/{serial}` (token; `If-Modified-Since` → `304`), `POST /log` (bounded: 20 messages × 500 characters, redacted, rate-limited). The update push is APNs with the Pass Type ID certificate (TLS client authentication), topic = pass type identifier, empty payload.

### 2.15 Household invitations and the delegation step-up
* **Invitation code:** `XXXX-XXXX` over the same alphabet (40 random bits), normalised like §2.13, stored as `HMAC-SHA256(serverPepper, "delegation-invite\n" + normalizedCode)`, single use (`open → accepted` compare-and-swap), valid 24 h. Preview and accept spend a per-consumer budget (10/hour, burst 5) and a global one (120/min), and each invitation locks after 10 lookups.
* **Scope text:** `DelegationScopePolicy.canonicalScope(of:)` = lines `role=…`, `purposes=` (sorted raw values, comma-joined), `businesses=` (sorted lowercase UUIDs, comma-joined), `expires=` (ISO-8601 ms UTC), `label=…`, joined with `\n`. `scopeDigest` = lowercase hex SHA-256 of its UTF-8.
* **Step-up proof** `{deviceId, signedAt, scopeDigest, signature}`: `signature` = base64url raw `r‖s` ECDSA P-256/SHA-256 by the device's **`approvalBiometric`** key over the UTF-8 of `"VIADERE-DELEGATION-STEPUP-V1\n" + deviceId + "\n" + signedAt + "\n" + scopeDigest` (`signedAt` ISO-8601 ms UTC). Required whenever the purposes include `security` or `accountService`. The server verifies: the proof's device is the calling device; the digest equals the digest of the request it rebuilds; `signedAt` is ≤ 60 s in the future and ≤ 300 s old; the signature verifies against that device's `approvalBiometric` key (a passcode or request key fails); and the proof has not been used before (`ReplayGuard` scope `delegation-stepup:{deviceId}`, key `sha256(deviceId|signedAt|scopeDigest)`: the signed content, not the signature string, because `(r, n − s)` is a second valid encoding). Errors: `403 insufficient_assurance` (missing, or no biometric key), `403` (device/scope mismatch), `400` (malformed), `401 signature_invalid`, `401 clock_skew`, `410 expired` (too old), `409 replay_detected`.
* **Limits:** sensitive grants last at most 30 days (others at most one year, at least one hour); only businesses the grantor is connected to; marketing and rewards purposes cannot be delegated.
* **Decisions:** a delegate's decision is accepted only through an active grant covering the interaction's purpose and business, from a `manager`, for `confirm`→`confirm|decline` and `choose`→`select|decline`. Everything else is `403` and audited as `delegation.denied`; an interaction outside every grant is `404`.
* **Audit actions** (subject type `delegation`): `delegation.created`, `.accepted`, `.revoked`, `.expired`, `.used`, `.denied`, `.stepup_rejected`.

### 2.16 Live Activity pushes
`apns-push-type: liveactivity`, topic `{bundleId}.push-type.liveactivity`. `event` is `start` (to a push-to-start token, with `attributes-type: ViadereActivityAttributes`, `attributes` `{businessName, businessId, interactionId}` and a neutral alert), `update` or `end` (terminal states) to the per-activity token registered for the same business and activity chain. `content-state` is `LiveActivityStatus` encoded with the default (non-ISO) `JSONEncoder` that ActivityKit's decoder expects. Sent only for `transactional`, `accountService` and `support` statuses of live (not test) keys.

### 2.17 Confirmation proofs (new device, new phone)
`ConfirmationProof {subject, subjectId, deviceId, signedAt, assurance, signature}` is made by a **trusted** device (an `app` device that is not revoked, expired, nor itself cooling down) with a user-verified key: `assurance: "biometric"` → the `approvalBiometric` key, `"devicePasscode"` → `approvalUserPresence`; a request key (`none`) never confirms. `signature` = ECDSA P-256/SHA-256 (raw r‖s, base64url, low-S) over the UTF-8 of
```
VIADERE-CONFIRM-V1\n{subject: device|phoneLink}\n{subjectId lowercase uuid}\n{deviceId}\n{signedAt ISO-8601 ms UTC}\n{assurance}
```
The server checks: the proof's device is the calling device; subject and id match the route; `signedAt` ≤ 60 s in the future and ≤ 300 s old; the signature verifies; the proof is single use (`ReplayGuard` scope `confirm:{deviceId}`, key `sha256(signing input)`). Routes: `POST /v1/devices/{deviceId}/confirm` (lifts the cool-down of another device of the same account; the confirming device must differ from the target) and `POST /v1/phone-links/{phoneLinkId}/confirm`. Errors: `403` (not a trusted device / not yours / assurance too low), `401 signature_invalid`, `401 replay_detected`. Both are audited (`device.confirmed`, `phone_link.confirmed`).

### 2.18 Sandbox (test mode)
`POST /v1/business/sandbox/relationships` (test key, scope `interactions:write`, ≤ 50 per business) creates a consumer with status `sandbox` and an active relationship. `issue`, `statuses` and `messages` with a test key require a sandbox relationship (`403` for a real one); with a live key a sandbox relationship is `404`. Sandbox consumers cannot sign in; test interactions are `livemode = false`, are never pushed, texted or decided, are metered as test usage, and every consumer query filters `livemode = true`.

### 2.19 Business display text
`InteractionValidation` rejects (`422 validation_failed`, issue codes `disallowedCharacters`, `tooLong`, `impersonation`) business strings that: contain any Unicode control, format, line/paragraph separator, private-use or unassigned scalar (this covers U+202A–202E, U+2066–2069, U+200E/F, U+061C, U+180E, U+200B–200D, U+2060, U+FEFF, U+00AD, U+2028/2029, U+0085, tag characters) or a known invisible filler (U+034F, U+115F/1160, U+17B4/5, U+180B–D, U+2800, U+3164, U+FFA0, variation selectors other than FE0E/FE0F); contain a line feed (allowed only in free-text fields of ≥ 1000 characters; CR and tab never); exceed the field's grapheme limit, `2×` that many unicode scalars, or `4×` that many UTF-8 bytes; or, after NFKD, lower-casing, combining-mark removal, homoglyph mapping and the handle confusable skeleton, start with "viadere" (every field) or contain it (name fields: service, merchant, titles, labels, action description, holder, venue). `DisplayTextSanitizer` (ViadereCore) is the shared definition; clients additionally `sanitize` before display.

### 2.20 Account deletion and retention
`DELETE /v1/account` revokes every session and device, blanks device names, deletes passkeys, and erases: phone numbers (`phone_links`, queued/sent `sms_outbound`, `channel_outbound`, `link_tokens`, found by phone hash before the hash is replaced), SMS thread state (an opted-out number keeps a fresh thread holding only the suppression), message bodies, interaction payloads and the `reply`/selection in stored outcomes, delegation labels, loyalty member references, and webhook delivery bodies for message/decision events that mention the consumer. `decisions` is append-only with exactly one permitted edit: `signed_payload` may be replaced by `[erased]` (database trigger `decisions_guard`); signature, decision, assurance, channel and ids remain. Retention (background sweep): finished `sms_outbound`/`channel_outbound` rows 30 days (`OUTBOUND_RETENTION_DAYS`), link tokens 7 days after expiry (`LINK_TOKEN_RETENTION_DAYS`), succeeded/dead webhook deliveries and their attempts 30 days (`WEBHOOK_RETENTION_DAYS`), devices past their `expiresAt` are revoked.

### 2.21 Field encryption
Wire form `v2.` ‖ base64url(nonce ‖ ciphertext ‖ tag), AES-256-GCM, additional data = UTF-8 of `"{table.column}#{rowId lowercase uuid}"`. The legacy `v1.` form (additional data = the column only) is still read; `ViadereServer reencrypt-fields` rewrites it (idempotent) and also encrypts webhook delivery bodies written in plaintext. A grant's label shares the id of the invitation it came from, so its ciphertext is valid on both rows.

### 2.22 Audit chain
Event hash version 2 = lowercase hex `HMAC-SHA256(AUDIT_CHAIN_KEY, canonicalJSON({seq, at, actorKind, actorId?, action, outcome, consumerId?, businessId?, subjectType?, subjectId?, correlationId?, meta, prev, v: 2, id}))`; version 1 (legacy) is the unkeyed SHA-256 of the same object without `v`/`id`. `audit_events.chain_version` records which. Verification (`ViadereServer audit-verify [--head file]`) accepts version 1 only for `seq ≤ AUDIT_CHAIN_LEGACY_THROUGH_SEQ` (default 0) and never after a version 2 event. **Head export:** `ViadereServer audit-head` prints `{seq, hash, occurredAt, exportedAt, mac}` with `mac = HMAC(AUDIT_CHAIN_KEY, "VIADERE-AUDIT-HEAD-V1\n{seq}\n{hash}\n{occurredAt}\n{exportedAt}")`; store it hourly or daily in write-once (object-lock) storage. `audit-verify --head` checks that the event at `seq` still has that hash.

### 2.23 Rate limiting
Token buckets keyed by `name|key`. Client IPs are normalised by `ClientIP.normalize`: IPv6 → its `/64` (`2001:db8:1:2::/64`), IPv4-mapped IPv6 → IPv4; `X-Forwarded-For` is honoured only for `TRUSTED_PROXY_COUNT` hops. The in-memory store holds at most 200 000 buckets; when full it sweeps fully-refilled buckets (at most once per second) and, if still full, **refuses new keys** (`429`, `Retry-After: 60`) while tracked keys keep exact limits. It is per instance: run a shared `RateLimitStore` when scaling out.

### 2.24 Configuration
`ENVIRONMENT` (required): `development`, `test`, `staging`, `production`. `staging` and `production`: every secret mandatory and distinct (`CONNECT_LINK_SIGNING_KEY`, `SERVER_PEPPER`, `DATA_ENCRYPTION_KEY`, `AUDIT_CHAIN_KEY`), `DATABASE_URL`, https `PUBLIC_BASE_URL`, provider credentials, `seed` refused. Outside development `RP_ORIGIN` must be an https origin of `RP_ID`. With any `DATABASE_URL`, an unset secret is an error (ephemeral secrets only exist with the in-memory database).

