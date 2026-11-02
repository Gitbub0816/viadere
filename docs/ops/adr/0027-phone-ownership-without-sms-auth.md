# ADR-0027: Phone-number ownership without SMS authentication (customer-originated nonce)

- **Status:** proposed (2026-11-02); revision 2 (2026-11-02): no immediate displacement of an existing link (S1-A2-7), victim-induced text R-13b and SMS-02 wording (A6/A7 finding 5, S1-A10-4), compose-sheet facts (A6/A7 finding 6), keyed hashes and row deletion (S1-A10-5), content limit for MO-linked numbers (S1-A10-4)
- **Spec reference:** §2.1, §3 (SMS caveats), §17 (SMS-first out of scope), §23; owner decisions 1 and **9**; open question O-2
- **Related:** SECURITY §2.8 (tokens, phone verification, linked-phone cool-down), §2.10 (SMS keywords), §2.17 (confirmation proofs); `docs/MESSAGING-GATEWAY-SPEC.md`; findings F-06, F-08
- **Review:** A2, A10, A6/A7 (compose sheet / intent), A9 (copy)

## Context

Decision 9: keep the SMS gateway only as an on-ramp for customers without the app (menus, routing, STOP/HELP, "get Viadere" links); **no authentication over SMS at all**: no OTPs, no account-link or hand-off links, no codes; phone-number ownership is proven another way, never by a Viadere-sent code. Today phone linking sends a 6-digit code by SMS (`Services/PhoneLinkService.swift:76-93`, verified: body "Viadere: Your verification code is …") and the gateway mints `/l/{token}` account-link and `/h/{token}` hand-off URLs (`SMS/GatewayService.swift:203-213`; SECURITY §2.8). What a phone link is used for: the SMS gateway treats a linked number as the account's routing identity (`requireLinkForRouting`), and interactions may be delivered to it over SMS/RCS (informational only after this ADR).

Options:

| Option | Proves | Spoof/port risk | Cost / dependency | Verdict |
|---|---|---|---|---|
| A. Viadere-sent SMS code (today) | control of the number at receive time | SIM swap, interception | per-message | **prohibited** (decision 9) |
| B. Customer-originated message (MO) from the device with an in-app nonce | that someone who can originate SMS with that From number had the in-app nonce within 10 min | inbound From spoofing through some aggregators; porting/SIM swap | inbound SMS only (usually free to receive on the Viadere number; standard rates for the sender) | **chosen** |
| C. Carrier number verification (CAMARA Number Verification / silent network auth via an aggregator) | the device's mobile data session belongs to the number | low spoofing; fails on Wi-Fi, needs carrier support | per-check fee, new vendor | future upgrade (new ADR) |
| D. Drop phone linking | n/a | n/a | n/a | partially: linking stays optional and is never needed for any app feature except SMS-thread continuity |

## Decision

### 1. Flow (option B)

1. In the app (Settings → Phone number), a **trusted device** (D1, not in cool-down; existing rule) calls `POST /v1/phone-links/mo/begin {phone}` (device-signed). Server: normalizes E.164, checks allowed regions (`OTP_ALLOWED_COUNTRIES` renamed `PHONE_LINK_ALLOWED_COUNTRIES`), per-account and per-number budgets, and returns `{phoneLinkId, nonce, sendTo, expiresAt}`; `nonce` = `VDR-` + 8 Crockford base32 characters (40 bits), stored as `HMAC-SHA256(SERVER_PEPPER, "phone-mo\n" ‖ phoneLinkId ‖ "\n" ‖ nonce)`, bound to account, device and the claimed number's **keyed** hash `HMAC-SHA256(SERVER_PEPPER, "phone\n" ‖ e164)` (never a plain hash, which a 10-digit number space makes reversible; S1-A10-5); TTL 10 minutes; only the newest begin per (account, number) is live. The whole challenge row is deleted at use or expiry. The request body carries a plaintext number, so the route is on the log allow-list (ADR-0026 §3).
2. The app opens the system compose sheet prefilled — iOS: **`MFMessageComposeViewController` only, never an `sms:` URL** (the sheet returns only `.sent` (queued), `.cancelled` or `.failed`, never the final text); Android `Intent.ACTION_SENDTO` `smsto:` with the `sms_body` extra, resolved through `PackageManager.queryIntentActivities` with a `<queries>` declaration in the app (not the SDK), or `try/catch ActivityNotFoundException` — and the person taps **Send** themselves (no silent sending is possible or attempted; Viadere never requests `SEND_SMS`). If the compose sheet is unavailable (`canSendText()` false: iPad without cellular or relay, Mac, Simulator, no SIM) or an OEM app drops `sms_body` (**verify** on the Stage 7 device set), the app shows the number and text to copy (UX_COPY S-PH-06). The body is editable, so the pattern match stays tolerant (§1.3). Dual SIM: the person picks the line; the From check handles a wrong one.
3. The provider's inbound webhook (existing, provider-signed, deduplicated) delivers the message. The gateway engine recognizes the pattern `VDR-[0-9A-Z]{8}` anywhere in the body (case-insensitive, whitespace-tolerant), **before** menu handling, and the server checks: nonce valid, unused, unexpired; inbound `From` (normalized) hash equals the claimed number's hash; number not opted out. The aggregator's spoof or "unverified sender" indicator is **evaluated on every inbound MO and a positive or missing-when-supported indicator is a hard fail** (S1-A2-7, S1-A10-4). The inbound path accepts SMS, MMS, concatenated long texts and, where the provider supports it, RCS/chat-delivered messages from Android and iOS 18+ (the Stage 5 provider test sends from RCS-capable Android and iOS phones). Then, in one transaction: link `verified` with `usableFrom` cool-down (existing: 24 h, or 72 h without another trusted device), nonce consumed, audit `phone_link.verified_mo`, notice to the account's other devices.

   **No immediate displacement (S1-A2-7).** If the number is already verified to another account, the existing link is **not** revoked by this transaction. The new link stays `pending_transfer` and the existing link stays the routing identity until (a) the new link's cool-down has ended **and** (b) the existing account was notified **in app** (a pull-based notice the app fetches on open, like the key-log head, not a push alone; UX_COPY S-PH-07) and did not choose "Keep my number". Only then does the existing link move.
4. A plain MT notice goes to the number (on-ramp copy, no code, no link) that states the effect and gives an opt-out (UX_COPY SMS-02): "Viadere: Someone linked this number to a Viadere app using a text sent from this phone. If that wasn't you, reply UNLINK. Reply STOP to stop messages." It is sent for every **valid** MO, before any cool-down ends.
5. `UNLINK` (new keyword, SECURITY §2.10) from that number revokes every link of the number at any time, notifies each affected account in app (UX_COPY S-PH-08 "Your phone number was unlinked by a text from that number."), and is audited. Repeated `UNLINK`/re-link cycles on one number are limited (at most 2 verified links per number per 7 days, and at most 1 per day) and alerted. `STOP` keeps its meaning (opt out of all messages; also ends routing).
6. The app polls `GET /v1/phone-links/{id}` until `verified` or `expired` (the app cannot know whether the text was sent: `.sent` means queued); S-PH-04 appears only at expiry. Wrong From, expired or reused nonce, spoof indicator: no link, no reply that reveals which check failed (the webhook path answers the provider identically in every case and sends no SMS on failure, so timing and replies do not enumerate; ST-PH-07 covers begin and webhook); the person sees "We didn't receive your text from {masked number}. Make sure you send it from that phone line."

### 2. Assurance and use

- New assurance label `phone_control_mo` on the link. It **satisfies no `AssurancePolicy` level**, is never an authenticator, never raises device trust, is never accepted by recovery, and the authority refuses it as evidence (THREAT_MODEL T-REC-6).
- Uses: SMS-gateway routing identity (after cool-down **and** the no-objection rule of §1.3; a trusted-device `ConfirmationProof` no longer shortens the cool-down, because the proving device is the requester's own and adds no protection for the number's real owner, S1-A10-4). Until phone-line control can be checked independently (option C), a `phone_control_mo` link receives **only on-ramp text and SMS-04** over SMS: no interaction content and no business names beyond SMS-04. Nothing else. (Owner question OQ-5 notes that this narrows SMS-thread continuity for app users; decision 9 is unchanged.)

### 3. Risks analysed

1. **Spoofed MO (From forgery).** An attacker who can inject an inbound SMS with the victim's number as From, and who knows the victim's number, can link it to the attacker's account. Gain: the attacker's account becomes the victim's routing identity on the SMS gateway (the victim's texts to Viadere would be attributed to the attacker's account context), after cool-down. Controls: the nonce is shown only to an authenticated trusted device; mandatory aggregator spoof indicator (hard fail); cool-down before routing; an existing link is never displaced before cool-down and in-app no-objection (§1.3); MT notice to the real number with `UNLINK` and `STOP`; one number per account; per-number limit on verified links. The gain is mainly **disclosure** (texts addressed to the victim's number attributed to the attacker's account), which the content limit of §2 bounds. Residual R-13.
1b. **Victim-induced text (R-13b, A6/A7 finding 5).** The nonce text is a plain, user-sent SMS. An attacker can begin a link for the **victim's** number from the attacker's own trusted device and persuade the victim ("text this to confirm your delivery") to send `Link my number VDR-…`. The victim's phone sends the MO from the right number, so the From check passes. Controls: SMS-02 to the number states plainly that the number was linked and offers UNLINK and STOP; the cool-down and no-objection rule of §1.3 protect an existing link; the per-number caps (§1.5) stop repeated re-targeting; the compose text says what it does ("Link my number to my Viadere app VDR-…", UX_COPY S-PH-02); and `phone_control_mo` is never a factor. Residual R-13b (owner A2, A9).
2. **Porting and SIM swap.** Whoever controls the number when the MO is sent can link it. Inherent to any phone proof; acceptable because the link is not an authenticator.
3. **Dual SIM / wrong line / iMessage.** A message sent from the wrong line fails the From check (clear copy). The Viadere number is not iMessage-enabled; the compose sheet sends SMS to it.
4. **Carrier filtering.** MO to a toll-free or 10DLC number generally passes; carrier-specific filtering of MO containing codes is possible; O-2 stays open for the owner/provider to confirm on staging numbers. Monitoring: rate of begins without matching MO.
5. **Abuse/cost.** Begin budgets per account (3/day) and per number (5/day); verified links per number (§1.5); SMS-02 is sent only for a valid MO, so it cannot be used to reflect texts at arbitrary numbers beyond the per-number cap; inbound volume is caller-paid. Provider-side retention of inbound messages (From number and nonce) is set to the shortest available and documented (S1-A10-5).
6. **Enumeration.** Begin answers identically for linked, unlinked and opted-out numbers, and the MO webhook path behaves identically for every failure (ST-PH-07).
7. **Counsel item.** TCPA/CTIA treatment of SMS-01, SMS-02 and SMS-04, the STOP/UNLINK wording, and retention of consent evidence in `sms_consent_events` are on the counsel list (S1-A10-4).

Tests: ST-PH-08 (spoofed or victim-induced MO against a linked number leaves the existing link in place until cool-down and no-objection), ST-PH-09 (UNLINK churn limited, alerted and notified in app), ST-PH-10 (spoof indicator positive → no link), ST-PH-11 (MO-linked number receives no interaction content over SMS).

### 4. Removal of SMS authentication artifacts (Stage 2-3)

| Artifact | Action |
|---|---|
| `POST /v1/phone-links/start`, `/verify` (SMS OTP) | removed from the route catalog; old app builds receive `410 gone` with "Update Viadere to link your number"; `phonelink*` OTP code paths deleted |
| `/l/{token}` account-link minting by the gateway (`sendAccountLink` effect) | removed; gateway replies with the static "get Viadere" text: "Get the Viadere app to connect: https://{domain}/get" (no token); linking then happens in the app via §1 |
| `/h/{token}` secure hand-off minting (SMS and RCS) | removed; for an interaction that needs an answer the text says "Open the Viadere app to respond." with no link; if the number has no app account, the business is told the customer is not reachable for that interaction type |
| Outstanding `link_tokens` | revoked at deploy (state `revoked`); routes `GET /v1/sms/link-tokens/{token}/preview` and `POST …/redeem` answer `410` |
| AASA paths `/l/*`, `/h/*` | kept one release so old links open the app on a "This link is no longer used" screen, then removed |
| `ChannelRenderer` SMS/RCS secure-handoff text | replaced by the no-link text; Core test asserts no outbound text contains a code, URL token or approval wording (ST-PH-05) |
| SECURITY §2.8 | rewritten in the same change |

## Implementation notes (clean-up round, 2026-11-02)

- Code: `PhoneLinkMO` (Core: nonce, tolerant extraction, compose text, `phone_control_mo`), `PhoneLinkService` (begin, status, inbound handling, UNLINK, pending transfers, sweep), `GatewayService.handleInbound` (link text and UNLINK before the menu engine, per-number limit), `ChannelRouter` (SMS-04 only over SMS), Kit `PhoneLinkViewModel`. Tests: `PhoneLinkMOTests` (Core, Server), `PhoneLinkViewModelTests` (Kit).
- The sender indicator is `InboundSMS.senderIndicator` (`verified`, `suspectedSpoof`, `notProvided`, `unsupported`). The shipped Twilio and MailerSend adapters report `unsupported` (neither documents such a flag for inbound SMS); `PHONE_LINK_REQUIRE_SENDER_INDICATOR=1` makes that a refusal. **Open (O-2):** the owner or provider must confirm a real indicator on the staging numbers before the linking feature flag is turned on.
- "One number per account" is enforced at begin (accounts that already hold several numbers from older builds keep them).
- `pending_transfer` (§1.3) is completed by the maintenance job after the new link's cool-down unless the current owner chose "Keep my number" (`POST /v1/phone-links/{id}/keep`); "Let it go" is dismissing the notice.
- `phone_control_mo` numbers receive SMS-04 only over SMS. RCS is unchanged apart from losing every link (it still answers inline for non-sensitive interactions under the existing assurance rules): the ADR text says "over SMS"; a stricter RCS limit needs an owner decision.
- Numbers linked by older builds (`source` `otp` or `sms_link`) stay verified; they also receive SMS-04 only, because the SMS rendering no longer depends on how the link was made.

## Consequences

- Phone linking needs one extra user action (tap Send); no Viadere-sent message ever carries a secret.
- The gateway loses its in-thread link button; on-ramp growth relies on "get Viadere" and in-app linking.
- Customers who used SMS hand-off must install the app to answer secure requests (intended by decision 9).

## Threat assumptions changed

- SIM-swap/interception of Viadere-sent codes disappears (no codes are sent). New, narrower risk: MO spoofing (R-13), bounded by cool-down, notice and `UNLINK`, and by the link never being a factor.

## Reviewers required

A2 (spoofing analysis, assurance label), A10 (phone number processing, notices), A6 and A7 (compose sheet / intent behavior), A9 (copy), A14 (removal of baseline SMS link features is within decision 9).
