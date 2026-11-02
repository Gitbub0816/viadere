# ADR-0027: Phone-number ownership without SMS authentication (customer-originated nonce)

- **Status:** proposed (2026-11-02)
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

1. In the app (Settings → Phone number), a **trusted device** (D1, not in cool-down; existing rule) calls `POST /v1/phone-links/mo/begin {phone}` (device-signed). Server: normalizes E.164, checks allowed regions (`OTP_ALLOWED_COUNTRIES` renamed `PHONE_LINK_ALLOWED_COUNTRIES`), per-account and per-number budgets, and returns `{phoneLinkId, nonce, sendTo, expiresAt}`; `nonce` = `VDR-` + 8 Crockford base32 characters (40 bits), stored as `HMAC-SHA256(SERVER_PEPPER, "phone-mo\n" ‖ phoneLinkId ‖ "\n" ‖ nonce)`, bound to account, device and the claimed number's hash; TTL 10 minutes; only the newest begin per (account, number) is live.
2. The app opens the system compose sheet prefilled — iOS `MFMessageComposeViewController` with recipient `sendTo` and body `Link my number VDR-XXXXXXXX`; Android `Intent.ACTION_SENDTO` `smsto:` with `sms_body` — and the person taps **Send** themselves (no silent sending is possible or attempted). If the compose sheet is unavailable (iPad, no SIM), the app shows the number and text to copy.
3. The provider's inbound webhook (existing, provider-signed, deduplicated) delivers the message. The gateway engine recognizes the pattern `VDR-[0-9A-Z]{8}` anywhere in the body (case-insensitive, whitespace-tolerant), **before** menu handling, and the server checks: nonce valid, unused, unexpired; inbound `From` (normalized) hash equals the claimed number's hash; number not opted out. Then, in one transaction: link `verified` with `usableFrom` cool-down (existing: 24 h, or 72 h without another trusted device), nonce consumed, audit `phone_link.verified_mo`, notice to the account's other devices.
4. A plain MT notice goes to the number (on-ramp copy, no code, no link): "Viadere: This number was just linked to a Viadere app. If this wasn't you, reply UNLINK." (UX_COPY SMS-02).
5. `UNLINK` (new keyword, SECURITY §2.10) from that number revokes every link of the number at any time, notifies the account ("Your phone number was unlinked by a text from that number"), and is audited. `STOP` keeps its meaning (opt out of all messages; also ends routing).
6. The app polls `GET /v1/phone-links/{id}` until `verified` or `expired`. Wrong From, expired or reused nonce: no link, no reply that reveals which check failed; the person sees "We didn't receive your text from {masked number}. Make sure you send it from that phone line."

### 2. Assurance and use

- New assurance label `phone_control_mo` on the link. It **satisfies no `AssurancePolicy` level**, is never an authenticator, never raises device trust, is never accepted by recovery, and the authority refuses it as evidence (THREAT_MODEL T-REC-6).
- Uses: SMS-gateway routing identity (after cool-down or a trusted-device `ConfirmationProof`, existing §2.17), informational delivery fallback. Nothing else.

### 3. Risks analysed

1. **Spoofed MO (From forgery).** An attacker who can inject an inbound SMS with the victim's number as From, and who knows the victim's number, can link it to the attacker's account. Gain: the attacker's account becomes the victim's routing identity on the SMS gateway (the victim's texts to Viadere would be attributed to the attacker's account context), after cool-down. Controls: the nonce is shown only to an authenticated trusted device; cool-down before routing; MT notice to the real number with `UNLINK`; one number per account and a re-link notice to the previous account; provider-side spoofing filters (aggregator "suspected spoof" flags, when provided, refuse the link). Residual R-13.
2. **Porting and SIM swap.** Whoever controls the number when the MO is sent can link it. Inherent to any phone proof; acceptable because the link is not an authenticator.
3. **Dual SIM / wrong line / iMessage.** A message sent from the wrong line fails the From check (clear copy). The Viadere number is not iMessage-enabled; the compose sheet sends SMS to it.
4. **Carrier filtering.** MO to a toll-free or 10DLC number generally passes; carrier-specific filtering of MO containing codes is possible; O-2 stays open for the owner/provider to confirm on staging numbers. Monitoring: rate of begins without matching MO.
5. **Abuse/cost.** Begin budgets per account (3/day) and per number (5/day); inbound volume is caller-paid.
6. **Enumeration.** Begin answers identically for linked, unlinked and opted-out numbers (ST-PH-07).

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

## Consequences

- Phone linking needs one extra user action (tap Send); no Viadere-sent message ever carries a secret.
- The gateway loses its in-thread link button; on-ramp growth relies on "get Viadere" and in-app linking.
- Customers who used SMS hand-off must install the app to answer secure requests (intended by decision 9).

## Threat assumptions changed

- SIM-swap/interception of Viadere-sent codes disappears (no codes are sent). New, narrower risk: MO spoofing (R-13), bounded by cool-down, notice and `UNLINK`, and by the link never being a factor.

## Reviewers required

A2 (spoofing analysis, assurance label), A10 (phone number processing, notices), A6 and A7 (compose sheet / intent behavior), A9 (copy), A14 (removal of baseline SMS link features is within decision 9).
