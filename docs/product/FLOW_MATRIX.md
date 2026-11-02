# Authentication delivery — flow × platform matrix (Stage 1)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §7.1, §8, §13 (mobile UX gate), §19.1, §21 |
| Decisions | 1, 2, 3, 4, 9; ADR-0020 to ADR-0024, ADR-0027 |
| Copy ids | `docs/product/UX_COPY.md` |
| Status | Proposed behavior. iOS and watchOS behavior is source-level design until A6 validates on devices in Stage 4; Android is design-only until the Kotlin package merges (A7). Every cell is a Stage 4/7 test case (A13 records device, OS version and result). |

## 1. Flows

| Id | Flow | Viadere role | Authority |
|---|---|---|---|
| F1 | Business magic link, same device | delivery only | no |
| F2 | Business magic link, link opened on the phone but sign-in started on another device | delivery only | no |
| F3 | Viadere link service, same device | asserts (grant) | yes |
| F4 | Viadere link service, cross-device (number entry) | asserts (grant) | yes |
| F5 | One-time code delivery (business OTP) | delivery only | no |
| F6 | Partner TOTP code delivery | delivery only | no |
| F7 | Push MFA sign-in with number matching | relay; business verifies JWS | no |
| F8 | Payment / high-value step-up | relay; business verifies JWS | no |
| F9 | Deny / "This wasn't me" / pause | reduce-only | no |
| F10 | Device linking / transfer | existing ceremony + key-log append | yes (append) |
| F11 | Account recovery | existing + authority-timed hold | yes (log) |
| F12 | Phone link by customer-originated text | routing only, never a factor | no |
| F13 | OIDC sign-in (staging): passkey or app approval | asserts (id_token) | yes |

## 2. Platforms and conditions (columns)

`iOS` app (iOS 17+), `watchOS` (10+, phone-mediated), `Android` (Kotlin SDK/app, later), `Web` (business page with `@viadere/web` or the OIDC authorize page), `Cold` (app not running; launched by the notification tap), `Locked` (device locked when the notification arrives), `No app` (customer has no Viadere app), `Notif off` (notifications denied), `Offline` (no network on the phone), `Expired`, `Denied`, `Cross-device` (started on device A, approving on phone B).

## 3. Matrix

Cell shorthand: **OK** = works as designed; **→App** = opens the app to a specific screen; **Inbox** = reachable from the in-app inbox only; **N/A** = not applicable; **Refuse** = server refuses; copy ids in brackets.

| Flow | iOS | watchOS | Android | Web | Cold | Locked | No app | Notif off | Offline | Expired | Denied | Cross-device |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 | NSE shows N-02; tap →App S-LINK-01; Continue → system open (universal link to business app or Safari) | W-04 (view only) | FCM tap → PendingIntent → S-LINK-01 equivalent; `ACTION_VIEW` with App Links | business page shows "Check your phone" (its own copy) | OK: link screen after launch, nothing fetched that consumes the token | generic title; body hidden per preview setting; Open needs unlock | create `404 not_deliverable`; business uses its own email/SMS | Inbox (E-06 banner) | E-02; open retried when online if not expired | S-LINK-06; open `410` | S-LINK-05; business gets `auth.delivery.denied` | S-LINK-01 says "on this device"; business refuses or pairs (WEB-06) |
| F2 | as F1, business shows WEB-06 or runs F7 | W-04 | as F1 | WEB-06 or business pairing | as F1 | as F1 | as F1 | Inbox | E-02 | S-LINK-06 | S-LINK-05 | **this is the cross-device case**: never transfers a session |
| F3 | S-LINK-02 → "this phone" → factor JWS (user presence) → opens return URL with code | W-04 | as iOS (Keystore key) | business redeems; grant verified with static JWKS | OK | as F1 | `404 not_deliverable` | Inbox | E-02 (evidence needs network) | S-LINK-06; authority refuses | S-LINK-05 | use F4 |
| F4 | S-LINK-02 → "another device" → S-LINK-03 number entry → evidence | W-04 | as iOS | page shows WEB-02 number, polls, redeems with verifier | OK | Open needs unlock | `404` | Inbox | E-02 | expired challenge → WEB-04 | WEB-03 | **OK by design** (number binds the two screens) |
| F5 | N-05; →App C-OTP-01 after open | none (code never on watch) | as iOS | business page: "Enter the code from Viadere" | OK | no code on Lock Screen | `404`; business may request email fallback per request (C-OTP-03) | Inbox | E-02 (code fetched online) | C-OTP-02 | "I didn't request this" → `denied` | code shown on phone, typed elsewhere: OK (OTP is not phishing resistant; labelled) |
| F6 | as F5 with C-TOTP-01 | none | as F5 | as F5 | OK | as F5 | `404` | Inbox | E-02 | C-OTP-02 | as F5 | as F5 |
| F7 | N-03 actions Review/Deny; Review →App S-MFA-01; number entry; Face ID/passcode; signs `ApprovalResult` v2 | W-01..W-03: Deny / This wasn't me only | FCM; Credential-Manager-independent; Keystore pairwise key; same screen | business page WEB-01 + WEB-02; outcome via verified JWS | OK: request fetched after launch | generic body; **no number on Lock Screen**; Approve needs unlock + UV | `404 not_deliverable` (business falls back to its own methods; no Viadere SMS) | Inbox (approval list) | E-02; submission retried while unexpired | request `expired`; WEB-04 | S-MFA-06; WEB-03; signed deny | **primary case**: number typed on phone; same-device uses S-MFA-10 |
| F8 | N-04; S-PAY-01; 3 digits; biometric only; D1 only (S-PAY-02) | Deny / This wasn't me only | as iOS, biometric `BIOMETRIC_STRONG` key | checkout shows 3-digit number | OK | no amount on Lock Screen | `404` | Inbox | E-02 | WEB-04 | WEB-03 | OK (checkout on laptop, approve on phone) |
| F9 | Deny from notification (background, signed) or screen; This wasn't me → S-MFA-07; pause/resume S-MFA-09 | Deny / This wasn't me | as iOS | WEB-03 | OK | **Deny works without Face ID** (reduce-only); report requires unlock | N/A | Inbox | queued deny sent when online if still pending | N/A | N/A | N/A |
| F10 | existing enrollment + S-DEV-01; key-log append via api | not allowed | Android enrollment (Kotlin, later) | N/A | N/A | N/A | N/A | confirmation shown in app | needs network | ceremony expires (5 min) | Not me → device not added; notices | **is** cross-device by nature (old device confirms new) |
| F11 | existing recovery screens; S-REC-01; pending shown via S-REC-02 on other devices | none | later | recovery begins only in the app | OK | notice push generic | N/A | S-REC-02 from key-log head on next open | needs network | hold continues; status poll | other device cancels ("Not you? Cancel") | recovering device ≠ existing devices by nature |
| F12 | S-PH-01 → `MFMessageComposeViewController` → user taps Send → S-PH-03/05 | N/A | `ACTION_SENDTO smsto:` | N/A | N/A | N/A | **N/A** — for people without the app the gateway is on-ramp only (SMS-01) | not needed (polling) | text queues on phone; nonce valid 10 min | S-PH-04 | UNLINK reply (SMS-03) | iPad/no SIM: copy text manually; From check still applies |
| F13 | app approval via QR or `login_hint` push; S-MFA-01 with OIDC client name | Deny only | later | OIDC-01..07; passkey first | OK | as F7 | passkey still works (no app needed) | QR path works; push path needs inbox | authorize page needs network | code/challenge expired → OIDC error to RP | RP receives `access_denied` | QR = cross-device (`acr:app`, not phishing resistant); passkey hybrid transport preferred |

## 4. Platform notes and constraints (with sources to re-check, spec §29)

1. **iOS tap behavior** (spec §7.1, Apple UserNotifications): the tap foregrounds Viadere first; a silent jump to a website is not possible and not promised. The link opens only from the link screen's Continue (ADR-0021 §4).
2. **iOS universal links**: `UIApplication.open` without `universalLinksOnly` lets a business universal link open the business app; otherwise Safari. The app never uses an embedded web view for business links.
3. **iOS notification categories** must be registered at launch, including `viadere.approve` (fixes F-15); approve always uses `.foreground` (fixes F-14).
4. **Cold launch**: the notification response is delivered after launch; the app routes by `adl`/`req` id once the account is unlocked from the Keychain; if protected data is unavailable (device locked since boot), the app shows "Unlock your iPhone to continue."
5. **Android** (Android FCM, App Links, Credential Manager docs): notification taps use an immutable `PendingIntent` to an exported-false activity; App Links verified with `assetlinks.json` on the business host (business's responsibility) and on Viadere's link domain (Viadere's, to add); OEM background restrictions can delay FCM, so the inbox is the fallback; approval keys use `setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)` with `BIOMETRIC_STRONG` only for payments; StrongBox when available.
6. **watchOS**: phone-mediated; no keys; never Approve for auth or payment (ADR-0022 §8). Wear OS follows the same rule.
7. **Web**: no secrets in `localStorage`; PKCE verifier held by the business backend session; CSP-compatible SDK (ADR-0030).
8. **Notifications denied**: every flow remains reachable from the in-app inbox; the business sees `queued`/`sent` without `delivered` and should offer its other methods after its own timeout.
9. **No app installed**: Viadere never falls back to SMS for authentication (decisions 1, 9); create returns `404 not_deliverable` without saying why.

## 5. Accessibility checks per screen (Stage 4)

VoiceOver/TalkBack labels name the business and action; the number field announces "Enter the number shown on {Business}"; codes are read digit by digit; Approve and Deny keep equal size and styling at all Dynamic Type sizes up to AX5 (side by side, stacked vertically at large sizes; reading order Approve then Deny, as on existing screens); Reduce Motion disables animated transitions on these screens; contrast meets WCAG 2.1 AA in light and dark. Usability metrics (spec §7.2): accidental approvals, completion rate, comprehension, phishing recognition, measured in the Stage 8 pilot.
