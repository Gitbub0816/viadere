# Authentication delivery — flow × platform matrix (Stage 1, revision 2)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §7.1, §8, §13 (mobile UX gate), §19.1, §21 |
| Decisions | 1, 2, 3, 4, 9; ADR-0020 to ADR-0024, ADR-0027, ADR-0031 to ADR-0033 |
| Copy ids | `docs/product/UX_COPY.md` |
| Status | Revision 2 after the A6/A7 and A9 reviews (`docs/reviews/STAGE1_RESPONSE.md`). iOS and watchOS behavior is source-level design until A6 validates on devices in Stage 4; Android is design-only until the Kotlin package merges (A7). Every cell is a Stage 4/7 test case (A13 records device, OS version and result). Cells marked **verify** depend on platform behavior not yet checked on a device. |

## 1. Flows

| Id | Flow | Viadere role | Authority |
|---|---|---|---|
| F1 | Business magic link, same device | delivery only (business-signed destination verified on device, ADR-0031) | tenant record only |
| F2 | Business magic link, link opened on the phone but sign-in started on another device | delivery only | tenant record only |
| F3 | Viadere link service, same device | asserts (grant) | yes |
| F4 | Viadere link service, cross-device (number entry) | asserts (grant) | yes |
| F5 | One-time code delivery (business OTP) | delivery only | no |
| F6 | Partner TOTP code delivery | delivery only | no |
| F7 | Push MFA sign-in with number matching | relay; business verifies JWS | no |
| F8 | Payment / high-value step-up | relay; business verifies JWS | no |
| F9 | Deny / "This wasn't me" / pause | reduce-only | no |
| F10 | Device linking / transfer | existing ceremony + key-log append with PoP | yes (append) |
| F11 | Account recovery | existing + authority-verified codes and authority-timed hold | yes (log) |
| F12 | Phone link by customer-originated text | routing only, never a factor | no |
| F13 | OIDC sign-in (staging): passkey or app approval | asserts (id_token) | yes |

## 2. Platforms and conditions (columns)

`iOS` app (iOS 17+), `watchOS` (10+, phone-mediated), `Android` (API 30+, Kotlin app, later), `Web` (business page with `@viadere/web` or the OIDC authorize page), `Cold` (app not running; launched by the notification tap), `Locked` (device locked when the notification arrives, after first unlock since restart), `No app` (customer has no Viadere app), `Notif off` (notifications denied), `Offline` (no network on the phone), `Expired`, `Denied`, `Cross-device` (started on device A, approving on phone B). Android-only conditions are in §3a.

## 3. Matrix

Cell shorthand: **OK** = works as designed; **→App** = opens the app to a specific screen; **Inbox** = reachable from the in-app inbox only; **N/A** = not applicable; **Refuse** = server refuses; copy ids in brackets.

| Flow | iOS | watchOS | Android | Web | Cold | Locked | No app | Notif off | Offline | Expired | Denied | Cross-device |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F1 | NSE shows N-02; Open →App S-LINK-01; tenant record + destination statement verified; Continue → URL digest check → system open (universal link to business app or Safari) | W-04 (view only) | data-only FCM → N-01 then updated N-02; Open = `getActivity` immutable → S-LINK-01; Continue → `startActivity(ACTION_VIEW)` from the foreground activity | business page shows "Check your phone" (its own copy) | OK: link screen after launch, nothing fetched that consumes the token | generic or business title per preview setting; **Open needs unlock; This wasn't me works without unlock** | create `404 not_deliverable`; business uses its own channels | Inbox (E-06 banner) | E-02; nothing opens offline; item stays in inbox while unexpired | S-LINK-06; open `410` | S-LINK-05; business gets `auth.delivery.denied` | S-LINK-01 says "on this device"; business refuses or pairs (WEB-06) |
| F2 | as F1, business shows WEB-06 or runs F7 | W-04 | as F1 | WEB-06 or business pairing | as F1 | as F1 | as F1 | Inbox | E-02 | S-LINK-06 | S-LINK-05 | **this is the cross-device case**: never transfers a session |
| F3 | S-LINK-02 → "this phone" → signed challenge verified → factor JWS (user presence) → after acceptance opens the signed return URL with `#vdr_code=` | W-04 | as iOS (Keystore key) | business page reads the fragment and redeems; grant verified with grant JWKS | OK | as F1 | `404 not_deliverable` | Inbox | E-02 (evidence needs network) | S-LINK-06; authority refuses | S-LINK-05 | use F4 |
| F4 | S-LINK-02 → "another device" → S-LINK-03 number entry → evidence | W-04 | as iOS | page shows WEB-02 number, polls, redeems with verifier | OK | Open needs unlock | `404` | Inbox | E-02 | expired challenge → WEB-04 | WEB-03 | **OK by design** (number binds the two screens) |
| F5 | N-05; →App C-OTP-01 after open | none (code never on watch) | as iOS, `VISIBILITY_PRIVATE` | business page: "Enter the code from Viadere" | OK | no code on Lock Screen | `404`; business may request email fallback per request (C-OTP-03; gated, ADR-0020 §7) | Inbox | E-02 (code fetched online) | C-OTP-02 | This wasn't me → `denied` + report | code shown on phone, typed elsewhere: OK (OTP is not phishing resistant; labelled) |
| F6 | as F5 with C-TOTP-01 | none | as F5 | as F5 | OK | as F5 | `404` | Inbox | E-02 | C-OTP-02 | as F5 | as F5 |
| F7 | N-03 actions Review/Deny; Review →App S-MFA-01 (needs unlock); number entry; Face ID/passcode; signs `ApprovalResult` v2; "Approved" only after the relay accepted | W-01..W-03: Deny / This wasn't me only, relayed to the phone (W-05 if unreachable); Review opens the watch app, not the phone (**verify**) | data-only FCM; Keystore pairwise key; same screen; `FLAG_SECURE` | business page WEB-01 + WEB-02; outcome via verified JWS | OK: request fetched after launch | generic body; **no number on Lock Screen**; Deny works without unlock; Review/Approve need unlock + UV | `404 not_deliverable` (business falls back to its own methods; no Viadere SMS) | Inbox (approval list) | E-02; **Approve is never queued**: S-MFA-11 on failure | request `expired`; S-MFA-12; WEB-04 | S-MFA-06; WEB-03; signed deny | **primary case**: number typed on phone; same-device uses S-MFA-10 |
| F8 | N-04; S-PAY-01; 3 digits; biometric only; D1 only (S-PAY-02) | Deny / This wasn't me only | as iOS, `BIOMETRIC_STRONG` key, invalidated by enrollment change | checkout shows 3-digit number | OK | no amount on Lock Screen | `404` | Inbox | E-02; never queued (S-MFA-11) | WEB-04 | S-PAY-01c; WEB-03 | OK (checkout on laptop, approve on phone) |
| F9 | Deny from approval notification or This wasn't me from link notification (background, signed, no unlock); screens: Deny and This wasn't me (S-MFA-07); pause/resume S-MFA-09 | Deny / This wasn't me (forwarded to the phone; W-05) | Deny = immutable broadcast to non-exported receiver, `goAsync()`/expedited work, no `setAuthenticationRequired` | WEB-03 | OK | **Deny works without unlock** (after first unlock since restart; before it, N-09) | N/A | Inbox | **not queued**: attempted once; on failure local N-09 "Deny not sent yet. Open Viadere."; business sees `pending` until expiry | N/A | N/A | N/A |
| F10 | existing enrollment + S-DEV-01; key-log append with PoP by the new key; S-SEC-02 until the head lists the new keys | not allowed | Android enrollment (Kotlin, later), key attestation chain | N/A | N/A | N/A | N/A | confirmation shown in app | needs network | ceremony expires (5 min) | This wasn't me → device not added; notices | **is** cross-device by nature (old device confirms new) |
| F11 | existing recovery screens; S-REC-01; S-REC-04 after legacy-code recovery; pending shown via S-REC-02 on other devices; S-SEC-01 if heads are withheld | none | later | recovery begins only in the app | OK | notice push generic | N/A | S-REC-02 from key-log head on next open | needs network | hold continues; status poll | other device cancels ("Not you? Cancel") | recovering device ≠ existing devices by nature |
| F12 | S-PH-01 → `MFMessageComposeViewController` (never `sms:`) → user taps Send → S-PH-03 until verified or expiry → S-PH-05 | N/A | `ACTION_SENDTO smsto:` with `sms_body`, `<queries>` or `ActivityNotFoundException` fallback; may be sent as RCS (**verify** inbound) | N/A | N/A | N/A | **N/A** — for people without the app the gateway is on-ramp only (SMS-01) | not needed (polling) | text queues on phone; nonce valid 10 min | S-PH-04 | UNLINK reply (SMS-03); S-PH-08 in app | iPad/no SIM: S-PH-06 copy text; From check still applies |
| F13 | app approval via QR (Viadere universal link, opened in the app) or `login_hint` push (fatigue-counted); OIDC-08 with client name and redirect host | Deny only | later | OIDC-01..07; passkey first | OK | as F7 | passkey still works (no app needed) | QR path works; push path needs inbox | authorize page needs network | code/challenge expired → OIDC error to RP | RP receives `access_denied` | QR = cross-device (`acr:app`, not phishing resistant); passkey hybrid transport preferred |

## 3a. Android-only conditions (A6/A7 finding 3)

| Flow | Force-stopped app | Doze / restricted standby bucket | Notification permission not granted (13+) | OEM battery manager |
|---|---|---|---|---|
| F1-F8, F13 push | FCM data messages are not delivered; item reachable from the inbox when the person opens the app | high-priority data messages are delivered but can be delayed; the app always posts a visible notification so priority is kept | no notification; inbox + E-06 banner | can delay or drop; E-08 help item; inbox fallback |
| F9 Deny | N/A (no notification shown) | broadcast runs; expedited work for signing | N/A | as left |

## 4. Platform notes and constraints (with sources to re-check, spec §29)

1. **iOS tap behavior** (spec §7.1, Apple UserNotifications): the tap foregrounds Viadere first; a silent jump to a website is not possible and not promised. The link opens only from the link screen's Continue (ADR-0021 §4).
2. **iOS universal links**: `UIApplication.open` without `universalLinksOnly` lets a business universal link open the business app; otherwise Safari. The app never uses an embedded web view for business links. A universal link to Viadere's own domain tapped inside Safari on that domain does not open the app (relevant to `/get`).
3. **iOS notification categories** are registered at launch in `didFinishLaunching` (required for cold-launch responses), including `viadere.approve` (fixes F-15). Action options: Review/Open `.foreground` (forces unlock); Deny/This wasn't me neither `.foreground` nor `.authenticationRequired`. A Core test asserts the option sets (ST-MFA-11).
4. **Cold launch and first unlock**: the notification response is delivered after launch; the app routes by `adl`/`req` id once the account is unlocked from the Keychain; if protected data is unavailable (device locked since boot), the app shows E-07. Before first unlock the NSE cannot read `AfterFirstUnlock` items either, so the push shows N-01/N-08 only; the app re-fetches on foreground. The NSE runs only for `apns-push-type: alert` with `mutable-content: 1`. No flow depends on silent pushes (throttled, not delivered after force-quit).
5. **Android** (FCM, App Links, Keystore docs): data-only high-priority FCM, the app renders and updates the notification (ADR-0022 §9); notification taps use `PendingIntent.getActivity(FLAG_IMMUTABLE)` to an exported-false activity; Deny uses an immutable broadcast to an exported-false receiver; no notification trampolines (Android 12+); App Links verified with `assetlinks.json` on the business host (business's responsibility) and on Viadere's link domain (Viadere's, to add); since Android 12 an unverified web link opens in the browser; Viadere cannot force the business app. Keys: `setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)` for sign-in, `BIOMETRIC_STRONG` only and `setInvalidatedByBiometricEnrollment(true)` for payments; StrongBox when available; key attestation at enrollment; Play Integrity. Minimum API 30.
6. **watchOS**: phone-mediated; no keys; never Approve for auth or payment (ADR-0022 §8). Watch actions forward to the phone; whether mirrored-notification actions reach the phone or the watch app with a watch app installed is **verify on device** (Stage 4). Wear OS bridged notifications use the phone's Deny action and never define Approve.
7. **Web**: no secrets in `localStorage`; PKCE verifier held by the business backend session; CSP-compatible SDK (ADR-0030). The link-service code arrives in the URL fragment and is posted by the business page's script.
8. **Notifications denied**: every flow remains reachable from the in-app inbox; the business sees `queued`/`sent` without `delivered` and should offer its other methods after its own timeout.
9. **No app installed**: Viadere never falls back to SMS for authentication (decisions 1, 9); create returns `404 not_deliverable` without saying why.
10. **Over budget** (ADR-0020 §8): the request is delivered silently (no alert); the inbox shows INB-01. A paused business's request leaves S-MFA-13 in the inbox; the business page shows WEB-05 without hinting at the pause.
11. **Live Activities**: never started for auth, payment, link or code items (ADR-0022 §5.7).
12. **Deny and This wasn't me never wait for a key-log head check** (ADR-0032 §3.4).
13. **Clipboard**: copying a code uses a local-only pasteboard item with an expiry (iOS) and `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+, **verify**).

## 5. Accessibility checks per screen (Stage 4)

VoiceOver/TalkBack labels name the business and action; the number field is labelled "Number on {Business}" and is the first control after the title; focus lands on the title when the sheet opens; codes are read digit by digit; wrong-number errors are announced (not color only). The safe action (Deny / This wasn't me) comes **first** in layout and reading order and has the same size, weight, type and contrast as Approve/Continue at all Dynamic Type sizes up to AX5 (side by side, stacked with the safe action on top when text would truncate; UX_COPY §0.2). This wasn't me is a ≥ 44 pt button. Unique Voice Control names "Deny", "Approve", "This wasn't me"; Switch Control works without any gesture (no slide-to-approve). Request expiry is shown as an absolute time with "Ask {Business} for a new request" on expiry (WCAG 2.2.1: no auto-regeneration; the person restarts at the business). Reduce Motion disables animated transitions on these screens; contrast meets WCAG 2.1 AA in light and dark. Number fields refuse paste and AutoFill and are never prefilled; Android security screens set `FLAG_SECURE` and hide overlay windows. Usability metrics (spec §7.2): accidental approvals, completion rate, comprehension, phishing recognition, measured in the Stage 8 pilot.
