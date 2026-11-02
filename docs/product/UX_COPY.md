# Authentication delivery — approved customer copy (Stage 1, revision 2)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §7, §7.1, §7.2, §20 (Part II copy is the default where §7 and §20 differ; deliberate deviations are recorded in §11) |
| Decisions | 1 and 9 (no SMS authentication), 2, 3, 4, 13; ADR-0021, ADR-0022, ADR-0024, ADR-0027, ADR-0031, ADR-0032, ADR-0033 |
| Voice | Existing app wording and `Design/brand-guide.html`: plain, calm, short sentences; second person; the business named exactly as verified; no exclamation marks, no urgency words ("now", "immediately", "warning", "hacked"), no shield imagery; existing patterns kept: "Not you? …", "This wasn't me", "Approve on your iPhone", "Approvals never happen by text." |
| Owner | A9 writes, A2 reviews for phishing and fatigue susceptibility, A6/A7 validate native affordances (spec §20). Validation on real devices is a Stage 4 gate (spec §27). |
| Status | Revision 2 after the A9 and A6/A7 reviews (`docs/reviews/STAGE1_RESPONSE.md`). English source strings; localization rules in §10. Every string must survive 200% text and AX5 sizes without truncating the business name, the host or the Deny button. |

## 0. Rules every string follows

1. **Identify the business** with `{Business}` = the verified display name (never a brand-kit field, never business-supplied text). For authority-backed prompts and business links it comes from the authority-signed record (ADR-0031, ADR-0033), never from api display fields.
2. **Name the action** ("sign-in", "payment", "sign-in link", "code"). Never "Approve" on a passive link notification; a tap to open a link is not an approval (spec §7).
3. **No success claim Viadere cannot know.** Viadere never says "You're signed in", never predicts what a business will do, and never shows "Approved" before the relay accepted the signed answer. It says what it did ("Your answer was sent to {Business}", "Opened {host}").
4. **No time-based trust claims.** Waiting never makes a device trusted (SECURITY §2.5a, §2.26, owner decision WP-B5). No string promises that an action becomes possible "after {date}" unless that is literally the rule (the recovery activation time and the phone-link cool-down are such rules; device trust for payments is not).
5. **Lock Screen and notification text carry no code, number, amount, payee, URL or personal data.** The business name appears on a locked device **unless** the person hides previews (iOS "Show Previews: When Unlocked" or "Never" replaces title and body with the category placeholder "You have a security item."; Android follows the lock-screen setting with a generic public version) or turns off "Show business names on the Lock Screen" in Viadere Settings. Interruption level is `active`; nothing is time-sensitive.
6. **One safe-action vocabulary** (§0.1), **equal prominence** (§0.2), and Deny never needs unlocking-plus-Face-ID: from a notification it works on a locked phone (after first unlock since restart); only Review/Open need unlocking.
7. **Businesses cannot edit** any string here, the warning hierarchy, or button roles. They supply only bounded variables: `{action}` (≤ 60 chars, e.g. "Sign in on Chrome, Mac") and `{reference}` (≤ 40 chars), validated (ADR-0020 §2).
8. **Context only when reliably known.** Location or device lines appear only when the business supplied them in a business-signed (E2EE) request; otherwise they are omitted, never guessed.
9. Server-visible requests keep the existing label: "Viadere passed this on and could read it. It is not signed by {Business}. Only approve if you started this yourself."
10. **Times are absolute.** "Expires at {time}", "Requested at {time}"; no live countdown (it adds pressure). On expiry: "Ask {Business} for a new request"; Viadere never regenerates a request by itself.

### 0.1 Safe-action vocabulary

| Word | Meaning | Where |
|---|---|---|
| **Deny** | Say no to this request | approval screens and approval notifications, watch |
| **This wasn't me** | Say no **and** report it (signed `report`, `not_me`) | approval screens (footer button), link and code screens, link notifications, device transfer, watch |
| **Review** | Open the request in the app (needs unlock) | approval notifications |
| **Open** | Open the sign-in link screen (needs unlock) | link notifications |

Retired on these surfaces: "Decline", "No", "Not me", "No, it isn't me", "I didn't request this", "I don't recognize this", "Report suspicious request". Non-security confirm flows (Loops, choose/confirm interactions) keep their existing words; that is a recorded exception, not a precedent.

Line under approval buttons: "Deny says no. This wasn't me also reports it."

### 0.2 Equal prominence (testable; ADR-0022 §2.5)

Deny and Approve (or This wasn't me and Continue on link screens) are one component: identical height, width, type size, weight and contrast ratio, neutral palette (no red on Deny, no filled Approve). The safe action comes **first** in layout and reading order. Side by side until text would truncate, then stacked with the safe action on top. Approve is disabled (not hidden) until the number is complete. On approval screens "This wasn't me" is a full-width secondary button (≥ 44 pt) inside the pinned footer, not a link. No slide-to-approve.

## 1. Notifications (push)

| Id | Where | Title | Body | Notes |
|---|---|---|---|---|
| N-01 | APNs/FCM payload as sent (before the NSE or the Android fetch runs); Android public version | Viadere | You have a new security item. | Generic; payload carries only the delivery id |
| N-02 | Sign-in link, after fetch | {Business} | {Business} sign-in link is ready. Tap to continue. | spec §20 "Magic link"; actions **Open**, **This wasn't me** |
| N-03 | Push approval (sign-in), after fetch | {Business} | Sign-in request from {Business}. Only approve if you started this. | Actions **Review**, **Deny**. Rewritten (A6/A7 finding 7c) so the line reads correctly on the wrist, where Approve does not exist |
| N-04 | Payment step-up | {Business} | Payment request from {Business}. Only approve if you started this. | No amount on the notification |
| N-05 | One-time code | {Business} | Your {Business} code is ready. Open Viadere to see it. | Code never in the notification |
| N-06 | Notice (account notice from a business) | {Business} | {Business} sent a security notice. | Fixed template; never business text |
| N-07 | Requests replaced (collapse) | {Business} | {Business} sent a new request. Earlier ones were replaced. | ADR-0022 §5.2; not sent while over budget |
| N-08 | Fetch failed / offline / before first unlock | Viadere | You have a new security item. Open Viadere to review it. | Never shows a stale business name |
| N-09 | Local notification: Deny could not be sent | Viadere | Deny not sent yet. Open Viadere. | ADR-0022 §5.6 |
| — | Previews hidden placeholder (`hiddenPreviewsBodyPlaceholder`, all auth categories) | — | You have a security item. | Replaces "Viadere needs your attention" |
| INB-01 | Inbox line for a request delivered silently (over budget) | — | You have a pending sign-in from {Business}. | ADR-0020 §8 |

Category actions: `viadere.auth.link` → **Open** (foreground, needs unlock), **This wasn't me** (background, signed reduce-only, no unlock). `viadere.approve` → **Review** (foreground, needs unlock), **Deny** (background, signed reduce-only, no unlock). There is no Approve action on any notification.

## 2. Sign-in link screens (ADR-0021, ADR-0031)

| Id | Element | Copy |
|---|---|---|
| S-LINK-01 | Title | {Business} sign-in link |
| | Body | Continue to sign in to {Business}. This opens {host}. |
| | Host row | {host}, full, registrable domain in strong type, wraps, never truncated; any `xn--` label shown as is with "This address uses unusual characters." |
| | Detail row | Expires at {time} |
| | Buttons (equal, safe action first) | This wasn't me · Continue (VoiceOver: "Continue to {host}") |
| | Footnote | Continue only if you asked {Business} for a sign-in link on this device. |
| S-LINK-02 | Link service choice (two equal options) | Continue on this phone / I'm signing in on another device |
| S-LINK-03 | Another device: number entry | Enter the 2-digit number on the {Business} screen where you're signing in. No number there, or someone gave it to you? Tap This wasn't me. |
| | Field label | Number on {Business} |
| | Buttons | This wasn't me · Continue (enabled when the entry is complete) |
| S-LINK-04 | After opening | Opened {host}. Finish signing in there. |
| S-LINK-05 | After "This wasn't me" | Thanks. We told {Business} you didn't ask for this. You can ignore it. If you keep getting these, report it. |
| | Optional action | Report to Viadere |
| S-LINK-06 | Expired | This sign-in link has expired. Ask {Business} for a new link. |
| S-LINK-07 | Already used | This sign-in link was already used. Ask {Business} for a new link if you still need to sign in. |
| S-LINK-08 | Destination failed validation on device | We didn't open this link because it doesn't go to a website {Business} has verified. |
| S-LINK-09 | Destination signature failed (ADR-0031 §4) | We couldn't confirm this link came from {Business}. We didn't open it. |
| S-LINK-10 | Old `/l/` or `/h/` link (ADR-0027 §4) | This link is no longer used. Open Viadere to see your requests. |

## 3. Push approval and payment screens (ADR-0022)

| Id | Element | Copy |
|---|---|---|
| S-MFA-01 | Title | Approve sign-in to {Business}? |
| | Subtitle | Only approve if you started this. |
| | Detail | {action} (when supplied) · Requested at {time} · Expires at {time} |
| | Field label | Number on {Business} |
| | Helper under the field | Enter the 2-digit number on the {Business} screen where you're signing in. No number there, or someone gave it to you? Tap Deny. |
| | Buttons (equal, Deny first) | Deny · Approve |
| | Footer button (≥ 44 pt) | This wasn't me |
| | Line under buttons | Deny says no. This wasn't me also reports it. |
| S-MFA-02 | Wrong number (1st, 2nd; announced to VoiceOver) | That number doesn't match. Check the screen where you're signing in. Don't type a number someone gave you. |
| S-MFA-03 | Wrong number (3rd, auto-deny) | The number didn't match, so we denied this request. If you're signing in, start again on {Business}. |
| S-MFA-04 | Face ID / passcode reason string (iOS `localizedReason`, set on the signing context) | Confirm it's you to approve this {Business} request. |
| S-MFA-05 | Approved (shown only after the relay accepted the signed answer) | Approved. Your answer was sent to {Business}. |
| S-MFA-06 | Denied | Request denied. We told {Business}. If that was a mistake, start again on {Business}. |
| S-MFA-07 | Reported ("This wasn't me") | Thanks. We denied this request and told {Business} it wasn't you. Someone may have your {Business} sign-in details. You can change your password there. If you keep getting requests you didn't start, you can pause them. |
| | Action | Pause requests from {Business} for 1 hour |
| S-MFA-08 | Fatigue warning (from 3 requests/hour) | There have been {n} sign-in requests for {Business} in the last hour. If you didn't start them, tap This wasn't me. |
| | Acknowledgement before Approve is enabled (kept from the existing app) | I started this myself |
| S-MFA-09 | Paused | Requests from {Business} are paused until {time}. |
| | Action | Resume (requires Face ID) |
| S-MFA-10 | Same-device hint (under the number field) | Switch to {Business}, read the number, then come back. Don't use a number from a message or call. |
| S-MFA-11 | Answer could not be sent (offline or error; nothing is queued) | Your answer wasn't sent. Check your connection and try again. {Business} hasn't received anything yet. |
| S-MFA-12 | Expired before the answer could be sent | This request expired before your answer could be sent. If you still need to sign in, start again on {Business}. |
| S-MFA-13 | Inbox item: request blocked by a pause | A request from {Business} was blocked while requests are paused until {time}. Resume if you're trying to sign in. |
| S-PAY-01 | Title | Confirm a payment to {payee}? |
| | Rows | Amount {amount formatted with currency} · Payee {payee} · Reference {reference} |
| | Subtitle | Only approve if you started this payment. |
| | Field label and helper | Number on {Business} · Enter the 3-digit number on the {Business} checkout screen. No number there, or someone gave it to you? Tap Deny. |
| | Buttons | Deny · Approve; footer: This wasn't me |
| S-PAY-01b | Approved | Approved. Your answer was sent to {Business}. Check {Business} to see whether the payment went through. |
| S-PAY-01c | Denied | Payment denied. We told {Business} you didn't approve it. |
| S-PAY-02 | Device not trusted for payments | This iPhone can't approve payments yet. To allow it, approve it with Face ID on a device you already trust. You can still deny. |
| S-PAY-02b | Same, no other trusted device | This iPhone can't approve payments yet. {Business} can set it up again. You can still deny. |

## 4. One-time code (OTP and partner TOTP codes)

| Id | Element | Copy |
|---|---|---|
| C-OTP-01 | Title | Your {Business} code |
| | Code display | {code} (large, monospaced, VoiceOver reads digits individually) |
| | Line 1 | Use it only on {Business}. |
| | Line 2 | Never share this code. {Business} will never ask you for it by phone, text or email. |
| | Detail | Expires at {time} |
| | Buttons | This wasn't me · Copy code (iOS pasteboard item local-only with expiry; Android `EXTRA_IS_SENSITIVE`, **verify**) |
| C-OTP-02 | Expired | This code has expired. Ask {Business} for a new one. |
| C-OTP-03 | Email fallback footnote (only in Viadere's email template) | {Business} sent this code by email because you asked for it there. Email is easier to intercept than the Viadere app. |
| C-TOTP-01 | Partner TOTP code label | Sign-in code for {Business}. Viadere passed it on; {Business} checks it. |

## 5. Device transfer, recovery, account security and phone linking

| Id | Element | Copy |
|---|---|---|
| S-DEV-01 | Cross-device transfer (spec §7) | Confirm that you're moving your Viadere account to this device. |
| | Detail | From {old device name} to {new device name}. You'll confirm with Face ID. |
| | Buttons | This wasn't me · Confirm |
| S-DEV-02 | New device recovery (spec §20) | Verify your existing device or use an approved recovery method. |
| S-REC-01 | Recovery downgrade (spec §7) | Recovering with a code gives this device less access. |
| | Detail | After a 72-hour wait, your other devices are signed out and this device takes over. It can message and deny requests, but it can't approve payments or other high-risk requests until each business sets it up again. Shared household access ends. Another trusted device of yours can cancel during the wait. |
| | Detail, no other trusted device | You don't have another trusted device, so nobody can cancel this during the wait. |
| | Buttons | Cancel · Continue |
| S-REC-02 | Pending recovery seen in the key-log head | Someone used a recovery code to start recovering your account. It finishes on {date and time} unless you cancel. Not you? Cancel. Cancelling also turns off your remaining recovery codes, so make new ones afterwards. |
| S-REC-03 | Trade-off statement (Settings → Recovery) | Keep your recovery codes somewhere safe and private. Anyone with your recovery ID and one code can start a recovery. If you lose every device and every code, nobody at Viadere can restore your account. That's what keeps others from taking it. |
| S-REC-04 | After recovery with old codes (ADR-0032 §3.3) | Your account was recovered with older recovery codes. Signing in to websites with Viadere stays off until you make new recovery codes on this device. |
| | Action | Make new recovery codes |
| S-REC-05 | Prompt after release (ADR-0032 §3.5) | Make new recovery codes. Your old codes still work for recovery, but new ones also protect sign-ins with Viadere. |
| S-SEC-01 | Head unavailable for over 1 hour while online (ADR-0032 §3.4) | We couldn't check your account's security. If you didn't start a recovery or add a device, keep Viadere open on a network you trust and try again. |
| S-SEC-02 | Enrollment not yet confirmed (ADR-0032 §1.4) | Finishing security setup… |
| S-SEC-03 | Account created during an authority outage (ADR-0032 §1.5) | Some sign-in features aren't available for this account. Messaging and approvals still work. |
| S-PH-01 | Phone linking intro | Link your number to your Viadere account on this phone by sending one text from it. We never send you codes by text. |
| | Button | Write text |
| S-PH-02 | Compose prefill (SMS body) | Link my number to my Viadere app {nonce} |
| S-PH-03 | Waiting (until expiry) | Waiting for your text from {masked number}… |
| S-PH-04 | Not received (at expiry) | We didn't receive your text from {masked number}. Make sure you send it from that phone line. |
| S-PH-05 | Linked (cool-down) | Number linked. Businesses can reach you by text there from {date}. Approvals never happen by text. |
| S-PH-06 | No compose sheet (iPad, no SIM) | Send this text from the phone with that number: "{prefill}" to {sendTo}. |
| | Button | Copy text |
| S-PH-07 | In-app notice to the current owner of a number (ADR-0027 §1.3) | Someone asked to link {masked number} to another Viadere account. If that number is still yours, keep it. |
| | Buttons | Keep my number · Let it go |
| S-PH-08 | Number unlinked by UNLINK | Your phone number was unlinked by a text from that number. |
| SMS-01 | Gateway "get Viadere" (on-ramp) | Get the Viadere app to connect with businesses: https://{domain}/get |
| SMS-02 | MT notice after a valid MO | Viadere: Someone linked this number to a Viadere app using a text sent from this phone. If that wasn't you, reply UNLINK. Reply STOP to stop messages. |
| SMS-03 | Reply to UNLINK | Viadere: Done. This number is no longer linked to a Viadere app. |
| SMS-04 | Secure request on a text-only number | Viadere: {Business} sent you something that needs the Viadere app. Open Viadere to respond. |

The spec's §7 "SMS fallback" copy ("Use a text message instead? …") is **not used**: decisions 1 and 9 exclude SMS for authentication. No string in this file offers a text message as a sign-in method.

## 6. Errors and outage

| Id | Situation | Copy |
|---|---|---|
| E-01 | Service outage / authority unavailable (spec §7) | We couldn't complete verification right now. Try again. |
| E-02 | Offline | You're offline. Connect to the internet to review this request. |
| E-03 | Request no longer valid (cancelled or superseded) | This request is no longer active. |
| E-04 | Delegate device | Only the account holder can respond to security requests. |
| E-05 | App update needed (old phone-link build) | Update Viadere to link your number. |
| E-06 | Notifications off (inbox banner) | Notifications are off. Security requests still appear here when you open Viadere. |
| E-07 | Cold launch, protected data unavailable | Unlock your iPhone to continue. |
| E-08 | Android, notifications delayed (Help item) | If requests arrive late, turn off battery optimization for Viadere. |

## 7. watchOS (ADR-0022 §8)

| Id | Element | Copy |
|---|---|---|
| W-01 | Approval item | {Business} sign-in request |
| W-02 | Instruction (first line of the long look) | Approve on your iPhone. |
| W-03 | Buttons | Deny · This wasn't me |
| W-04 | Link item | {Business} sign-in link is ready. Open it on your iPhone. |
| W-05 | Phone unreachable | Couldn't reach your iPhone. Open Viadere on your iPhone to deny. |

## 8. Web surfaces

| Id | Surface | Copy |
|---|---|---|
| WEB-01 | `@viadere/web` status UI: waiting | Check your phone. We sent a request to the Viadere app. |
| WEB-02 | Number display (business page) | Enter this number in Viadere: {code} |
| WEB-03 | Denied | The request was denied in the Viadere app. |
| WEB-04 | Expired | The request expired. Try again. |
| WEB-05 | No app / not deliverable / paused | We couldn't reach the Viadere app for this account. Choose another way to sign in. (Never hints at a pause: no enumeration.) |
| WEB-06 | Wrong browser (link service same-device, initiating session missing) | Open this link on the device where you started signing in. |
| OIDC-01 | Authorize page heading | Sign in to {Client} with Viadere |
| OIDC-02 | Passkey button (first, primary) | Use your Viadere passkey |
| OIDC-03 | App option | Use the Viadere app instead |
| OIDC-04 | QR instruction | Scan with the Viadere app. Only scan a code on this page. Don't scan one that someone sent or showed you. |
| OIDC-05 | Consent | {Client} wants to confirm it's you. It gets an ID that only {Client} can use. It doesn't get your name, email or phone number, and other apps can't match it. You'll return to {redirect host}. |
| OIDC-06 | Consent buttons | Cancel · Continue |
| OIDC-07 | Error (bad client or redirect) | This sign-in request isn't valid. Return to the app you came from. If you got here from a message, close this page. |
| OIDC-08 | Phone screen after QR or `login_hint` push | Title "Sign in to {Client}?"; row "Website {redirect host}"; number field as S-MFA-01; subtitle "Only approve if you opened this page yourself."; buttons Deny · Approve; footer This wasn't me |
| OIDC-09 | Settings list | Apps you've signed in to with Viadere · {Client}, last used {date} |
| OIDC-10 | Revoke action | Stop {Client} recognizing me |

## 9. Business-facing integration guidance (developer docs, not customer copy)

- Show the number from `match_code` in large type next to "Enter this number in Viadere" (WEB-02).
- Never tell the customer "Approve the request you received" without the number; never pre-fill or auto-submit; never read the number to a customer by phone or text.
- On cross-device magic links, refuse or pair (ADR-0021 §6) and show WEB-06.
- Throttle unauthenticated sign-in triggers per client IP and per account (R-20).
- `variables` must not contain names, emails or phone numbers.

## 10. Localization rules (S1-A9-12)

- Strings live in a String Catalog with plural variations ("{n} requests", "2 earlier requests were replaced"); no sentence is assembled in code; ids in this file are stable keys.
- Every variable (`{Business}`, `{host}`, `{Client}`, `{payee}`, `{reference}`) is wrapped in Unicode bidi isolates (FSI … PDI) so names and hosts render correctly in RTL locales.
- Times, dates, money and masked phone numbers use locale formatters; nothing is formatted by hand.
- Each English source string ships with a `comment` describing every variable and the screen.
- Target reading level: grade 8 or lower.
- First additional locale: Spanish for the US launch (owner question OQ-6; "US-only" residency does not mean English-only).

## 11. Deliberate deviations from spec Part II default copy

| Id | Part II default | This file | Reason |
|---|---|---|---|
| S-MFA-06 | "Sign-in request denied. Your account has not been approved for this attempt." | "Request denied. We told {Business}. If that was a mistake, start again on {Business}." | A9 (S1-A9-6): the default reads as if the person's account was rejected and gives no next step. Needs A0 acknowledgement at the gate |
| N-03 | "Approve sign-in to {Business}? Only approve if you started this." | "Sign-in request from {Business}. Only approve if you started this." | The notification is mirrored to the watch, where Approve does not exist (A6/A7 finding 7c) |
