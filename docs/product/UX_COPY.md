# Authentication delivery — approved customer copy (Stage 1 draft)

| | |
|---|---|
| Spec | `docs/product/AUTH-DELIVERY-SPEC-v2.md` §7, §7.1, §7.2, §20 (Part II copy is the default where §7 and §20 differ) |
| Decisions | 1 and 9 (no SMS authentication), 2, 3, 4; ADR-0021, ADR-0022, ADR-0024, ADR-0027 |
| Voice | Existing app wording and `Design/brand-guide.html`: plain, calm, short sentences; second person; the business named exactly as verified; no exclamation marks, no urgency words ("now", "immediately", "warning"), no shield imagery; existing patterns kept: "Not you? …", "This wasn't me", "Approve on your iPhone", "Approvals never happen by text." |
| Owner | A9 writes, A2 reviews for phishing and fatigue susceptibility, A6/A7 validate native affordances (spec §20). Validation on real devices is a Stage 4 gate (spec §27). |
| Status | Draft for A9 review. Strings are English source; every string is localizable and must survive 200% text and AX5 sizes without truncating the business name or the Deny button. |

## 0. Rules every string follows

1. **Identify the business** with `{Business}` = the verified display name (never a brand-kit field, never business-supplied text).
2. **Name the action** ("sign-in", "payment", "sign-in link", "code"). Never "Approve" on a passive link notification; a tap to open a link is not an approval (spec §7).
3. **No success claim Viadere cannot know.** Viadere never says "You're signed in"; after a handoff it says what it did ("Opened {host}").
4. **Lock Screen and notification text carry no code, number, amount, payee, URL or personal data.** Business name only where the system preview setting allows it (iOS "Show Previews: When Unlocked" hides the body while locked; the generic title stays).
5. **Deny is always available and equal in weight** to Approve or Continue. Deny and Report never need unlocking-plus-Face-ID where safe (they only reduce).
6. **Businesses cannot edit** any string here, the warning hierarchy, or button roles. They supply only bounded variables: `{action}` (≤ 60 chars, e.g. "Sign in on Chrome, Mac") and `{reference}` (≤ 40 chars), validated (ADR-0020 §2).
7. **Context only when reliably known.** Location or device lines appear only when the business supplied them in a business-signed (E2EE) request; otherwise they are omitted, never guessed.
8. Server-visible requests keep the existing label: "Viadere passed this on and could read it. It is not signed by {Business}. Only approve if you started this yourself."

## 1. Notifications (push)

| Id | Where | Title | Body | Notes |
|---|---|---|---|---|
| N-01 | APNs/FCM payload as sent (before the NSE runs) | Viadere | You have a new security item. | Generic; payload carries only the delivery id |
| N-02 | Sign-in link, after NSE fetch | {Business} | {Business} sign-in link is ready. Tap to continue. | spec §20 "Magic link" |
| N-03 | Push approval (sign-in), after NSE fetch | {Business} | Approve sign-in to {Business}? Only approve if you started this. | spec §20 "Push MFA"; actions: **Review** (foreground), **Deny** |
| N-04 | Payment step-up | {Business} | Confirm a payment with {Business}? Only approve if you started this. | No amount on the notification |
| N-05 | One-time code | {Business} | Your {Business} code is ready. Open Viadere to see it. | Code never in the notification |
| N-06 | Notice (account notice from a business) | {Business} | {Business} sent a security notice. | |
| N-07 | Requests replaced (collapse) | {Business} | {Business} sent a new request. Earlier ones were replaced. | ADR-0022 §5.2 |
| N-08 | NSE fetch failed / offline | Viadere | You have a new security item. Open Viadere to review it. | Never shows a stale business name |

Category actions: `viadere.auth.link` → **Open** (foreground), **Not me** (background, signed deny). `viadere.approve` → **Review** (foreground), **Deny** (background, signed deny). There is no Approve action on any notification (ADR-0022 §5.5).

## 2. Sign-in link screens (ADR-0021)

| Id | Element | Copy |
|---|---|---|
| S-LINK-01 | Title | {Business} sign-in link |
| | Body | Continue to sign in to {Business}. This opens {host}. |
| | Detail row | Expires in {m} min |
| | Primary (equal weight) | Continue |
| | Secondary (equal weight) | I didn't request this |
| | Footnote | Continue only if you asked {Business} for a sign-in link on this device. |
| S-LINK-02 | Link service choice (two equal options) | Continue on this phone / I'm signing in on another device |
| S-LINK-03 | Another device: number entry | Enter the number shown on {Business}. |
| | Field label | Number from {Business} |
| | Button | Continue (enabled when the entry is complete) · I didn't request this |
| S-LINK-04 | After opening | Opened {host}. Finish signing in there. |
| S-LINK-05 | Unsolicited (after "I didn't request this") | Didn't request this? You can ignore it. We told {Business} you didn't ask for it. |
| | Optional action | Report to Viadere |
| S-LINK-06 | Expired | This sign-in link has expired. Request a new link from {Business}. |
| S-LINK-07 | Already used | This sign-in link was already used. Request a new link from {Business} if you still need to sign in. |
| S-LINK-08 | Destination failed validation on device | We didn't open this link because it doesn't go to a website {Business} has verified. |

## 3. Push approval and payment screens (ADR-0022)

| Id | Element | Copy |
|---|---|---|
| S-MFA-01 | Title | Approve sign-in to {Business}? |
| | Subtitle | Only approve if you started this. |
| | Detail | {action} (when supplied) · Requested {relative time} · Expires in {m} min |
| | Number field prompt | Enter the number shown on {Business} |
| | Buttons (equal size, weight, contrast) | Approve · Deny |
| | Link below buttons | This wasn't me |
| S-MFA-02 | Wrong number (1st, 2nd) | That number doesn't match. Check the screen where you're signing in. |
| S-MFA-03 | Wrong number (3rd, auto-deny) | The number didn't match, so we denied this request. If you're signing in, start again on {Business}. |
| S-MFA-04 | Face ID / passcode reason string (iOS `localizedReason`) | Confirm it's you to approve this {Business} request. |
| S-MFA-05 | Approved (honest result) | Approved. {Business} will finish signing you in. |
| S-MFA-06 | Denied | Sign-in request denied. Your account has not been approved for this attempt. |
| S-MFA-07 | Reported ("This wasn't me") | Thanks. We denied this request and let {Business} know it wasn't you. If you keep getting requests you didn't start, you can pause them. |
| | Action | Pause requests from {Business} for 1 hour |
| S-MFA-08 | Fatigue warning (from 3 requests/hour) | {Business} has sent {n} requests in the last hour. Only approve one you started yourself. |
| S-MFA-09 | Paused | Requests from {Business} are paused until {time}. |
| | Action | Resume now (requires Face ID) |
| S-MFA-10 | Same-device hint (shown under the number field) | Switch to {Business} to see the number, then come back. |
| S-PAY-01 | Title | Confirm a payment to {payee}? |
| | Rows | Amount {amount formatted with currency} · Payee {payee} · Reference {reference} |
| | Subtitle | Only approve if you started this payment. |
| | Number field prompt | Enter the 3-digit number shown at checkout |
| | Buttons | Approve · Deny; link: This wasn't me |
| S-PAY-02 | Device not trusted yet | This iPhone was added recently. For your security it can approve payments after {date}. You can still deny. |

## 4. One-time code (OTP and partner TOTP codes)

| Id | Element | Copy |
|---|---|---|
| C-OTP-01 | Title | Your {Business} code |
| | Code display | {code} (large, monospaced, VoiceOver reads digits individually) |
| | Line 1 | Use it only on {Business}. |
| | Line 2 | Never share this code. {Business} will never ask you for it by phone, text or email. |
| | Detail | Expires in {m} min |
| | Buttons | Copy code · I didn't request this |
| C-OTP-02 | Expired | This code has expired. Request a new one from {Business}. |
| C-OTP-03 | Email fallback footnote (only in Viadere's email template) | {Business} sent this code by email because you asked for it there. Email is easier to intercept than the Viadere app. |
| C-TOTP-01 | Partner TOTP code label | Code from {Business}'s authenticator. Viadere delivered it; {Business} checks it. |

## 5. Device transfer, recovery and phone linking

| Id | Element | Copy |
|---|---|---|
| S-DEV-01 | Cross-device transfer (spec §7) | Confirm that you're moving your Viadere account to this device. |
| | Detail | From {old device name} to {new device name} · Confirmed with Face ID |
| | Buttons | Confirm · Not me |
| S-DEV-02 | New device recovery (spec §20) | Verify your existing device or use an approved recovery method. |
| S-REC-01 | Recovery downgrade (spec §7) | This recovery method offers less protection. Some actions will be temporarily restricted. |
| | Detail | Your other devices can cancel this during a 72-hour wait. Afterwards this device can't approve payments until each business sets it up again. (Matches SECURITY §2.26: recovered devices are D0 for high-risk approvals until re-enrolled.) |
| | Buttons | Continue · Cancel |
| S-REC-02 | Pending recovery seen in the key-log head | Someone started recovering your account on {date}. Not you? Cancel. |
| S-REC-03 | Trade-off statement (Settings → Recovery) | If you lose every device and your recovery codes, we can't restore your account. That's what keeps others from taking it. |
| S-PH-01 | Phone linking intro | Link your number by sending one text from this phone. We never send you codes. |
| | Button | Write text |
| S-PH-02 | Compose prefill (SMS body) | Link my number {nonce} |
| S-PH-03 | Waiting | Waiting for your text from {masked number}… |
| S-PH-04 | Not received | We didn't receive your text from {masked number}. Make sure you send it from that phone line. |
| S-PH-05 | Linked (cool-down) | Number linked. Businesses can reach you by text there from {date}. Approvals never happen by text. |
| SMS-01 | Gateway "get Viadere" (on-ramp) | Get the Viadere app to connect with businesses: https://{domain}/get |
| SMS-02 | MT notice after MO link | Viadere: This number was just linked to a Viadere app. If this wasn't you, reply UNLINK. |
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

## 7. watchOS (ADR-0022 §8)

| Id | Element | Copy |
|---|---|---|
| W-01 | Approval item | {Business} sign-in request |
| W-02 | Instruction | Approve on your iPhone with Face ID |
| W-03 | Buttons | Deny · This wasn't me |
| W-04 | Link item | {Business} sign-in link is ready. Open it on your iPhone. |

## 8. Web surfaces

| Id | Surface | Copy |
|---|---|---|
| WEB-01 | `@viadere/web` status UI: waiting | Check your phone. We sent a request to the Viadere app. |
| WEB-02 | Number display (business page) | Enter this number in Viadere: {code} |
| WEB-03 | Denied | The request was denied in the Viadere app. |
| WEB-04 | Expired | The request expired. Try again. |
| WEB-05 | No app / not deliverable | We couldn't reach the Viadere app for this account. Choose another way to sign in. |
| WEB-06 | Wrong browser (link service same-device, initiating session missing) | Open this link on the device where you started signing in. |
| OIDC-01 | Authorize page heading | Sign in to {Client} with Viadere |
| OIDC-02 | Passkey button (first, primary) | Use a passkey |
| OIDC-03 | App option | Use the Viadere app |
| OIDC-04 | QR instruction | Scan with the Viadere app on your phone. Only scan a code shown on a screen you trust. |
| OIDC-05 | Consent | {Client} wants to confirm it's you. It will receive a private identifier for this app only. |
| OIDC-06 | Consent buttons | Continue · Cancel |
| OIDC-07 | Error (bad client or redirect) | This sign-in request isn't valid. Return to the app you came from. |

## 9. Business-facing integration guidance (developer docs, not customer copy)

- Show the number from `match_code` in large type next to "Enter this number in Viadere" (WEB-02).
- Never tell the customer "Approve the request you received" without the number; never pre-fill or auto-submit.
- On cross-device magic links, refuse or pair (ADR-0021 §6) and show WEB-06.
