# Stage 1 review: A9 (UX writing and behavioral security) and A10 (privacy and compliance)

| | |
|---|---|
| Reviewed at | `0fab4ce` (branch `claude/inspiring-cannon-t5hxfw`), 2026-11-02 |
| Reviewers | A9 and A10, independent of the Stage 1 author (who acted as A1, A2, A3, A5, A10). |
| Read | Spec v2 §7, §7.1, §7.2, §10, §11, §11.1, §19.1, §20, §23; `AUTH-OWNER-DECISIONS.md`; `STAGE1_REVIEW_REQUEST.md`; `Design/brand-guide.html`; `UX_COPY.md`; `FLOW_MATRIX.md`; ADR-0020 §6-§7, ADR-0022, ADR-0024, ADR-0026, ADR-0027 (and ADR-0023/0025 for identifiers); `THREAT_MODEL.md`; `TRUST_BOUNDARIES.md`; `docs/ops/DATA-INVENTORY.md`; SECURITY §2.5a, §2.17, §2.26. Existing wording compared against `App/Viadere/Features/Approve/ApproveRequestSheet.swift`, `Approval/ApprovalSheet.swift`, `App/ViadereWatch/WatchRootView.swift`, `App/Shared/Runtime/NotificationCategories.swift`, `BrandDecorations.swift`, onboarding phone copy. |
| Scope limits | Source-level review only. No device, VoiceOver, Dynamic Type or usability testing was possible; those stay Stage 4/8 gates. Not legal advice (see section 4). |

## 1. Verdict

**A9: APPROVE WITH CONDITIONS. A10: APPROVE WITH CONDITIONS.**

The design is sound where it matters most: no SMS authentication, no codes or links in push payloads, Deny always available, businesses cannot edit security copy, Viadere never claims a sign-in succeeded, and the retention model separates pending secrets from metadata from evidence. Nothing found requires redesign.

The conditions: the five A9 High findings and the four A10 High findings below must be fixed in the documents (or an owner/counsel decision recorded) before the Stage 1 exit gate is signed. One A9 High (S1-A9-1) is a string that is **factually wrong against SECURITY** and would mislead people about payment approvals. The A10 residency and E-class findings must be settled before any production data, but do not block staging pilot work.

## 2. A9 findings (copy and behavioral security)

Severity: High = wrong, deceptive or defeats a stated control; Medium = weakens comprehension or consistency; Low = polish. IDs are `S1-A9-n`.

### S1-A9-1 (High) S-PAY-02 states a rule that does not exist
- **Location:** `UX_COPY.md` §3, S-PAY-02 ("...it can approve payments after {date}").
- **Issue:** SECURITY §2.5a and §2.26 and the owner decision WP-B5: **no time-based elevation**. A notice window ending never makes a device D1; only a D1 device's approval (§2.17) does, and a recovered device is D0 with no end date. The existing app says "Waiting doesn't change that." The string promises the opposite, so people will wait and then fail, or will learn that waiting works.
- **Required change:** replace with:
  - "This iPhone can't approve payments yet. To allow it, approve it with Face ID on a device you already trust. You can still deny."
  - Variant for an account with no trusted device: "This iPhone can't approve payments yet. {Business} can set it up again. You can still deny."
  - Remove the `{date}` variable.

### S1-A9-2 (High) Success claims and the offline state
- **Location:** S-MFA-05, FLOW_MATRIX F7/F8/F9 "Offline" cells.
- **Issue:** (a) "Approved. {Business} will finish signing you in." predicts a business action Viadere cannot know (rule 3, spec §7 "no deceptive success state"). (b) FLOW_MATRIX says a submission is "retried while unexpired" when offline, yet no string exists for that state, so the only available result copy is "Approved", shown before anything reached the business.
- **Required change:**
  - S-MFA-05: "Approved. Your answer was sent to {Business}." Payment (S-PAY-01): "Approved. Your answer was sent to {Business}. Check {Business} to see whether the payment went through."
  - New S-MFA-11 (queued, offline or retrying): "Saved on this phone. We'll send it to {Business} when you're back online, if it hasn't expired."
  - New S-MFA-12 (send failed after expiry): "This request expired before your answer could be sent. If you still need to sign in, start again on {Business}."
  - Show "Approved" only after the relay accepted the signed result.

### S1-A9-3 (High) Number matching: people are not told what to do when the number is missing
- **Location:** S-MFA-01, S-PAY-01, S-MFA-10; ADR-0022 §2; FLOW_MATRIX §5.
- **Issue:** "Enter the number shown on {Business}" does not say (a) how many digits, (b) that **no number on the sign-in screen means do not approve**, (c) that a number read out or sent by someone else must never be typed (voice and text pretexting is the realistic attack on number matching). Unprompted guessing or asking the "support agent" is the failure mode. Also, ADR-0022 does not say the field must resist paste and AutoFill; an attacker-sent text could be pasted in.
- **Required change (copy):**
  - S-MFA-01 helper under the field: "Enter the 2-digit number on the {Business} screen where you're signing in. No number there, or someone gave it to you? Tap Deny." Field label: "Number on {Business}".
  - S-PAY-01: "Enter the 3-digit number on the {Business} checkout screen. No number there, or someone gave it to you? Tap Deny."
  - S-MFA-10 (same device): "Switch to {Business}, read the number, then come back. Don't use a number from a message or call."
  - S-MFA-02: keep, add: "Don't type a number someone gave you."
- **Required change (behavior, add to ADR-0022 §2.3 and FLOW_MATRIX §5):** numeric field with `textContentType` unset, AutoFill and paste disabled, no `oneTimeCode` suggestions, wrong-entry announced to VoiceOver as an accessibility announcement (not color only).

### S1-A9-4 (High) Deny / report vocabulary and prominence contradict the existing app and are not yet testable
- **Location:** UX_COPY §0 rule 5, §1 category actions, §3, §5 (S-DEV-01 "Not me"), FLOW_MATRIX §5; existing `ApproveRequestSheet.swift`, `ApprovalSheet.swift`.
- **Issue:**
  1. The same decline action is called "Deny", "Decline", "No", "Not me", "I didn't request this", "This wasn't me", "I don't recognize this" and "Report suspicious request" across the new doc and the app. People cannot learn one safe action.
  2. Existing Approve v2 sheet styles Decline as `.destructive` (red) next to a primary Approve. "Equal weight" is claimed but not defined; red marks the safe action as dangerous and fails for color-blind users.
  3. FLOW_MATRIX §5 sets reading order "Approve then Deny"; the existing footer puts Decline first. Putting Approve first primes it and, for VoiceOver, reaches the riskier control first.
  4. "This wasn't me" is a text link below the buttons (S-MFA-01). At AX5 it can fall below the fold and is a small target. Notifications offer **Deny** or **Not me**, never both, and no "This wasn't me".
  5. Nothing tells people how Deny and This wasn't me differ.
  6. `ApprovalSheet` still has "Slide to approve/sign in", which makes approval one gesture.
- **Required change:**
  - One vocabulary: **Deny** (say no) and **This wasn't me** (say no and report). Retire "Decline", "No", "Not me", "I didn't request this" and "I don't recognize this" on these surfaces (record any exception for non-security confirm flows). Links: S-LINK-01/03 secondary becomes "This wasn't me"; C-OTP-01 "This wasn't me"; S-DEV-01 "This wasn't me"; link notification action "This wasn't me".
  - UX_COPY §3 adds a testable definition: Deny and Approve are one component, identical height, width, type size, weight and contrast ratio, neutral palette (no red on Deny); Deny first in layout and reading order; side by side until a size where text would truncate, then stacked with Deny on top; Approve disabled (not hidden) until number entry is complete.
  - "This wasn't me" is a full-width secondary button (min 44 pt) inside the pinned footer, not a link.
  - Line under the buttons: "Deny says no. This wasn't me also reports it."
  - No slide-to-approve for any flow in this program; state it in ADR-0022 §2.5.
  - Notification actions for approvals: **Review** and **Deny**; for links: **Open** and **This wasn't me**. Lock-screen report needs no unlock only if it is a signed reduce-only action; if it needs unlock, say so in the matrix (it does today, F9 cell).

### S1-A9-5 (High) Recovery copy is not accurate to SECURITY §2.26
- **Location:** S-REC-01, S-REC-02, S-REC-03 (spec §7/§23, FLOW_MATRIX F11).
- **Issue:**
  - S-REC-01 says "Some actions will be **temporarily** restricted." After code recovery the device is D0 with **no end date** for high-risk approvals until each business re-enrolls it; and after the 72 h wait every other device, session, passkey and code is revoked, household shares end and phone links go back into cool-down. The "downgrade" wording understates a decision that is hard to undo.
  - It says other devices can cancel, but a person with no other trusted device has nobody who can cancel; the app should say so.
  - S-REC-02 omits when it finishes and that cancelling invalidates all remaining recovery codes.
  - S-REC-03 is accurate but omits that recovery codes are the way back and are bearer secrets.
- **Required change (replacement text):**
  - S-REC-01: "Recovering with a code gives this device less access." Detail: "After a 72-hour wait, your other devices are signed out and this device takes over. It can message and deny requests, but it can't approve payments or other high-risk requests until each business sets it up again. Shared household access ends. Another trusted device of yours can cancel during the wait." Buttons: Continue · Cancel.
  - S-REC-02: "Someone used a recovery code to start recovering your account. It finishes on {date and time} unless you cancel. Not you? Cancel. Cancelling also turns off your remaining recovery codes, so make new ones afterwards."
  - S-REC-03: "Keep your recovery codes somewhere safe and private. Anyone with your recovery ID and one code can start a recovery. If you lose every device and every code, nobody at Viadere can restore your account. That's what keeps others from taking it."

### S1-A9-6 (Medium) S-MFA-06 and S-MFA-07: confusing denial and no way forward
- **Location:** S-MFA-06 (spec §20 text), S-MFA-07.
- **Issue:** "Your account has not been approved for this attempt" reads as if the person's account was rejected. It also says nothing about the business being told and gives a person who denied by mistake no next step. S-MFA-07 gives no calm next step for someone whose sign-in details may be known to a stranger.
- **Required change:** Part II lists S-MFA-06 as the approved default, so the author/A0 must record a deliberate deviation. Proposed: S-MFA-06 "Request denied. We told {Business}. If that was a mistake, start again on {Business}." (payment: "Payment denied. We told {Business} you didn't approve it."). S-MFA-07 add: "Someone may have your {Business} sign-in details. You can change your password there." (no "hacked", no urgency).

### S1-A9-7 (Medium) OIDC consent and QR instructions do not resist QR phishing or explain what is shared
- **Location:** OIDC-04, OIDC-05, OIDC-06; ADR-0024 §4, §8; FLOW_MATRIX F13.
- **Issue:**
  1. "Private identifier for this app only" is jargon. It does not say what is not shared (name, email, phone), that the app can recognize the person next time, or where they will land.
  2. "Only scan a code shown on a screen you trust" is vague; the realistic attack is a code shown by someone else or sent in a message.
  3. The phone-side screen for the QR path is not specified (S-MFA-01 with a "client name"). Client names are not the verified business names UX rule 1 requires, and the redirect host is not shown.
  4. ADR-0024 §8 has a consent record that is revocable, but no copy exists for viewing or revoking it.
  5. OIDC-02 "Use a passkey" does not say whose; OIDC-03 hides that the app path is less phishing resistant.
- **Required change:**
  - OIDC-04: "Scan with the Viadere app. Only scan a code on this page. Don't scan one that someone sent or showed you."
  - OIDC-05: "{Client} wants to confirm it's you. It gets an ID that only {Client} can use. It doesn't get your name, email or phone number, and other apps can't match it. You'll return to {redirect host}."
  - Phone screen after scan: title "Sign in to {Client}?", rows "Website {redirect host}" and the 2-digit number field, subtitle "Only approve if you opened this page yourself.", Deny and This wasn't me as in S1-A9-4. State in ADR-0024 §3 that `display_name` is reviewed at registration and shown with the host.
  - OIDC-02 "Use your Viadere passkey"; OIDC-03 "Use the Viadere app instead".
  - Add Settings copy: "Apps you've signed in to with Viadere" list with "{Client}, last used {date}" and "Stop {Client} recognizing me" (revokes consent).
  - OIDC-07: add "If you got here from a message, close this page."

### S1-A9-8 (Medium) Lock Screen disclosure: rule 4 is inaccurate and the existing placeholder is off-voice
- **Location:** UX_COPY §0 rule 4, §1; `NotificationCategories.swift` (`hiddenPreviewsBodyPlaceholder: "Viadere needs your attention"`).
- **Issue:** Rule 4 says that with previews hidden "the generic title stays". With default category options iOS hides title and body and shows only the category placeholder (the title is shown only with `hiddenPreviewsShowTitle`). The existing placeholder "needs your attention" is mildly urgent and different from N-01. When previews are shown, the business name (a clinic, lender or counselor) is displayed to anyone who sees the phone. The doc sets no interruption level; `timeSensitive` would break through Focus (manufactured urgency).
- **Required change:**
  - Rewrite rule 4: with previews hidden, title and body are replaced by the category placeholder; set `hiddenPreviewsBodyPlaceholder` to "You have a security item." for all auth categories (same as N-01 wording, no "attention").
  - Interruption level `active` for every auth and payment notification, `timeSensitive` never (state it in ADR-0022 §5.5 and ADR-0021).
  - Settings option "Show business names on the Lock Screen" (default: follow the system setting); when off, the NSE leaves the generic text.
  - ST-PRIV-05 covers device behavior; add "placeholder text" and "interruption level" to it.

### S1-A9-9 (Medium) S-DEV-01 states a result before it happens
- **Location:** S-DEV-01 detail "Confirmed with Face ID".
- **Issue:** Shown before the person confirms; it is a success claim in the future tense. Buttons "Confirm · Not me" also break S1-A9-4.
- **Required change:** "From {old device} to {new device}. You'll confirm with Face ID." Buttons: Confirm · This wasn't me.

### S1-A9-10 (Medium) Fatigue and pause copy
- **Location:** S-MFA-08, S-MFA-09, ADR-0022 §5.
- **Issue:** (a) S-MFA-08 says "{Business} has sent {n} requests", which blames the business that the attacker is abusing, and silently drops the existing gate that requires "I started this myself" before Approve is enabled. (b) A paused business shows WEB-05 ("We couldn't reach the Viadere app") to a legitimate user, who then does not know why; nothing in the app says a request was blocked.
- **Required change:**
  - S-MFA-08: "There have been {n} sign-in requests for {Business} in the last hour. If you didn't start them, tap This wasn't me." Keep the existing acknowledgement gate "I started this myself" before Approve is enabled.
  - New S-MFA-13 (inbox item when a request is blocked by a pause): "A request from {Business} was blocked while requests are paused until {time}. Resume if you're trying to sign in."
  - WEB-05: "We couldn't reach the Viadere app for this account. Choose another way to sign in." is acceptable and must not hint at the pause (enumeration).

### S1-A9-11 (Medium) Link screen: destination shown unreliably; countdowns create pressure
- **Location:** S-LINK-01, S-MFA-01, C-OTP-01 ("Expires in {m} min", "Requested {relative time}").
- **Issue:** "This opens {host}" is the main phishing defense of the link screen but does not say how the host is shown (long subdomain trimming, look-alike or punycode names). Relative countdowns tick and add pressure; the existing sheet shows an absolute time ("Expires 3:42 PM").
- **Required change:** show the full host with the registrable domain in strong type, never truncated (wrap), punycode hosts shown in `xn--` form with "This address uses unusual characters"; VoiceOver label on Continue: "Continue to {host}". Use static "Expires at {time}" and "Requested at {time}" like the existing sheet; no live countdown.

### S1-A9-12 (Medium) Localization readiness
- **Location:** UX_COPY header ("every string is localizable"), all strings with variables.
- **Issue:** No plural, ordering or bidi rules. "{n} requests", "{m} min", "2 earlier requests were replaced" need plural forms; business names and hosts must be isolated for RTL/bidi; masked phone numbers and dates need formatters.
- **Required change:** add a section "Localization rules": String Catalog with plural variations, no sentence assembled in code, variables wrapped in bidi isolates, locale formatters for time, date, money and phone, string ids stable (use the ids in this file), target reading level grade 8, Spanish as the first additional locale for US launch (US-only does not mean English-only). Ship the English source with `comment` fields describing each variable.

### S1-A9-13 (Medium) Accessibility additions
- **Location:** FLOW_MATRIX §5.
- **Issue:** Good baseline; gaps: no time-extension path for people who need longer (WCAG 2.2.1), no Voice Control names, no statement on the error being announced, number field behaviors (see S1-A9-3), and "Approve then Deny" order (S1-A9-4).
- **Required change:** add: request expiry shown as a time, with "Ask {Business} for a new request" on expiry (never auto-regenerate, spec §7); unique Voice Control names "Deny", "Approve", "This wasn't me"; focus lands on the title when the sheet opens and the number field is the first control; errors announced; target size 44 pt; Switch Control works without the slide gesture; Deny first in reading order.

### S1-A9-14 (Low) Smaller copy items
- C-TOTP-01: "authenticator" is jargon. Replace with "Sign-in code for {Business}. Viadere passed it on; {Business} checks it."
- W-02: "Approve on your iPhone with Face ID" matches the app today but is wrong when the passcode is the allowed fallback. Use "Approve on your iPhone."
- S-LINK-05: add "If you keep getting these, report it." under the optional action.
- N-02 "Tap to continue" is spec default; keep. N-06 "{Business} sent a security notice." must not accept business text (template fixed); say so in ADR-0020 §2.
- Missing strings that FLOW_MATRIX relies on: cold launch with protected data ("Unlock your iPhone to continue." is in FLOW_MATRIX §4 but not in UX_COPY), no-SIM compose fallback for S-PH-01, UNLINK confirmation to the account ("Your phone number was unlinked by a text from that number" in ADR-0027 §1.5). Add them with ids.
- S-PH-01 "We never send you codes." is accurate for authentication but the number receives SMS-02/SMS-04 messages; phrase: "We never send you codes by text."

### What passes A9
Business named and verified (rule 1) and bounded variables (rule 6); no urgency language in the strings; "Approve" absent from passive link notifications; honest handoff text S-LINK-04; the server-visible label (rule 8) reused unchanged from the app; no SMS fallback string; watch never offers Approve; Viadere security framing is fixed by the catalog regardless of Brand Kit (ST-UX-01); the Part II default copy was kept for the six strings it covers unless noted above.

## 3. A10 findings (privacy and compliance)

IDs are `S1-A10-n`.

### S1-A10-1 (High) E-class (730 days or longer) is wider than owner decision O-3
- **Location:** ADR-0026 §1-§2 (`authority_grants`, `approval_results`, `authority_audit_events`, key log); owner decisions 7 and 10, O-3.
- **Issue:** O-3 classifies *signed device decisions and approval-result JWS* as high-value evidence. ADR-0026 also puts every grant issuance record (jti, aud, acr, sub hash, `ach`) in E for 730 days, and every low-risk push sign-in `approval_results` row. Together these are a two-year per-person sign-in history by business, held centrally by Viadere, in tension with decisions 7/10 ("align to 30 days"), spec §11 minimization and §11.1 ("no blanket long retention"). `authority_audit_events` at 2555 days (up to 7 years) covers every "This wasn't me" report too.
- **Required change:** split class E into E-high (payment and step-up decisions, recovery and key-log entries, admin and operator actions) and E-routine (low-risk sign-in grants, results and reports). Proposal for owner/counsel: E-routine uses the T period (30 days) or a documented shorter evidence period (for example 90 days); only E-high uses the `signed_decisions` class. If the owner keeps 730 days for all, record that as an explicit owner decision with counsel's basis. Reports keep minimal fields. Update ADR-0026 §2 and the pre-production approval list.

### S1-A10-2 (High) Secrets and identifiers in URLs reach edge and application logs
- **Location:** ADR-0024 §4 (`login_hint` = tenant `subject_ref`, `nonce`, `state`, QR `ach`), ADR-0026 §2 (App Insights "add redaction patterns"), THREAT_MODEL T-DO-1, ST-PRIV-01; DATA-INVENTORY §84.
- **Issue:** `GET /oidc/authorize` carries the pairwise `subject_ref` (a stable per-tenant person id) and other parameters in the **query string**. Query strings are recorded by Cloudflare analytics and logs, Azure request telemetry, browser history and Referer-style channels. Pattern-based redaction ("`adl_`, codes, URLs") fails open when a pattern is missed. T-DO-1 lists logs but not the edge.
- **Required change:**
  - Auth and OIDC routes log an allow-list of fields only (route template, status, ids, latency); no query string, no body; implemented in the logger/App Insights telemetry initializer, not by regex. State in ADR-0026 and ST-PRIV-01.
  - Cloudflare: Logpush and Analytics for the `id.` host and the link-service host exclude query strings; document retention of Cloudflare logs.
  - Prefer carrying `login_hint` in a signed request object or a POST (PAR) in a later phase; for staging, document the exposure and keep `login_hint` optional.
  - Extend ST-PRIV-01 to the Cloudflare log export and to the authorize URL.

### S1-A10-3 (High) "US-only" is not true of every processor; residency needs a precise definition and controls
- **Location:** owner decision 7; ADR-0026 §3 (Residency); TRUST_BOUNDARIES §1; `Infra/azure/variables.tf` (`centralus`); DATA-INVENTORY §2-§3.
- **Issue:**
  1. Azure stores are in `centralus`, but the ADR defines no control that keeps *new* resources, geo-redundant backup pairs (standard profile), Log Analytics, Service Bus and Key Vault replicas in US regions.
  2. All api traffic, including device-signed requests and link/OIDC traffic, passes the Cloudflare **global** edge and tunnel; Workers Static Assets and the CDN are global. That is processing outside the US even if storage is in the US.
  3. APNs/FCM (ids only), MailerSend (email fallback; operator of record and processing location not verified here) and Didit (EU by default, DATA-INVENTORY) are outside Viadere's residency control.
  4. DATA-INVENTORY still lists Fly.io, Neon and GCP KMS; it is not updated by ADR-0026/0029, so the published sub-processor list would be wrong.
- **Required change:**
  - Define residency as "stored and processed at rest in Azure US regions", separately list transit (Cloudflare edge) and provider processing; add to the consumer and business disclosures.
  - Azure Policy "allowed locations" restricted to US regions, a `policy_check.py` rule (ADR-0028 §5), and geo-redundant backup pairs verified to be US.
  - Decide whether Cloudflare Regional Services/Data Localization is required for the pilot or a documented disclosure is enough (owner + counsel).
  - Verify and record MailerSend's processing/storage location for the fallback or restrict fallback to a US-located provider; keep Didit outside the auth-delivery claim.
  - Update `DATA-INVENTORY.md` (sub-processors, logs, retention rows) in the same change that implements ADR-0026.

### S1-A10-4 (High) Spoofed MO link can route another person's messages to an attacker (ADR-0027 R-13)
- **Location:** ADR-0027 §3.1, §2; UX_COPY SMS-02/SMS-04, S-PH-05.
- **Issue:** ADR-0027 treats a spoofed MO as low gain ("routing identity"). From a privacy view the gain is **disclosure**: after the 24-72 h cool-down, texts addressed to the victim's number (business interactions routed over SMS, thread continuity) are attributed to the attacker's account context. The "trusted-device ConfirmationProof" that can shorten the cool-down is the attacker's own device, so it adds no protection for the real number owner. The only independent signal is the MT notice, which a non-user of Viadere may ignore or not understand. SMS-02 is also an unsolicited text to a person who did not ask for it (reflection abuse), bounded only by 5/day per number.
- **Required change:**
  - Spoof indicators from the aggregator are mandatory (hard fail, not "when provided").
  - Until phone-line control can be checked independently (option C in ADR-0027, carrier verification), a `phone_control_mo` link must not receive business content over SMS beyond on-ramp text: no interaction content, no business names beyond what SMS-04 shows. Record this in ADR-0027 §2 "Uses".
  - Rewrite SMS-02 to be understandable without the app and include an opt-out: "Viadere: This number was linked to a Viadere app. Not you? Reply UNLINK. Reply STOP to stop messages."
  - Add to the counsel list: TCPA/CTIA treatment of SMS-01, SMS-02, SMS-04 and the consent evidence kept in `sms_consent_events`.

### S1-A10-5 (Medium) Phone-number handling details in ADR-0027
- **Location:** ADR-0027 §1.1, §1.3, §3; ADR-0026 (`phone_link_mo_challenges`); DATA-INVENTORY (`phone_links`).
- **Issue:**
  - "Claimed number's hash" and "inbound From hash" are not specified as keyed. A plain hash of a 10-digit US number is reversible by enumeration.
  - Rows for begins that never verify keep the claimed number context for 30 days (T), longer than needed.
  - The inbound message (From number plus the nonce) also sits in the SMS provider's logs and in the gateway message tables; only the nonce hash is protected.
  - `POST /phone-links/mo/begin {phone}` carries a plaintext number in the request body: it must be on the log allow-list (S1-A10-2).
  - Enumeration answers are specified for begin but not for the MO webhook path or for SMS-02 timing.
- **Required change:** use `HMAC-SHA256(SERVER_PEPPER, "phone\n" ‖ e164)` (domain-separated) everywhere a number is compared; delete the challenge row (not only the nonce hash) at expiry for unverified begins; document provider-side retention of inbound messages and configure the shortest available; extend ST-PH-07 to the webhook path; extend ST-PRIV-01 to cover phone numbers in logs on these routes (it already lists them for the pilot run).

### S1-A10-6 (Medium) Email fallback: provider retention, suppression lists and bounce data
- **Location:** ADR-0020 §7, ADR-0026 §2 (MailerSend row), UX_COPY C-OTP-03.
- **Issue:** Deleting the address from `auth_delivery_secrets` after send does not reach MailerSend, which keeps recipient address, activity/bounce records and (unless configured off) message content including the one-time code or business link. Suppression lists hold addresses indefinitely. Bounce/complaint webhooks bring the address back into Viadere logs. The address is supplied by a *business*, so Viadere is a processor and has no relationship with the person.
- **Required change:** require MailerSend content retention off or minimum and activity retention at the shortest plan setting; document suppression-list handling and a delete path; bounce webhooks store only the delivery id and status; email fallback links and codes limited to a TTL of at most 15 minutes; list MailerSend as a sub-processor in the business DPA and the public list; keep `allow_email_fallback` off by default per tenant with a console warning explaining the privacy difference.

### S1-A10-7 (Medium) Data-subject rights for the new stores
- **Location:** ADR-0026 §5; SECURITY §2.20, §2.78.
- **Issue:** The export covers "auth deliveries (business, purpose, state, time)" only. The person also has data in `approval_results`, authority grants, OIDC consents, key-log entries, pause/fatigue state, reports and phone-link MO records. Deletion keeps class E rows "for the dispute period" on a legitimate-interest basis; for a US-only product the relevant exceptions are state-law ones (security and integrity, legal claims) and need counsel. No UI exists to view or revoke OIDC consents (see S1-A9-7).
- **Required change:** extend the export to list every store above by category (counts, businesses, times; never secrets or signatures); state in the privacy notice that evidence rows survive deletion for the stated period and why; apply the E-high/E-routine split from S1-A10-1; give consent revoke and list in the app; add a deletion test for each new table (ST-PRIV).

### S1-A10-8 (Medium) Controller/processor roles are not stated per store
- **Location:** ADR-0026 (all), spec §11, TRUST_BOUNDARIES.
- **Issue:** The ADR assumes tenants can shorten retention (processor model) while the authority, OIDC provider, key log, fatigue counters and consumer accounts are Viadere's own purposes (controller). Business-facing and consumer-facing disclosures required by spec §11 depend on this split.
- **Required change:** add a column "Role" to the ADR-0026 §2 table (Viadere as processor for business deliveries and relayed content; Viadere as controller for the consumer account, device keys, authority log, OIDC consents, abuse controls, security evidence; joint or separate for business-signed decisions, to be decided by counsel) and link it to the DPA template and the sub-processor list.

### S1-A10-9 (Medium) Business-supplied free text in T-class rows
- **Location:** ADR-0020 §2 (`variables`: `action_display` ≤ 60, `reference` ≤ 40; `client_transaction_ref`), ADR-0026 (`auth_deliveries` T 30 days).
- **Issue:** The validators check characters, not content; a business can put a name or email into `reference`. ADR-0026 clears displayed details at terminal state for `approve_requests` but keeps `auth_deliveries` rows (and potentially variables) 30 days and in webhook deliveries.
- **Required change:** treat `variables` as personal data: store them in the P-class secrets table or clear them at terminal state, keep only digests in `auth_deliveries`; exclude from audit events and support console; document in the developer guide that these fields must not contain contact data.

### S1-A10-10 (Medium) Backups and the transition from 400 to 30 days
- **Location:** ADR-0026 §2 (backups), §3; DATA-INVENTORY §7.
- **Issue:** Backups hold P and T rows up to 35 days (standard) and deleted accounts persist there. P-class ciphertext remains decryptable while the `AUTH_SECRET_KEY` version exists. The move of `approve_requests` from 400 to 30 days needs a one-time purge of older rows and a note for existing retention settings. Existing gaps (`channel_endpoints`, `rcs_postbacks` no purge; `sms_consent_events` kept indefinitely `[counsel]`) are untouched.
- **Required change:** retire `AUTH_SECRET_KEY` versions after the longest backup window; restore procedure re-runs sweeps and deletion tombstones before serving (state it as a runbook step, ST-PRIV-04 variant); migration plan for older `approve_requests`; list the three inherited gaps in the ADR with owners.

### S1-A10-11 (Low) Pairwise identifiers: acceptable, with notes
- Grant `sub` = existing per-tenant `subject_ref`, OIDC `sub` per sector, approval `kid` per business, push `thread-id` per device: no new cross-tenant correlation is introduced for businesses. Accepted.
- Notes: (a) the authority itself holds the cross-business view (`account_ref` with grants and consents); that is why S1-A10-1 and S1-A10-7 matter, and operator access to it needs the same `security_auditor` controls as E data. (b) `sector_identifier` with several hosts or a shared `sector_identifier_uri` lets two relying parties correlate the same person; require the reviewed registration to confirm common ownership. (c) `OIDC_PAIRWISE_KEY` used for two purposes is an A3 question; from a privacy view, separation is preferred.

### What passes A10
No SMS authentication or codes/links over text; push payloads carry ids only (ADR-0020 §6.2, ST-PRIV-02); P-class values are encrypted, minutes-lived and excluded from console, export and logs; a legal hold never preserves bearer secrets; evidence has role, step-up, reason and audit controls (ADR-0026 §4); the authority DB is separate; account deletion removes P/T/consents and revokes keys; the unlinking path and re-link notices exist; Live Activities exclude auth and approvals (ST-UX-05).

## 4. Items that need legal or counsel review before production

1. E-class retention periods (ADR-0026 §1, spec §11.1), including the E-high/E-routine split, report retention, and key-log retention after deletion.
2. State consumer-privacy law (deletion and access exceptions for security evidence, "service provider" contract terms for Viadere as processor, notice at collection for the app and OIDC consent screens); any sector rules a customer business brings (financial, health, children).
3. COPPA/age handling for anonymous accounts (no age gate is specified in this program).
4. TCPA/CTIA treatment of SMS-01, SMS-02 and SMS-04, STOP/UNLINK wording, and consent-evidence retention (`sms_consent_events`).
5. Residency claim wording (S1-A10-3) and Cloudflare, MailerSend, APNs/FCM, Didit as sub-processors, including any cross-border transfer terms.
6. Controller/processor allocation and the DPA/sub-processor list (S1-A10-8).
7. Lawful-request procedure for authority logs and grants (spec §11).
8. OIDC consent record as a consent artifact, and the terms between Viadere as identity provider and relying parties.
9. Claims language: "phishing resistant", "private identifier", "we never send codes" must not be broader than the verified behavior.

## 5. Items to add to the next revision (checklist for the author)

- UX_COPY: S1-A9-1 to S1-A9-14 strings and ids (S-MFA-11, S-MFA-12, S-MFA-13, consent management, unlock, UNLINK confirmation, no-SIM fallback), vocabulary table, localization rules.
- ADR-0022: interruption level, number field behavior, no slide-to-approve, definition of equal prominence.
- ADR-0024: client display-name review, redirect host on the phone screen, consent list/revoke, `login_hint` exposure note.
- ADR-0026: E-high/E-routine, Role column, log allow-list rule, backups/key retirement, variables handling, residency definition and policy.
- ADR-0027: no content routing for `phone_control_mo`, keyed hashes, SMS-02 rewrite.
- DATA-INVENTORY: sub-processors and retention rows brought in line.

## 6. Sign-off

This is an agent review record by A9 and A10 (AI reviewers, not the Stage 1 author, 2026-11-02). It is an input to the Stage 1 gate and does not replace human sign-off, device validation (Stage 4), usability measurement (Stage 8) or legal counsel review.

Verdict: A9 APPROVE WITH CONDITIONS; A10 APPROVE WITH CONDITIONS (conditions: S1-A9-1 to S1-A9-5 and S1-A10-1 to S1-A10-4 resolved or formally accepted by the owner before the gate closes).
