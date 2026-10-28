---
title: Privacy Notice
order: 2
description: "What Viadere collects, why, who receives it, how long it is kept, and the rights you have over it."
version: 0.2.0
effective_date: ""
owner: "Privacy lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete layered notice with data tables, legal bases, retention by class, subprocessors, rights by region, biometric and California notices. Counsel decisions remain bracketed."
disclosures: [encryption, device_custody, age_verification]
---
This notice explains how Viadere handles personal information when you use the Viadere app, text the Viadere number, or connect to a business through Viadere. It is written to be read. A plain-language companion with the same facts is in the [Privacy Center](/privacy/).

::: callout
**Draft.** This notice has not been approved by counsel and has no effective date. Some products it describes are in beta or planned, and it says which. Text in square brackets is a decision that has not been made yet.
:::

## 1. At a glance

- **We carry requests, not a profile of you.** Viadere delivers sign-in approvals, purchase authorizations, messages, orders and rewards between you and verified businesses. It does not build an advertising profile, does not sell personal information and does not share it for cross-context behavioral advertising.
- **Businesses see a pseudonym, not you.** Each business sees a reference that is different for every business, the decisions you make and the messages you choose to send. It does not see your Viadere account identity or your phone number unless you give it to them yourself.
- **Your keys stay on your device.** Approval signing keys are created in your iPhone's Secure Enclave and never leave it. Viadere holds the public keys needed to check your decisions.
- **Consumer accounts have no email address and no password.** You sign in with a passkey. Your phone number is optional and is needed only to use Viadere by text.
- **Text messages are not private from carriers.** SMS is not end-to-end encrypted. Carriers and the messaging providers we use can read ordinary text messages. Anything that needs real assurance is moved into the app.
- **Identity and age checks are planned and optional.** If Verify launches, document images, selfies and liveness video go from your device directly to our verification provider, not to Viadere. Viadere keeps only the minimal result and asks the provider to erase the session.
- **Retention is set by data class.** Message text, interaction details and most records have stated maximum periods (section 12). Deleted data can remain in encrypted backups for up to 30 days.
- **You are in control.** You can download your data and delete your account from the app, disconnect from a business, change consent per purpose, reply STOP to texts, and contact us about any other right (section 16).

## 2. Who we are and what role we play

[COUNSEL: Viadere legal entity name, registered address, registration number and the contact details to publish here.] In this notice "Viadere", "we" and "us" mean that entity. Privacy contact: [PRIVACY-CONTACT-PLACEHOLDER]. [COUNSEL: whether a data protection officer is required and, if so, the name and contact. EU and UK representatives under GDPR Article 27 and UK GDPR, if required.]

Our role depends on the activity. This is the working position of the product team; counsel will confirm each row.

| Activity | Viadere's role | Notes |
|---|---|---|
| Your Viadere account, passkeys, devices, recovery, security notices and fraud and abuse prevention | Controller (a "business" under California law) | We decide why and how this data is used. |
| Your consent records and connections to businesses | Controller | We keep them so that you can see and change them, and as evidence of what you agreed to. |
| Sending requests and messages for a business, and carrying your replies and decisions back | Processor or service provider for the business, and controller of the delivery, security and abuse records we need to run the network | [COUNSEL: confirm the split. The business decides what to send you and why. Viadere decides how the network, its security and its abuse controls work.] |
| Loyalty, rewards and Wallet passes a business issues to you | Processor or service provider for the business; controller of your Wallet pass registration data | [COUNSEL: confirm.] |
| Signed approval decisions kept for disputes | Controller for the copy Viadere keeps; the business is a separate controller of the result it receives | [COUNSEL: confirm.] |
| Verify (planned): identity and age checks | Controller of the verification attempt and consent record; verification provider is our processor; the requesting business is a separate controller of the result it receives | [COUNSEL: confirm, and confirm joint controller analysis.] |
| Authenticator vault (planned) | Controller of account and sync metadata; we hold vault contents only as ciphertext we cannot open | [COUNSEL: confirm.] |
| Business dashboard users (people who work for a business) | Controller | Covered by the same notice; see section 5. |

Businesses are independent of Viadere. When a business sends you a message or a request, the business is responsible for what it says, why it contacted you and what it does with your reply. Read the business's own privacy notice for how it handles data it holds about you.

## 3. What we collect, by source

### 3.1 What you give us

- **Account details.** A display name you choose, and a passkey (we store its public key and a user handle). We do not collect a password or an email address for consumer accounts.
- **A phone number, if you link one.** Needed only to use Viadere by text. We confirm it with a one-time code. We store it encrypted, with a keyed hash for matching, a masked form and the last four digits.
- **Recovery material.** Ten single-use recovery codes and a recovery ID, shown once. We store only keyed hashes of them.
- **Messages and replies.** What you type to a business in the app or by text, and your answers to choices and prompts.
- **Consent choices.** Which purposes (security, account service, transactional, support, marketing, rewards) you allow for each business, with version and source.
- **Support requests and reports.** What you write when you contact us or report a suspicious request.
- **Verification inputs (planned).** If you choose Verify: an eligible ID in Apple Wallet, or a photo of an identity document, a selfie and liveness capture. See section 10.

### 3.2 What comes from your device and from using the app

- **Device records.** Device name you or the system provide, platform and kind (iPhone, Apple Watch, App Clip), enrollment time, cool-down and expiry state, and public keys for each purpose. On Apple devices we also record App Attest key identifiers and counters, which tell us that requests come from a genuine copy of the app.
- **Push tokens.** The Apple Push Notification service (APNs) token for each device, plus Live Activity tokens if you use Live Activities.
- **Wallet registration.** If you add a pass, the pass serial, a hashed authentication token, the device library identifier and a push token.
- **Approval activity.** Which requests were shown to which device, your answer, signed decisions, the answer time, and counts used to detect prompt fatigue (for example how many requests a business has sent you in an hour).
- **Camera.** The app uses the camera to scan QR codes. If you choose to scan an ID document for Verify, the camera also captures it, and a selfie, for that check only.
- **Face ID or passcode.** The operating system checks them on your device. Viadere never receives biometric data from Face ID or Touch ID.

We do not ask for your location. A business may include an approximate location of a sign-in or purchase in the request it sends you, which we pass on so you can decide.

### 3.3 What businesses send us about you

- **Requests and context.** What the business wants you to approve or answer: purpose, amount, merchant, approximate location, device or browser of the sign-in, expiry and similar details the business chooses to include.
- **Messages and updates.** Replies, order and delivery status, appointment and travel updates, ticket and pass content, reward offers and redemptions.
- **A reference to you.** Businesses address you by the pairwise reference (section 6), not by your Viadere identity.

### 3.4 What comes from our providers

- **Delivery status.** Whether a text, RCS message, push or email was delivered, failed or was blocked, with provider message identifiers. Carriers or the SMS provider can report opt-out signals (for example error 21610 from Twilio).
- **Verification results (planned).** From Didit: an approved or declined decision, whether liveness and face match passed, and the document's issuing country. From Apple Wallet: a presentation that we verify and reduce to the requested elements. See section 10.
- **Wallet and device signals.** From Apple, whether a pass was added or removed.

### 3.5 What we collect automatically when you connect

- **Network data.** Your IP address and request headers reach our edge (Cloudflare) and our servers. We use the address to rate-limit abuse and to detect attacks. We normalize IPv6 to a /64 range and use it as a limiter key. Rate-limit records are deleted when the limit window has passed. Server logs redact tokens, secrets and phone numbers.
- **Security audit events.** Who did what, when, and the outcome, in a tamper-evident log (section 11).
- **Usage counts per business.** Counts of messages and verifications for billing, without message content.

### 3.6 People who use the business dashboard

If you work for a business that uses Viadere we also collect your work email address (stored encrypted, with a hash for lookup), display name, passkey public key, role, sign-in sessions (with hashed and masked network details and the country), security contacts you provide, and records of what you accepted or approved in the console. Unverified sign-ups are deleted after 24 hours.

## 4. The data, in one table

The table is by category. "Retention" gives the longest period Viadere's system keeps the data before its automatic deletion job runs; section 12 explains the classes and the exceptions.

| Category | Examples | Source | Why we use it | Retention | Who receives it |
|---|---|---|---|---|---|
| Account | Display name, passkey public key and user handle, account status | You, your device | Run your account and sign you in | Until you delete the account | Hosting and database providers as processors |
| Phone number | Linked number (encrypted), keyed hash, masked form, last four digits | You | Deliver texts, confirm it is yours, suppress after STOP | Erased when you delete the account or unlink the number. Opt-out record is kept as suppression evidence | SMS and RCS providers, carriers |
| Devices and keys | Device name, platform, public keys, App Attest identifiers, enrollment and cool-down state | Your device | Check that decisions come from your devices, prevent takeover | With the device or account. Revoked device records are kept as cool-down evidence, names are blanked on account deletion | Hosting and database providers |
| Sessions and tokens | Hashed session and refresh tokens | Your device | Keep you signed in safely | Expired tokens 30 days after expiry | Hosting and database providers |
| Recovery | Hashes of recovery codes and ID | You | Let you regain access | With the account | None |
| Connections and consent | Which businesses you connected to, purposes allowed, versions | You | Enforce your choices, keep evidence | Current consent until account deletion. Superseded consent versions 1,095 days | The business sees only the current consent for its own relationship |
| Interactions | Request text, purpose, amount and context, status, your reply or choice | Business, you | Deliver the request and show you history | Content erased 400 days after the interaction finishes (shorter if the business sets a shorter period) | The business that sent it |
| Signed decisions | Device-signed approval, signature, assurance level | Your device | Prove what was approved, resolve disputes | 730 days, then deleted. Free-text replies erased when you delete the account | The business receives a compact signed result, not the raw device record |
| Messages | Text and attachments you and a business exchange | You, business | Deliver conversations, show history | Bodies replaced after 730 days (shorter if the business sets a shorter period) or when you delete the account | The business; SMS or RCS providers and carriers when the channel is text |
| Outbound delivery records | Phone ciphertext, channel, delivery status, provider message ID | Providers | Retry, order and troubleshoot delivery | Finished rows 30 days | SMS, RCS and email providers |
| SMS consent and opt-out | Phone hash, keyword (STOP and similar), time | You | Honor opt-outs and prove consent | Kept as suppression evidence. [COUNSEL: evidence period under TCPA and carrier rules] | None |
| Push and Live Activity tokens | APNs tokens | Your device | Deliver notifications | Removed when APNs reports the token invalid, and with the account | Apple |
| Rewards and loyalty | Program membership, points ledger, reward claims, redemption code hash | Business, you | Run rewards you joined | Until account deletion. Ledger entries kept for accounting [COUNSEL: period] | The business |
| Wallet passes | Pass serial, hashed token, registration, push token | Business, Apple | Issue and update passes | Until the pass is voided or you delete the account. Pass logs 7 days | Apple |
| Household and delegation | Grants, sealed labels, invitation code hash | You | Share access you choose to share | Until revoked, expired or account deleted | The household member you invite |
| Security audit events | Actor, action, outcome, internal IDs, redacted metadata | Our systems | Detect fraud, investigate incidents, show you security notices | 2,555 days, and only after the log's integrity head has been exported to write-once storage | Business sees a projection that shows only its own pseudonym for you |
| Network and abuse data | IP address (as a /64 range for IPv6), rate-limit counters, abuse signals | Automatic | Stop abuse and attacks | Rate-limit records deleted when the window passes. Per-business complaint counters 90 days | Cloudflare and Fly.io as processors |
| In-app security notices | New device, recovery started, suspicious request | Our systems | Warn you | 365 days (dismissed notices 90 days) | None |
| Support and appeals | Ticket text (sealed), status, operator note | You | Resolve your request | 730 days after closing | None |
| Verification (planned) | Request, minimized result, provenance, consent receipt, provider session ID | You, provider | Confirm an attribute you chose to share | Result payload erased after the business retrieves it or after 15 minutes. Records deleted after 400 days | Business receives the requested attribute only |
| Backups | Encrypted copies of the above | Our systems | Recover from failure | Point-in-time history 7 days, daily snapshots 30 days | Database provider |

[COUNSEL AND PRIVACY: the retention periods marked 400, 730 and 2,555 days are the defaults of the retention job and are being reviewed. They can be changed within stated bounds.]

## 5. What we do not collect or do

Each statement below was checked against the product's specifications and code at the date of this draft.

- **No advertising.** No advertising identifier is read, no cross-app tracking is performed, the app declares no tracking domains, and we do not show or sell advertising.
- **No selling and no cross-context behavioral advertising.** We do not sell personal information and do not share it for cross-context behavioral advertising.
- **No contacts or address book access.** The app does not ask for your contacts.
- **No location tracking.** The app does not ask for your device location.
- **No analytics or crash-reporting SDKs in the app.** The app and the website include no third-party analytics SDK. [PRODUCT: re-confirm before each release.]
- **No cross-business tracking.** Your pseudonym differs at every business. Businesses cannot compare notes to link you, and our business-facing audit views show only that business's own pseudonym.
- **No raw identity documents, birthdates or selfies on our servers.** If Verify launches, evidence goes to the verification provider and is not stored by Viadere.
- **No biometric templates held by Viadere.** Face ID and Touch ID run in the operating system.
- **No private keys.** We never hold your approval private keys or passkey private keys.
- **No plaintext phone numbers or message bodies at rest.** They are encrypted at the field level with row-bound keys.
- **No promotional messages that bypass consent.** Marketing is a separate consent from security and service messages.

## 6. What businesses receive

A business that you connect to receives:

- **A pairwise reference to you** (`subject_ref`). It is computed with a Viadere secret key from the business and your account, so it is stable for that business and unrelated to the reference any other business holds for you. It cannot be computed, reversed or enumerated without that key.
- **Your decisions.** Approve, deny, or the choice you made, with the time, the channel and the assurance level. For approvals the business receives a signed result from your device-held key for that business, not a raw record and no identifier shared with other businesses.
- **Messages and replies you send it**, and your consent state for its purposes.
- **For Verify (planned):** only the attribute you agreed to share, such as "meets the age threshold", with its provenance, validity period and the business as audience. Names and addresses are shared only if you explicitly approve that exact request.

A business does not receive your Viadere account identity, your phone number, your other connections, or your device identifiers, unless you tell it. What a business does with what it receives is governed by that business's own notice and its agreement with Viadere. Your business-facing audit views, exports and webhooks use the same pseudonym.

## 7. What stays on your device and what the server sees

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

**On your device**

- Approval signing keys, one per business relationship, in the Secure Enclave. Using them requires Face ID, Touch ID or your passcode, handled by the operating system.
- Your passkey private key.
- For the planned Authenticator: your third-party passkeys and one-time-code secrets in an encrypted vault.
- The private key for your data export, generated for each export and kept in the device Keychain until you read the file.

**On our servers**

- Account, device, relationship, consent and interaction records described in section 4.
- Public keys, signed decisions and audit events.
- Message bodies, phone numbers and other personal fields as ciphertext, with the encryption key held outside the database.
- For requests where the business uses end-to-end protection, an opaque envelope that we cannot read. Where the business uses server-visible mode, the request details are sealed in the database and cleared when the request ends.

Deleting data on our servers does not revoke a credential or record that a third party holds, such as an account at a business, a Wallet pass already on your phone or a passkey you registered at a website. You must remove those with the party that holds them.

## 8. How we use personal information, and our legal bases

We use personal information to:

1. Create and secure your account and devices.
2. Deliver, display and record requests, messages and your answers.
3. Keep consent records and enforce your choices, including opt-outs.
4. Detect and prevent fraud, abuse, impersonation and attacks, including rate limiting and per-business trust controls.
5. Keep tamper-evident records so that disputes about what was approved can be resolved.
6. Run rewards, passes, orders and similar features you use.
7. Bill businesses, meter usage and keep accounting records.
8. Operate, maintain and improve the service, fix errors and keep it available.
9. Respond to your requests and to legal process, and establish or defend legal claims.
10. Verify attributes you choose to share (planned).

Where the GDPR or UK GDPR applies, we rely on these bases. [COUNSEL: confirm each mapping and the legitimate-interest assessments.]

| Purpose | Data | Legal basis (GDPR Article 6, and Article 9 where noted) |
|---|---|---|
| Account, sign-in and device security | Account, devices, tokens, recovery | Contract (6(1)(b)) |
| Delivering requests and messages you asked to receive | Interactions, messages, delivery records, phone number | Contract (6(1)(b)). Marketing by text or RCS: consent (6(1)(a)), by purpose and business |
| Consent records and opt-out suppression | Consent events, phone hash | Legal obligation (6(1)(c)) and legitimate interest (6(1)(f)) in proving consent and honoring opt-outs |
| Fraud, abuse and security | Audit events, rate limits, abuse signals, IP ranges | Legitimate interest (6(1)(f)) in protecting users, businesses and the service |
| Dispute evidence | Signed decisions, audit events | Legitimate interest (6(1)(f)) of Viadere and businesses in proving what a device signed |
| Billing and accounting | Usage records, loyalty ledger | Contract (6(1)(b)) and legal obligation (6(1)(c)) |
| Operating and improving the service | Operational logs | Legitimate interest (6(1)(f)) |
| Identity or age verification (planned) | Verification inputs and results | Consent (6(1)(a)); explicit consent (9(2)(a)) for biometric data used to identify you, with a non-biometric alternative where Apple Wallet can be used [COUNSEL: confirm] |
| Responding to requests, legal process, claims | Relevant records | Legal obligation (6(1)(c)); legitimate interest (6(1)(f)) |

Where we act as a processor for a business, the business determines the legal basis for its own communications and we process under its instructions.

## 9. Messaging, SMS and push notifications

**Text messages (SMS) and RCS.** You can use Viadere by texting its number, and a business may reach you through that same thread. We keep a state record of the conversation (for example which menu is active and which business you are connected to) so that a reply goes to the right place. Business text is shown with the business's name.

- SMS is not end-to-end encrypted. Carriers, the SMS provider (MailerSend, or Twilio as an alternative), and others on the route can read ordinary text messages. We never ask you to approve a sensitive action by text.
- Messages are sent from a shared Viadere number, so the sender number alone does not prove who is texting. Security-sensitive requests are replaced with a secure link to the app.
- **Opt out and help.** Reply STOP (or STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT, OPTOUT, REVOKE) to opt out in any state. Reply HELP or INFO for help. Reply START, UNSTOP or YES only to resume after an opt-out. Standard message and data rates may apply. See the [Messaging Consent and Content Policy Addendum](/legal/messaging-consent-content-policy-addendum/).
- **What providers keep.** The SMS or RCS provider keeps message content and delivery records under its own terms. See the [Subprocessors](/legal/subprocessors/) list. [COUNSEL: provider retention periods, to be confirmed with each provider.]
- Messaging and Approve are in beta. RCS is not yet available.

**Push notifications.** Notifications travel through Apple's push service (APNs). They include the text needed to display the notification, such as the business name and a short summary of the request. Apple processes them under its own terms. You control notifications in iOS settings and Focus. By default Viadere interrupts you only when action is required, and Live Activities are used only for ongoing events and never for marketing, rewards or security.

**Email.** Consumer accounts have no email address. We send email to business dashboard users, such as sign-in codes and invitations, through our transactional email provider.

## 10. Identity and age verification (Verify, planned)

Verify is planned and not available. This section describes how it is designed so you can review it in advance.

::: disclosure
Where supported, Viadere can confirm that a person meets a specified age threshold without disclosing their date of birth. Availability and legal sufficiency vary by jurisdiction and service.
:::

**What happens.** A business asks Viadere to confirm one attribute about you, such as "18 or older". Your app shows the business, the purpose, exactly what would be shared and what would not, and the expiry. Nothing happens unless you consent. Your consent is recorded as a receipt that contains no attribute values.

**Two methods.**

1. **Apple Wallet ID.** You present an eligible ID from Apple Wallet. Viadere's server decrypts the presentation in memory, checks the issuer's signature, reduces it to the requested element (for an age check, only the yes or no for the threshold), and does not store or log the presentation. Apple and the issuing authority do not learn where you shared your ID, by Apple's design.
2. **Identity document and liveness check by Didit.** If you have no eligible Wallet ID, you can choose a check run by our provider, Didit. The camera captures your ID document, a selfie and liveness video on your device, and they are sent directly to Didit. Viadere does not receive the images, video or biometric data. Didit processes them to check the document, confirm a live person and compare the face with the document photo. This can involve biometric data. A selfie-based age estimate on its own is never reported as a verified age.

**Biometric data and your consent.** For the Didit method we ask for your explicit consent before capture, in the app, with the purpose and retention described here. The inventory shows no face template is retained at Didit: biometric-template retention is switched off, the session is erased after Viadere reads the result, and Didit's own retention window is set to the shortest its account allows as a backstop. [COUNSEL: BIPA written release and public retention schedule, GDPR Article 9(2)(a) explicit consent text, Texas, Washington and other biometric statutes; whether Didit or Viadere is the "private entity" in possession; Didit contract and residency.] You can decline and use Wallet where available, or not use Verify. Declining never affects your account, messaging or approvals.

**What Viadere keeps.** The request and result record, the method, the verifier, the policy version, the expiry and the provider's opaque session ID, with no names, birthdates, document numbers, images or scores. The result payload is erased when the business retrieves it once or after 15 minutes, whichever is first. Request records are deleted after 400 days. After each Didit check we delete the session and the provider's user record and record that we did, retrying until it succeeds and alerting if it is overdue.

**What the business gets.** Only the attribute requested. The default is a threshold result. A name or address is disclosed only if the business is cleared for that capability and you approve that exact request, and, if the business has published a key, it is sealed so that Viadere cannot read it.

**Limits.** A result describes the attribute and assurance evaluated. It is not a universal guarantee of identity or eligibility and does not automatically satisfy a business's legal duties. Wallet credential revocation status is not checked today. We treat a person as of age only after the threshold date has passed everywhere in the world, so there can be up to 12 hours of delay.

**Regional limits.** Rules for biometrics, age assurance and government ID differ by place. Verify will be offered only where counsel has cleared it. [COUNSEL: launch jurisdictions and the privacy impact assessment status for government ID, biometric verification and age assurance.]

## 11. Security

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

We use these measures, described further in the [security overview](/security/):

- **Encryption in transit.** TLS 1.3 preferred; TLS 1.2 is accepted only with modern authenticated cipher suites under a reviewed compatibility policy.
- **Encryption at rest.** The database provider encrypts storage. On top of that, sensitive fields (phone numbers, message bodies, request details, webhook secrets, dashboard emails) are encrypted with AES-256-GCM using keys bound to the table, column and row. Tokens, API keys and recovery codes are stored only as keyed hashes. Service keys are protected in Google Cloud KMS hardware-backed keys.
- **Device-held keys.** Approval keys live in the Secure Enclave and require user presence for sensitive actions. Biometrics authenticate you to your device; they do not tell us who you are.
- **Where end-to-end encryption applies.** For approvals where the business enrolls a key, for Verify identity results sealed to a business key, for your data export, and for the planned Authenticator vault, content is sealed to the recipient and Viadere cannot read it. It does not apply to ordinary SMS, to routing and delivery metadata or to requests sent in server-visible mode.
- **Tamper-evident audit.** Audit events are chained with a keyed hash, and the chain head is exported on a schedule to write-once storage.
- **Abuse controls.** Rate limits, new-device cool-downs, prompt-fatigue limits, a freeze control, and suspicious-request reporting.
- **Access control.** Least-privilege roles, passkey-only sign-in for staff, tenant isolation and separate deployment credentials.
- **Testing.** We run security tests that reproduce known attacks, and publish a [vulnerability disclosure policy](/legal/vulnerability-disclosure-policy/).

No system is perfectly secure. See the [Incident Notification Policy](/legal/incident-notification-policy/) for how we tell people about incidents.

## 12. Authenticator vault (planned)

The Authenticator is planned and not available. It is designed to hold your third-party passkeys and one-time-code secrets. Private keys and secrets are encrypted on your devices. If you turn on optional sync, the server stores only ciphertext, signed public structures and public keys: it never receives a key that can open the vault.

What the server can still see: how many items you have, when they change, their sizes in 256-byte steps, how many devices are enrolled, whether a recovery key is set, and when joins, recoveries and restores happen. It does not see contents, names, websites or device names. If you turn on "Suggest in AutoFill", the iOS system's AutoFill store receives the site, account name and credential ID so it can offer them.

Recovery uses a 256-bit recovery key shown once. A recovery from a new device is held for 72 hours and every other device is told, so you can cancel. Viadere cannot recover a vault or non-exportable keys for you, and identity verification never unlocks a vault. Removing a device rotates the vault key, but a removed device keeps what it already copied. See the [Credential Vault Terms](/legal/credential-vault-terms/).

## 13. How long we keep data

Retention is set by data class in a documented inventory, enforced by an automatic job that runs at least every minute and is limited to a stated minimum and maximum for each class. The table shows the platform default in days, with the allowed range. A business can shorten (never lengthen) the periods marked for its own data. A legal hold, requested by a court or regulator or needed for a claim, suspends deletion of held records.

| Class | What is deleted or erased | Default (range) in days |
|---|---|---|
| Interaction content | Request text, reply and signed decision of finished interactions. The row, IDs and status remain | 400 (30 to 1,095) |
| Conversation content | Message bodies, replaced by `[expired]` | 730 (30 to 3,650) |
| Signed decisions | Device-signed decisions | 730 (365 to 2,555) |
| Consent history | Superseded consent versions. The current consent is never deleted by this job | 1,095 (365 to 3,650) |
| Audit events | Events past the period and covered by an exported integrity head | 2,555 (730 to 3,650) |
| Business applications | Free text of decided applications | 730 (90 to 3,650) |
| Usage records | Metering rows | 2,555 (365 to 3,650) |
| Webhook deliveries | Event deliveries and their attempts | 30 (1 to 365) |
| Outbound messages | Finished text and channel sends | 30 (1 to 365) |
| Link tokens | Used or expired account-link tokens | 7 (1 to 90) |
| Security tokens | Expired session tokens and challenges | 30 (7 to 180) |
| Channel capability | RCS capability cache, postbacks, provider de-duplication markers | 180 (14 to 730) |
| Security notices | In-app notices | 365 (30 to 1,095) |
| Support records | Closed tickets, finished notices, decided approvals and data requests, expired exports | 730 (90 to 3,650) |

Other rules:

- **Account deletion.** When you delete your account we revoke all sessions and devices, delete passkeys, erase phone numbers, text thread state, message bodies, interaction payloads and replies, household labels, loyalty member references and webhook delivery bodies about you, and delete your verification requests and results. Signed decisions are kept without personal content so they remain verifiable; only a free-text reply inside one is erased. Records that identify no one except by pseudonym, such as audit events, may remain for the audit period. An opted-out number keeps a record that only suppresses further texts.
- **Backups.** Deleted data can remain in encrypted backups until they age out: point-in-time recovery history is 7 days and daily snapshots are 30 days.
- **Server logs.** Operational logs are redacted and kept for a short period. [PRIVACY: confirm log retention with the hosting provider; the inventory lists about 7 days to be verified.] Key-management audit logs are kept for 400 days.
- **Law.** We may keep data longer where a law, tax or accounting rule, or a legal claim requires it. [COUNSEL: set the final period for each class, in particular signed decisions, audit events, consent evidence and SMS opt-out evidence.]

## 14. Who we share data with

We share personal information only as described here.

- **Businesses you connect to**, as described in section 6.
- **Service providers (subprocessors)** that process data for us under contract. They may use it only to provide their service to us. The current list follows and is also on the [Subprocessors](/legal/subprocessors/) page.
- **Apple**, for push delivery, Wallet and App Attest, under Apple's terms.
- **Carriers and messaging networks**, which carry text messages.
- **Legal and safety.** To comply with law or valid legal process, to protect rights, safety and security, and to enforce our terms. See the [Law-Enforcement Request Policy](/legal/law-enforcement-request-policy/).
- **Corporate transactions.** If Viadere merges, is acquired or sells assets, your information may transfer under commitments no weaker than this notice. [COUNSEL: confirm wording.]

We do not sell your personal information and we do not share it for cross-context behavioral advertising.

| Subprocessor | Purpose | Data | Location |
|---|---|---|---|
| Fly.io | Application hosting | All service data in transit and in memory; logs | United States, Ashburn Virginia region |
| Cloudflare | DNS, edge network, web application firewall, website hosting | Network data and request traffic; the website | Global edge network |
| Neon | Managed PostgreSQL database and backups | All stored service data, with sensitive fields encrypted before storage | United States, AWS us-east-1 |
| Google Cloud (KMS) | Hardware-backed key management | Keys and wrapped keys only; no personal data | United States, us-east1 |
| MailerSend | Transactional email and SMS (US and Canada) | Email address and codes of business dashboard users; phone numbers and text content | [COUNSEL: confirm processing locations] |
| Twilio | Alternative SMS provider | Phone numbers and text content | [COUNSEL: confirm if used] |
| RCS provider | RCS business messaging (provider not yet chosen) | Phone numbers and message content | [COUNSEL: when selected] |
| Apple | Push (APNs), Wallet passes, App Attest | Push tokens and notification text; pass data; device attestation | Global |
| Didit | Identity document and liveness verification, only if Verify is enabled and you choose it | ID images, selfie, liveness video and results during one check | EU by default [COUNSEL: confirm residency and DPA] |

Write-once storage for audit integrity heads (Google Cloud Storage or Cloudflare R2) holds hashes only, not personal data.

## 15. International transfers

Viadere's servers and its main subprocessors are in the United States. If you use Viadere from outside the United States, your information is transferred to and processed in the United States. Didit processes verification sessions in the European Union by default, and some providers process data in other countries.

Where the GDPR or UK GDPR applies, we use a transfer mechanism that provides appropriate safeguards. [COUNSEL: choose per region: EU-US Data Privacy Framework participation of each provider, Standard Contractual Clauses (modules), the UK International Data Transfer Addendum or Agreement, Swiss addendum, and transfer impact assessments.] You can ask for a copy of the safeguards by contacting us.

## 16. Your rights and how to use them

### 16.1 What you can do in the app

- **Download your data.** Settings, Download my data. The file is encrypted to a key held only on your iPhone, so Viadere cannot read it. It is available for 7 days.
- **Delete your account.** Settings, Delete account. See section 13 for what that erases.
- **Manage connections and consent.** Disconnect from a business, and change consent by purpose. Revoking marketing never turns off security notices.
- **Manage devices.** See your devices, remove one, and freeze approvals for your account or for one business.
- **Stop texts.** Reply STOP.

### 16.2 Your rights by region

The rights below depend on where you live. We apply them to everyone as far as we can, and say where we cannot.

**GDPR and UK GDPR (European Economic Area, United Kingdom and similar):**

- Access, rectification, erasure, restriction of processing, data portability, and objection to processing based on legitimate interests.
- Withdraw consent at any time, without affecting earlier processing.
- Not be subject to a decision based solely on automated processing with legal or similarly significant effects (section 19).
- Complain to your supervisory authority: [COUNSEL: lead authority, and the list of local authorities, including the UK Information Commissioner's Office].

**California (CCPA and CPRA):**

- Know the categories and specific pieces of personal information we collected, the sources, purposes and recipients.
- Delete, and correct, personal information we hold about you, subject to exceptions.
- Opt out of the sale or sharing of personal information. We do not sell or share personal information, so there is nothing to opt out of. [COUNSEL: confirm including for any future analytics.]
- Limit the use of sensitive personal information. We use sensitive personal information only to provide the service you asked for and for the security, integrity and legal purposes the law allows. [COUNSEL: confirm that no use requires a right-to-limit link.]
- Not be discriminated against for using these rights.
- Use an authorized agent (we may ask you to confirm the agent's authority and your identity) and appeal a decision about your request.
- Request information about disclosures for direct marketing by third parties: we make none.

**Virginia, Colorado, Connecticut, Texas, Oregon, Utah, Montana and other US states with comprehensive privacy laws:** access, correct (where provided), delete and obtain a copy of your personal data; opt out of targeted advertising, sale and profiling in furtherance of decisions with legal or similarly significant effects (we do none of these); and appeal a refusal. We do not process sensitive data for the purposes that require opt-in consent unless you choose Verify. [COUNSEL: applicability thresholds, and a state-by-state table.]

**Illinois (BIPA) and other biometric laws:** see section 10 and the biometric notice below.

**Nevada:** we do not sell covered information.

### 16.3 How to make a request

Use the in-app tools above where they fit. For anything else write to [PRIVACY-CONTACT-PLACEHOLDER]. Because consumer accounts have no email address, we may ask you to make a request from the app, from your trusted device, or by replying from the linked phone number, so that we can be sure it is you. We may ask for enough information to find your records and verify you, and we do not ask for a government ID unless nothing else works. We will not ask you for a password, a code or an approval by text or email.

If you use an authorized agent, tell us in writing. Businesses hold their own records about you: ask the business for what it holds. Where Viadere acts as a processor for a business, we may refer your request to the business, as the law allows.

### 16.4 When we respond, and appeals

We confirm receipt promptly and respond within one month under the GDPR and UK GDPR (extendable by two months where permitted), and within 45 days under US state laws (extendable once by 45 days). If we refuse, we tell you why. You may appeal by replying to our decision or writing to [PRIVACY-CONTACT-PLACEHOLDER] with "Appeal" in the subject. We respond to appeals within 60 days. If you are still dissatisfied, you may contact your state attorney general or the supervisory authority above. [COUNSEL: appeal and response period per state; appeal address.]

We do not charge a fee for requests unless they are manifestly unfounded or excessive, as the law allows.

### 16.5 Limits on deletion

We may keep data we need for a legal duty, to detect fraud or security incidents, or to establish or defend a legal claim. Signed decisions and audit events are kept, in minimized form, for the periods in section 13 so that disputes can be resolved. Deleting data on our servers is not the same as revoking a credential held by a third party (section 7).

## 17. Biometric information notice

This notice applies only if Verify launches and you choose the document and liveness method.

- **What may be collected:** a photo of your ID document, a selfie and liveness video, and face-matching data derived from them, by Didit on Viadere's behalf.
- **Purpose:** to confirm that the document is genuine, that a live person is present and that the face matches the document, so that Viadere can confirm an attribute you agreed to share.
- **Who holds it:** Didit, as our processor, only for the duration of the check. Viadere does not receive the images, video or templates.
- **Retention and destruction:** the session is deleted after the result is read, with the provider's user record. Template retention is switched off. Provider retention is configured to the shortest the account allows as a backstop. [COUNSEL: publish a retention schedule and destruction guidelines as required by Illinois BIPA and similar laws, and state the maximum interval.]
- **Consent:** we ask for your written consent (an electronic acknowledgment in the app) before collection. [COUNSEL: BIPA written release text.]
- **No sale, no profit:** we do not sell, lease or trade biometric information.
- **Alternative:** you can use an Apple Wallet ID where available, or not use Verify.

## 18. Children

Viadere is not directed to children under 13, and we do not knowingly collect personal information from children under 13. [COUNSEL: set the minimum age: 13 in the United States, 16 where required by the GDPR (national variations 13 to 16), and whether an age gate is needed; the app does not currently check age at sign-up.] If you believe a child has given us personal information, contact [PRIVACY-CONTACT-PLACEHOLDER] and we will delete it. Verify age checks are used by businesses to assess whether someone meets a threshold; they are not a means of collecting information from children. [COUNSEL: COPPA, state age-appropriate design codes, the UK Children's Code.]

## 19. Automated decisions

We use automated tools to protect the service: rate limits, new-device cool-downs, prompt-fatigue limits, suspension of abusive businesses, and abuse signals such as complaint and opt-out rates per business. A request that breaches a limit is delayed or refused. These tools do not make decisions with legal or similarly significant effects about you, and nothing is decided about you solely by automated means in a way that affects your legal rights. Businesses, not Viadere, decide whether to grant access or complete a purchase after your approval. A Verify result is a factual check on one attribute; if a business takes a significant automated decision based on it, that is the business's decision. You can ask for a human to review any decision about your account by contacting us.

## 20. Our website, cookies and similar technologies

The viadere.com website sets no cookies, runs no scripts, uses no analytics or advertising trackers, uses no browser storage and loads no fonts, images or code from other companies. Cloudflare serves the site and, like any web host, receives your IP address and request headers to deliver it. This is stated in the [Cookie Notice](/legal/cookie-notice/). The business dashboard uses essential session storage described there. The app does not use cookies or advertising identifiers.

## 21. Changes to this notice

When we make a material change we will update the version and date, keep earlier versions at stable addresses, and tell you in the app before the change takes effect. If we need your consent for a new use, we will ask. [COUNSEL: advance notice period.] This is version 0.2.0, a draft with no effective date.

## 22. Contact, representatives and complaints

Privacy contact: [PRIVACY-CONTACT-PLACEHOLDER]. Postal address: [COUNSEL: entity address]. Data protection officer: [COUNSEL: name and contact, if appointed]. EU and UK representatives: [COUNSEL: if appointed].

You may complain to a supervisory authority. Contact details of some authorities:

| Region | Authority | Contact |
|---|---|---|
| United Kingdom | Information Commissioner's Office | ico.org.uk |
| European Union | The data protection authority of your member state of residence, place of work or the alleged infringement | edpb.europa.eu lists each authority |
| Switzerland | Federal Data Protection and Information Commissioner | edoeb.admin.ch |
| Canada | Office of the Privacy Commissioner of Canada | priv.gc.ca |
| United States | Your state attorney general; for California, the California Privacy Protection Agency and the Attorney General | Your state's website |

[COUNSEL: lead supervisory authority, if a one-stop-shop applies, and the authority for any other launch region.]

## 23. California notice at collection

This section is the notice at collection for California residents, and supplements the rest of this notice. It describes, for each category of personal information, the sources, the purposes, who receives it and how long we keep it. It also explains your California rights.

### 23.1 Categories of personal information, sources, purposes, recipients and retention

| CPRA category | What we collect | Sources | Purposes | Recipients (categories) | Retention |
|---|---|---|---|---|---|
| Identifiers | Display name, passkey user handle, pairwise reference, device and push identifiers, IP address, phone number if linked, dashboard user email | You, your device, businesses, our systems | Account, delivery, security, abuse prevention | Businesses you connect to (pairwise reference only); hosting, database, edge, SMS, email and push providers | Account life; tokens 30 days after expiry; rate-limit records until the window passes |
| Customer records (Cal. Civ. Code 1798.80(e)) | Display name, phone number | You | Account and delivery | Hosting and database providers; SMS provider (number) | Until account deletion |
| Commercial information | Rewards, points ledger, redemption records, order and purchase context businesses send | Businesses, you | Run rewards and requests you use | The business concerned; hosting and database providers | Until account deletion; ledger [COUNSEL: period] |
| Internet or network activity | Request metadata, rate-limit counters, abuse signals | Automatic | Security and reliability | Edge and hosting providers | Rate-limit data short-lived; abuse counters 90 days |
| Geolocation | Approximate location a business places in a request. We do not collect device location | Businesses | Showing you context to decide | Your device; hosting and database providers | With the interaction (400 days default, then erased) |
| Audio, electronic, visual information (planned) | Selfie and liveness video for Verify, held only by our provider | You | Verification you choose | Didit | Session deleted after the check |
| Professional or employment information | For dashboard users: employer, role | Business dashboard users | Run the console | Hosting and database providers | While the user is a member |
| Inferences | None used to build a profile of you | Not applicable | Not applicable | Not applicable | Not applicable |
| Sensitive personal information | See section 23.2 | See 23.2 | See 23.2 | See 23.2 | See 23.2 |

### 23.2 Sensitive personal information

| Sensitive category | Do we collect it? | Purpose | Recipients | Retention |
|---|---|---|---|---|
| Account log-in with credentials | Passkey public key and hashed tokens. We never hold the passkey private key or a password | Sign you in | Hosting and database providers | Account life |
| Contents of mail, email and text messages where we are not the intended recipient | Yes, for text and RCS threads we carry (SMS or RCS content passes through us and our providers) | Deliver the message | The business you chose; SMS and RCS providers; carriers | Outbound rows 30 days; bodies 730 days by default; erased on account deletion |
| Government identifiers (driver licence, ID number) | Planned, Verify only. Read in memory from Wallet or by Didit. Viadere stores none | Verify an attribute you choose to share | Didit; Apple (Wallet) | Not stored by Viadere |
| Biometric information for identification | Planned, Verify document method only, held by Didit. Viadere receives none | Verify | Didit | Session erased after the result is read |
| Precise geolocation | No | Not applicable | Not applicable | Not applicable |
| Racial or ethnic origin, religious beliefs, union membership, health, sex life, genetic data | Not requested. A message you send a business could contain such information; we do not use it for any purpose other than delivering it | Delivery only | The business; providers | As messages |
| Financial account details | Not collected by us. A business may show an amount or merchant in a request | Show you the request | Your device; hosting providers | With the interaction |

We use sensitive personal information only to provide the services you request, to detect security incidents and resist fraud, to ensure safety, to carry out the functions described and for the other purposes California regulations (11 CCR 7027(m)) permit. We do not use or disclose it to infer characteristics about you. Because of this, we do not offer a "Limit the Use of My Sensitive Personal Information" link. [COUNSEL: confirm.]

### 23.3 Sale, sharing and disclosure for a business purpose

We have not sold or shared personal information for cross-context behavioral advertising in the preceding 12 months and we do not do so. We have no actual knowledge that we sell or share the personal information of consumers under 16.

Viadere is in beta and has not formally launched. In the preceding 12 months, based on current operation, we disclosed the following categories for a business purpose: identifiers, customer records, commercial information, internet or network activity, geolocation (approximate, as supplied by a business) and sensitive personal information (message content and credentials) to the recipient categories in the tables above. [COUNSEL: update this statement at the date the notice takes effect.]

### 23.4 Notice of financial incentive

We do not offer financial incentives or price or service differences in exchange for personal information. Viadere is free for consumers. A business may offer you a reward or offer through Viadere; that is the business's program and is subject to the business's own terms. [COUNSEL: confirm; if a program changes this, add the required notice, material terms, good-faith estimate of value and opt-in and withdrawal instructions.]

### 23.5 Your California rights

You have the right to know, delete, correct, opt out of sale and sharing, limit use of sensitive personal information, and not be retaliated against, as described in section 16. Submit a request in the app or to [PRIVACY-CONTACT-PLACEHOLDER]. You may use an authorized agent. We will verify your request by matching it to information we hold, which may include a request from your trusted device or the linked phone number, and respond within 45 days (extendable once by 45 days). You may make two requests to know per 12 months. We will say if a request is denied and why.

### 23.6 California "Shine the Light"

California Civil Code section 1798.83 lets California residents ask for information about personal information disclosed to third parties for their direct marketing. We do not disclose personal information to third parties for their direct marketing purposes. You may ask at [PRIVACY-CONTACT-PLACEHOLDER].

### 23.7 Minors in California

If you are under 18 and a California resident and have posted content through Viadere, you may ask us to remove it. Viadere does not offer a public posting feature. [COUNSEL: confirm applicability of Cal. Bus. & Prof. Code 22581.]

## 24. Nevada

Nevada residents may opt out of the sale of certain covered information. We do not sell covered information as Nevada law defines "sale". To ask a question, write to [PRIVACY-CONTACT-PLACEHOLDER].

## 25. Do Not Track and Global Privacy Control

The website sets no cookies and runs no scripts, so there is nothing for a Do Not Track or Global Privacy Control signal to switch off. We nonetheless treat a browser's Global Privacy Control signal, and any Do Not Track signal, as a valid request to opt out of sale and sharing, which we do not do. The app does not track you across other companies' apps and websites; its Apple privacy manifest declares no tracking and no tracking domains.

## 26. If there is a data security incident

If an incident affects your personal information in a way that creates a legal duty to notify you, or that creates a risk to you, we will tell you without undue delay and as the law requires. Where we process data for a business, we notify that business under our agreement with it. We will describe what happened, what data was involved, what we have done, what you can do and who to contact. Because consumer accounts have no email address, we may notify you by an in-app notice, a push notification, a text from the Viadere number or a notice on our [status page](/status/). We will never ask you for a password, code or approval in a notice. See the [Incident Notification Policy](/legal/incident-notification-policy/). [COUNSEL: statutory notification periods by jurisdiction.]

## 27. Language and accessibility

This notice is provided in English. [COUNSEL: translations and the governing language.] If you need it in another format, contact [PRIVACY-CONTACT-PLACEHOLDER]. See our [Accessibility Statement](/legal/accessibility-statement/).
