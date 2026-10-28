---
title: MFA and Approval Services Addendum
order: 9
description: "Key enrollment, signature validation, request protection, fallback, dispute handling and responsibilities for Approve."
version: 0.2.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete addendum covering enrollment, request protection modes, signed results and mandatory validation, replay, assurance limits, fallback, fatigue and freeze controls, disputes and evidence, retention, availability, responsibility and liability."
disclosures: [mfa]
---
::: draft-notice
**Draft for counsel review.** This addendum is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This MFA and Approval Services Addendum (the "**Approve Addendum**") is part of the [Business Services Agreement](/legal/business-services-agreement/) between [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") and the business that accepted it ("**Customer**"). It applies to Customer's use of Approve, Viadere's service for delivering authentication and transaction-authorization requests to Consumers and returning their signed decisions. It applies only if Customer has been approved for Tier A. Approve is a beta feature.

## 1. Definitions

- "**Approval Key**" means the pairwise key that a Consumer's device creates, in its Secure Enclave, for one relationship with Customer, used to sign decisions.
- "**Approval Result**" means the compact signed statement (a JWS) that the device produces for a request, containing the decision.
- "**Approval Request**" means a request from Customer for a Consumer to approve, deny or report an authentication or a transaction.
- "**Capability**" means `auth.challenge` (a sign-in or similar challenge) or `transaction.approve` (authorization of a transaction or action).
- "**Enrollment**" means the process by which a Consumer's device creates an Approval Key for Customer and Customer confirms it.
- "**Relay**" means Viadere's service that carries requests and results between Customer and the Consumer's device.
- "**Server-visible mode**" and "**end-to-end mode**" have the meaning in section 4.
- "**Subject Reference**" means the pairwise identifier that Viadere gives Customer for a Consumer.

## 2. Role of each party

### 2.1 What Viadere does

Viadere delivers Approval Requests to the Consumer's registered devices, shows them in a native notification or app flow, enforces rate and fatigue limits, receives the signed result from the device and makes it available to Customer, and records the outcome.

### 2.2 What Customer remains responsible for

::: disclosure
Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.
:::

Customer is authoritative for granting access, completing a transaction or taking any action. Customer is responsible for deciding what to request approval for, for the risk model around it, for the contents it displays, for validating the Approval Result itself, and for any decision it takes. Viadere does not process payments, does not hold the Consumer's funds or account and is not a party to the Consumer's transaction.

## 3. Key enrollment

### 3.1 Customer-authorized enrollment

A Consumer's device creates an Approval Key for Customer only at an enrollment that Customer authorizes, for a Consumer whom Customer already knows and who has connected to Customer. Customer creates the enrollment through the Business API, which returns a single-use code. Customer shows a link or QR code from its own authenticated session. The code is valid for [10] minutes (at most 15) and at most three enrollments can be open at once for a relationship. Viadere's Relay is not trusted to bind a device's key to Customer.

### 3.2 Customer's verification

When the device completes the enrollment, Customer must: (a) fetch the enrollment statement; (b) verify its signature with the key in the statement; (c) check that the business, Subject Reference and enrollment identifiers match what Customer created; (d) check that the assurance level meets what Customer required; (e) authenticate the origin of the statement using the enrollment secret that only Customer and the Consumer's app hold, through the binding tag (link or QR) or the short authentication string (typed code) described in the Documentation; and (f) only then confirm the enrollment with a signed confirmation. A statement that fails the check must be rejected, which cancels the enrollment. An unconfirmed key is revoked by Viadere after the enrollment's expiry and a short grace period, and Customer is alerted.

### 3.3 Enrollment security

Customer must keep the enrollment secret and check codes confidential, must never send them by SMS or email, must not read them out over a call, must display the link only in its own authenticated session, must use the Viadere SDK to build the link, and must not display a link supplied by Viadere's Relay. Customer must publish and maintain its confirmation and request-signing keys in the authenticated key directory.

### 3.4 Key properties

An Approval Key and the Subject Reference exist for one relationship, and no value is shared across businesses or derived from a device or account key. Customer receives the public key and its key identifier, and never a device identifier. Keys can be revoked by the Consumer, by Customer, by device revocation, by disconnecting from Customer and by account deletion. Customer must check its own record for each result, and must treat a revoked key as invalid.

### 3.5 Key rotation and loss

If a Consumer replaces a device, a new Approval Key is enrolled; a new device passes through a cool-down period before it can approve high-risk requests. Customer must support re-enrollment and key revocation events, which Viadere sends by webhook, and must not silently recreate prior keys.

## 4. Request protection modes

### 4.1 End-to-end mode

In end-to-end mode, Customer signs the exact content that the Consumer will see with a key published in the key directory, seals it to the device's key with HPKE, and sends the envelope through the Relay. The device decrypts it, checks that the signer is a valid published key of Customer, checks the business, subject, key identifier, request identifier and expiry, and shows it only if all pass. Viadere cannot read or alter such a request. In end-to-end mode Viadere's Relay cannot check the transaction digest, so the check is Customer's.

### 4.2 Server-visible mode

Customers who cannot encrypt may send requests in server-visible mode, with the challenge and the transaction or authentication details in the clear. In this mode Viadere's systems can read the request details, which are sealed in Viadere's database and cleared when the request ends. The app labels such a request to the Consumer as one that Viadere passed on and could read, and that is not signed by the business. A relay could invent a prompt in this mode, but not an authorization: the result is still signed by the Approval Key and must be verified by Customer against the pending request that Customer itself created.

### 4.3 Choice and fallback between modes

Customer chooses the mode. For high or critical risk, Customer should use end-to-end mode. Viadere may require end-to-end mode for certain Capabilities or tiers. [PRODUCT: policy for high and critical risk.]

### 4.4 Display content

Customer is responsible for the accuracy of the displayed content: business name, amount and currency, payee, action, location, device, expiry and effect of approval. The Services reject display text that contains hidden or control characters or that impersonates Viadere or another business. Customer will not use a request to carry marketing or unrelated content.

## 5. Signed results and mandatory validation

### 5.1 The result

For each request, the device produces an Approval Result, a compact JWS signed with the Approval Key using ES256, that contains the audience (Customer's identifier), the Subject Reference, the request identifier, the challenge, the Capability, the decision (approve, deny or report), the authentication method (biometric or device passcode), the issue and expiry times (at most 600 seconds, normally 300) and a digest of the displayed transaction.

### 5.2 What Customer must verify

Before acting on an approval, Customer must verify the Approval Result itself, against its own records and never against the Relay's status, and must check at least: (a) that the result parses strictly, with only the expected header parameters and algorithm; (b) that the key identifier is an active key that Customer enrolled and confirmed for exactly this Subject; (c) the signature, with the key that Customer recorded and not with a key supplied with the result; (d) that the audience is Customer and the Subject, request identifier, challenge and Capability equal the pending request Customer created; (e) that the transaction digest equals the digest of the transaction that Customer itself holds, so that a changed amount, payee, currency or reference fails; (f) that the times are valid and not after the request's expiry; (g) that the decision is "approve"; (h) that the authentication method meets Customer's minimum and does not exceed what the enrolled key can provide; and (i) that the result has not been used before, by recording the audience, key identifier and challenge in a replay guard in an atomic way, after all other checks pass.

### 5.3 Relay status is not evidence

The Relay's status field is information for the user experience. Delivery of a request, a Relay status or a webhook event alone is not evidence of approval. An approval for which Customer did not verify the Approval Result is at Customer's risk.

### 5.4 Retrieval

Customer retrieves the result through the Business API using the result reference carried by the webhook event. Webhook events carry a reference and no personal content in the opaque envelope format. Customer must verify webhook signatures.

### 5.5 Business keys and directory

Customer's keys are published in an authenticated, append-only, signed key directory and are pinned on devices after first use. Customer must keep its keys secure, rotate them as the Documentation describes and tell Viadere at once of a compromise. The transparency log is public, and it contains public keys and key identifiers only.

## 6. Assurance, limits and fallback

### 6.1 Assurance levels

Approval requests state a required assurance: biometric for high and critical requests. Face ID, Touch ID or a passcode confirms the person using the device and is not a verification of legal identity. A device that cannot produce a biometric-protected key cannot enroll for a Capability that requires it.

### 6.2 What a simple prompt does not provide

A simple approve or deny prompt is not phishing-resistant authentication by itself, and Customer must not describe it as such. Prompt fatigue, social engineering, a compromised device and the Consumer's own error can defeat it. Viadere applies limits to reduce some of these risks, but does not warrant that approvals will prevent fraud or unauthorized access. Customer remains responsible for layering other controls. Customer must not make claims about the strength of Approve beyond what Viadere's documentation states.

### 6.3 No downgrade

A sensitive request is never downgraded to a yes or no text. Viadere does not accept a decision made over SMS or RCS as an approval of a sensitive action, and a text-channel reply carries no device assurance. If a Consumer cannot receive an Approval Request in the app, Customer must use another method that it considers suitable, or deny the action. SMS is not end-to-end encrypted, and must not be used to carry approvals. When a request falls back to a text, it contains only a secure link to the app.

### 6.4 Fallback if the app or Approve is unavailable

If the Relay or the app is unavailable, requests may be delayed or fail. Customer must have its own fallback for authentication, which does not rely on Approve alone, and which does not weaken Customer's own security. Customer must plan for outages: Viadere makes no availability commitment for Approve beta.

### 6.5 Risk indicators

Viadere may show a Consumer risk context that Customer supplies, such as sign-in device, browser, approximate location and time. Customer is responsible for its accuracy.

## 7. Consumer protection controls

### 7.1 Prompt-fatigue limits

Per relationship, in a one-hour window: the device warns the Consumer from the third request; more than six an hour are refused; three denials or reports pause Customer's requests for that Consumer; and at most three requests are pending at once. Customer will not try to evade these limits, including by using multiple keys, workspaces or identifiers.

### 7.2 Freeze

A Consumer can freeze approvals for their account or for a relationship at any time, from a registered device. While frozen, results are refused, new requests are accepted but marked paused, and Customer receives an event. A Consumer can lift a freeze only from a trusted device with a fresh biometric check. Customer may freeze a Subject Reference but may lift only its own freeze, never a Consumer's. Customer must respect a freeze and must not treat it as an approval.

### 7.3 Reports

A Consumer can deny a request or report it as suspicious. A report is a negative result. Customer must treat a report as a possible account-takeover attempt, investigate it, and not penalize the Consumer for reporting.

### 7.4 New-device cool-down

A device newly enrolled for an account that has previously had an app device cannot approve high-risk requests until a cool-down has passed. Customer should treat a result from a device within its cool-down with extra care when Viadere indicates it.

## 8. Disputes and evidence

### 8.1 What Viadere keeps

Viadere keeps the signed decision (the device-signed record), the compact signed result, the request metadata and audit events for dispute resolution. The raw device-signed decision is kept by Viadere for the dispute period and is not given to Customer. Customer holds the Approval Result it received, which is its evidence. Free-text replies in a decision are erased when a Consumer deletes their account, and the rest of the record is retained in a form that remains verifiable. The retention periods are in the [Privacy Notice](/legal/privacy-notice/) and the DPA: Approval requests and results are deleted after 400 days, and signed decisions after 730 days. [COUNSEL: confirm that the retention periods meet Customer and regulatory needs.]

### 8.2 Dispute process

If a Consumer or Customer disputes an approval, either may ask Viadere for information relevant to it. Viadere may export, for the interaction concerned, the signed decision and the related evidence, with its signature, the key identifier, the time and the assurance level, with personal data minimized. Customer must first review its own records and the Approval Result it holds. Viadere will respond within [30] days, may require reasonable proof of the requester's authority, and may withhold information the law protects or that would affect another person's privacy or security. [COUNSEL: dispute process, evidence format, timelines and who decides.] Viadere does not decide a dispute between Customer and a Consumer, and does not guarantee that its records will be accepted as evidence.

### 8.3 Unauthorized approvals

[COUNSEL: allocation of responsibility among Viadere, Customer and the Consumer for an approval the Consumer did not make, which depends on the contract between Customer and the Consumer, and on payment and consumer-protection law, such as the rules that apply to unauthorized electronic fund transfers.] Customer is responsible for its own decisions on the basis of an approval.

### 8.4 Cooperation

Each party will cooperate in good faith in investigating a disputed or suspected unauthorized approval, subject to law, and Customer will keep for at least [the period required by law and no less than 400 days] the records it needs to prove what it verified and acted on.

## 9. Security and incidents

### 9.1 Customer's security

Customer will keep its Approve integration secure, as described in the Documentation, including: protecting its API keys with least scope and an IP allow-list or client certificate for Tier A; verifying webhook signatures; protecting its enrollment secrets; keeping its replay guard durable and atomic; keeping its signing and confirmation keys secure; and monitoring for unusual approval patterns. Tier A requires incident-response readiness.

### 9.2 Incidents

If a Customer key, secret or system that handles Approve is compromised, or an approval is suspected to be forged, Customer will tell Viadere at once, and will revoke the affected keys. Viadere may revoke Approval Keys or a Customer's access, pause approvals and notify Consumers. See the [Incident Notification Policy](/legal/incident-notification-policy/).

### 9.3 Viadere kill switches

Viadere can disable Approve globally or for a business, and can revoke a business's keys without suspending it, to contain an incident.

## 10. Data and privacy

Customer receives a Subject Reference and the decisions that the Consumer makes for Customer. It does not receive the Consumer's Viadere identity, phone number, other connections or device identifiers. The DPA governs Viadere's processing for Customer. Viadere is an independent controller for the Consumer's account, devices and security records.

## 11. Marketing and statements

Customer will describe Approve accurately. Customer will not say Approve is phishing-resistant unless Viadere's documentation says so for the mode and assurance level used, will not say that Viadere approves transactions or guarantees them, and will not make claims about certifications that Viadere has not made. Customer will not suggest that Viadere is an identity provider or issues sessions for Customer's users.

## 12. Fees

Fees for Approve are in the Order Form and Exhibit C of the Agreement. Approval requests may be metered. Pricing is not final.

## 13. Beta, availability and changes

Approve is a beta feature, as described in the Agreement. Viadere may change request formats, limits and protection modes with the notice the Agreement describes, and may withdraw Approve. Customer's remedies for discontinuation are in the Agreement.

## 14. Liability

Viadere's liability related to Approve is subject to section 17 of the Agreement. [COUNSEL: whether Approve has a separate cap or exclusion for losses from unauthorized transactions, and how it relates to Customer's regulatory obligations.] Customer is responsible for decisions it takes on the basis of an approval and for failure to verify the Approval Result.
