---
title: Subprocessors
order: 6
description: "The companies that process data on Viadere's behalf, what they do, where, and how changes are announced."
version: 0.2.0
effective_date: ""
owner: "Privacy lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: the full provider list from the data inventory with purpose, data, location and safeguards, plus a change-notification and objection process."
---
::: draft-notice
**Draft for counsel review.** This list reflects the providers named in the repository's data inventory at the date of drafting. Contracts, data processing terms and transfer mechanisms with each provider are counsel items and are shown in brackets until confirmed.
:::

This page lists the third parties ("**subprocessors**") that Viadere engages to process personal data in providing its services, as referred to in the [Data Processing Addendum](/legal/data-processing-addendum/) and the [Privacy Notice](/legal/privacy-notice/). A plain-language version is in the [Privacy Center](/privacy/subprocessors/).

**Last updated:** [DATE, set when the list takes effect]. **Version:** 0.2.0.

## 1. Current subprocessors

| Subprocessor | Service it provides to Viadere | Personal data processed | Processing location | Transfer safeguard |
|---|---|---|---|---|
| Fly.io, Inc. | Application hosting for the Viadere API, dashboard and operator console | All service data while in transit or in memory; redacted server logs | United States, Ashburn, Virginia region | [COUNSEL: DPA and SCCs or Data Privacy Framework] |
| Cloudflare, Inc. | DNS, edge network, TLS termination, web application firewall, rate limiting and hosting of the viadere.com website | Request traffic, IP addresses and headers; the website has no personal data of its own | Global edge network | [COUNSEL: DPA and SCCs or Data Privacy Framework] |
| Neon, Inc. | Managed PostgreSQL database, point-in-time recovery and snapshots | All stored service data. Sensitive fields (phone numbers, message bodies, request details, dashboard emails, secrets) are encrypted by Viadere before storage; the key is not held by Neon | United States, AWS us-east-1 | [COUNSEL: DPA and SCCs or Data Privacy Framework] |
| Google LLC (Google Cloud KMS) | Hardware-backed management of signing and wrapping keys; write-once storage for audit integrity heads if Google Cloud Storage is chosen | Cryptographic keys and wrapped keys; audit-head hashes. No consumer personal data | United States, us-east1 | [COUNSEL: Google Cloud DPA and SCCs] |
| MailerSend | Transactional email to business dashboard users; SMS (United States and Canada) for Viadere's text channel | Dashboard user email address and sign-in or invitation codes; consumer phone numbers and the text of messages | [COUNSEL: confirm locations of email and SMS processing] | [COUNSEL: DPA and SCCs] |
| Twilio Inc. | Alternative SMS provider (supported; used only if selected) | Consumer phone numbers and the text of messages, with delivery status | [COUNSEL: confirm, if used] | [COUNSEL: DPA and SCCs or Data Privacy Framework] |
| RCS Business Messaging provider | RCS delivery of rich messages and suggested replies | Consumer phone numbers and message content | [COUNSEL: provider not yet chosen; list on selection] | [COUNSEL] |
| Apple Inc. | Apple Push Notification service (push delivery), Apple Wallet (passes and, in the planned Verify service, identity presentment) and App Attest (device attestation) | Push tokens and notification text; pass data; device attestation keys and counters | Global | Apple's terms govern; [COUNSEL: confirm Apple's role as independent controller or processor for each service] |
| Didit | Identity document, liveness and face-match checks. Used only if the Verify service is enabled and a person chooses the document method | ID document images, selfie, liveness video, document fields, face-match scores and the decision, for the duration of one check. Viadere does not receive the images or biometric data | European Union by default [COUNSEL: confirm residency] | [COUNSEL: DPA, residency, biometric terms, breach clause] |

### Notes

- **Verify is planned.** Didit and the Wallet identity services apply only if Verify is enabled. Messaging and Approve are in beta.
- **Write-once audit storage.** The integrity head of the audit log (a hash and a sequence number) is exported on a schedule to write-once storage at Google Cloud Storage or Cloudflare R2. It contains no personal data.
- **No advertising, analytics or crash-reporting vendors.** None is engaged.
- **Business customers' own providers.** The services a business uses to receive Viadere webhooks, such as its support platform or CRM, are the business's own service providers, not Viadere's.
- **Carriers.** Wireless carriers and messaging networks carry text messages. They are not Viadere's subprocessors: they act under their own terms with the sender and recipient. SMS is not end-to-end encrypted, and carriers can read ordinary text messages.
- **Affiliates.** [COUNSEL: list any Viadere affiliate that processes personal data.]

## 2. What each subprocessor is bound to

Viadere has a written agreement with each subprocessor [COUNSEL: confirm, per provider] that: restricts use of the data to providing the service to Viadere; requires confidentiality and appropriate security; requires the subprocessor to help with data-subject requests, breach notification and deletion; restricts further subprocessing; and provides an appropriate transfer mechanism. Viadere reviews each provider's security and privacy practices before engaging it and at renewal.

## 3. How we announce changes

Viadere will give at least **[30] days'** notice before it authorizes a new subprocessor, or a subprocessor that will process customer personal data in a new location or for a materially different purpose. Notice is given by all of the following:

1. Updating this page with the new subprocessor, its purpose, data and location, and marking the date the change takes effect.
2. Sending an email to every business that has subscribed to subprocessor notices in the dashboard (Compliance), and to its security and privacy contacts.
3. Showing a notice in the business dashboard.

An emergency replacement, needed to keep the service secure or available or to prevent harm, may happen on shorter notice. Viadere will tell businesses as soon as practicable and will give them the objection right below.

## 4. How to object

A business that has accepted the Data Processing Addendum may object to a new subprocessor in writing to [PRIVACY-CONTACT-PLACEHOLDER] within [30] days of the notice, on reasonable grounds relating to data protection. Viadere will discuss the concern in good faith, and may offer a different configuration or a different way to deliver the service. If it cannot be resolved within [30] days, the business may terminate the affected service before the new subprocessor processes its data, with a refund of prepaid fees for the unused period.

## 5. Change history

| Date | Change |
|---|---|
| [DATE] | First publication of this list (draft 0.2.0) |

Earlier versions of this page stay at their own addresses under [Legal](/legal/).

## 6. Related

[Data Processing Addendum](/legal/data-processing-addendum/), [Privacy Notice](/legal/privacy-notice/), [Security overview](/security/) and the [Privacy Center](/privacy/subprocessors/).
