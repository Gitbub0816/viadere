---
title: Retention
order: 4
description: How long each class of data is kept, what deletion does and what stays in backups.
---
There is no single retention period. Each class of data has a stated default and a minimum and maximum, enforced by an automatic job that runs at least every minute. A business can shorten (never lengthen) some periods for its own data. A legal hold suspends deletion for the data it covers. The binding version is in the [Privacy Notice](/legal/privacy-notice/).

## Defaults by class

| Class | What is deleted or erased | Default (range) in days |
|---|---|---|
| Interaction content | Request text, reply and signed decision of finished interactions. The row, IDs and status remain | 400 (30 to 1,095) |
| Conversation content | Message bodies, replaced by an expiry marker | 730 (30 to 3,650) |
| Signed decisions | Device-signed decisions | 730 (365 to 2,555) |
| Consent history | Superseded consent versions. Your current consent is never deleted by this job | 1,095 (365 to 3,650) |
| Audit events | Events past the period and already covered by an exported integrity head | 2,555 (730 to 3,650) |
| Business applications | Free text of decided applications | 730 (90 to 3,650) |
| Usage records | Metering rows | 2,555 (365 to 3,650) |
| Loop activity | Inputs, state and outcome of finished Loops | [Counsel and product to set] |
| Shopify order status | Order reference, status, item titles, tracking, timestamps, after the order completes or is cancelled | 90 (set by the business within bounds) |
| Webhook deliveries | Event deliveries and their attempts | 30 (1 to 365) |
| Outbound messages | Finished text and channel sends | 30 (1 to 365) |
| Link tokens | Used or expired account-link tokens | 7 (1 to 90) |
| Security tokens | Expired session tokens and challenges | 30 (7 to 180) |
| Channel capability | RCS capability cache, postbacks, de-duplication markers | 180 (14 to 730) |
| Security notices | In-app notices | 365 (30 to 1,095) |
| Support records | Closed tickets, finished notices, decided approvals and data requests, expired exports | 730 (90 to 3,650) |

[COUNSEL AND PRIVACY: the defaults are being reviewed against legal duties and may change within the bounds.]

## Other retention rules

| Data | Retention |
|---|---|
| Account, devices, relationships | Until you delete your account. Revoked device records are kept as cool-down evidence, with names blanked on deletion |
| Phone number | Erased when you delete your account or unlink it. The opt-out record stays as suppression |
| SMS opt-out and consent evidence | Kept as suppression evidence. [COUNSEL: period] |
| Rate-limit records | Deleted when the limit window passes. Per-business abuse counters 90 days |
| Pass logs | 7 days |
| Dashboard sessions | 24 hours after expiry. Unverified dashboard sign-ups 24 hours |
| Data export bundle | 7 days, then erased |
| Verification result payload (planned) | Erased when the business retrieves it once, or after 15 minutes |
| Verification request records (planned) | 400 days |
| Verification provider session (planned) | Deleted after the result is read, retried until it succeeds |
| Business handles and codes | Kept. They are never reassigned |
| Server logs | Redacted and kept for a short period. [PRIVACY: confirm, about 7 days] |
| Key-management audit logs | 400 days |

## What deleting your account erases

When you delete your account we revoke all sessions and devices, delete your passkeys, erase phone numbers, text thread state, message bodies, interaction payloads and replies, household labels, loyalty member references and webhook delivery bodies about you, and delete your verification requests and results. Signed decisions are kept without personal content so they remain verifiable. Only a free-text reply inside one is erased. Audit events, which identify you only by internal pseudonym, remain for the audit period. An opted-out number keeps a record that only suppresses further texts.

## Backups

Deleted data can remain in encrypted backups until they age out. Point-in-time recovery history is 7 days, and daily snapshots are 30 days. If we restore a backup, we repeat deletions.

## Legal holds and legal duties

A court order, regulator or legal claim can require us to keep data. We keep what the law requires, for as long as it requires.

## Businesses

A business holds its own records about you, under its own retention. Ask the business for those. Where Viadere carries data for a business, the business can shorten some retention periods for its own data.
