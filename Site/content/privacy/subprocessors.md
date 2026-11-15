---
title: Subprocessors
order: 6
description: Companies that process data on Viadere's behalf, what they do and where.
---
The binding list, with its change-notification process, is the [Subprocessors](/legal/subprocessors/) document. It is a draft pending counsel review, and contracts, transfer mechanisms and some locations are still to be confirmed.

| Provider | What it does for us | Data | Where |
|---|---|---|---|
| Fly.io | Runs the Viadere servers | Service data in transit and memory; redacted logs | United States (Ashburn, Virginia) |
| Cloudflare | DNS, edge network, firewall, website | Request traffic, IP addresses | Global edge |
| Neon | PostgreSQL database and backups | Stored service data (sensitive fields encrypted by us first) | United States (AWS us-east-1) |
| Google Cloud KMS | Hardware-backed key management | Keys only, no personal data | United States (us-east1) |
| MailerSend | Email to dashboard users; SMS (US and Canada) | Work email addresses and codes; phone numbers and text content | [COUNSEL: confirm] |
| Twilio | Alternative SMS provider (if used) | Phone numbers and text content | [COUNSEL: confirm] |
| RCS provider | RCS messages (not yet chosen) | Phone numbers and message content | [COUNSEL: on selection] |
| Apple | Push notifications, Wallet, App Attest | Push tokens and notification text, pass data, attestation | Global |
| Didit | Document and liveness checks, only if Verify is enabled and you choose it | ID images, selfie, liveness video, decision, for one check | EU by default [COUNSEL: confirm] |

## Notes

- **Verify is planned.** Didit and Wallet identity services apply only if Verify is enabled.
- **No advertising, analytics or crash-reporting providers.**
- **Shopify** is chosen by a business that connects its store. Viadere receives minimized order status from it for that business and sends customers to the business's checkout. It is not a Viadere subprocessor, and payment data never reaches Viadere. [COUNSEL: confirm.]
- **Carriers** carry text messages under their own terms. SMS is not end-to-end encrypted.
- **Audit integrity heads** (a hash and a sequence number, no personal data) are exported to write-once storage.

## How we tell businesses about changes

At least [30] days before a new subprocessor starts: an update to this list, an email to subscribed business contacts and a dashboard notice. Businesses may object on data-protection grounds. See the [Data Processing Addendum](/legal/data-processing-addendum/).
