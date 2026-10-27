---
title: Security overview
nav_title: Overview
order: 0
eyebrow: Security & Trust
description: How Viadere is designed to limit what it can see, what a business can do, and what an attacker can gain.
disclosures: [encryption]
---
Viadere connects, delivers and verifies. Businesses control their own accounts, customers control their credentials and disclosures, and Viadere tries to hold as little as it can.

::: callout
This page describes design intent and controls that exist in the product. It is not an audit report. See [attestations](/security/attestations/) for what we have and have not independently achieved.
:::

## Principles

- **Minimize what Viadere must possess.** Raw identity evidence and private keys for third-party credentials stay with the customer or the issuer wherever possible.
- **Separate duties.** A credential that can send a message cannot invoke an age check or approve a payment. Each key has scopes, and sensitive actions need the matching scope and policy.
- **The business verifies.** A business validates an approval signature with a key it enrolled. A relay status alone is not evidence.
- **Tenant isolation.** One business cannot read another's messages, results or audit events by changing an identifier.
- **Nothing is approved by text.** Security-sensitive requests are approved only by a device-signed decision in the app.

## Encryption, plainly

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

Ordinary SMS is not end-to-end encrypted. Viadere's relay handles operational metadata such as routing identifiers and delivery state, and distinguishes it from encrypted payloads. See the [architecture overview](/security/architecture/).

## More

::: grid grid-2
::: card
### Responsible disclosure
How to report a vulnerability to us. [Report a vulnerability](/security/disclosure/)
:::
::: card
### Verification badges
What "verified" does and does not mean. [Verification badges](/security/verification-badges/)
:::
::: card
### Identity assurance
What a verification result describes. [Assurance](/security/assurance/)
:::
::: card
### Attestations
What is published, and what is not claimed. [Attestations](/security/attestations/)
:::
:::
