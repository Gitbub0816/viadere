---
title: Security overview
nav_title: Overview
layout: marketing
order: 0
eyebrow: Security & Trust
headline: Designed to hold less, *and prove more.*
description: How Viadere is designed to limit what it can see, what a business can do, and what an attacker can gain.
disclosures: [encryption]
hero_art: signed-result
actions:
  - label: Architecture overview
    href: /security/architecture/
  - label: Report a vulnerability
    href: /security/disclosure/
---
::: section
::: prose
Viadere connects, delivers and verifies. Businesses control their own accounts, customers control their credentials and disclosures, and Viadere tries to hold as little as it can.

::: callout
This page describes design intent and controls that exist in the product. It is not an audit report. See [attestations](/security/attestations/) for what we have and have not independently achieved.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:chip} Architecture in four ideas
:::
## Keys on the device. *Proof with the business.*
:::

{{ generate: mockup pillars }}
:::

::: section
::: section-head
::: kicker
{icon:sliders} Principles
:::
## Five rules the product is built around.
:::

::: grid grid-3
::: card
### {icon:eye-off} Minimize what Viadere holds
Raw identity evidence and private keys for third-party credentials stay with the customer or the issuer wherever possible.
:::
::: card
### {icon:key} Separate duties
A credential that can send a message cannot invoke an age check or approve a payment. Each key has scopes, and sensitive actions need the matching scope and policy.
:::
::: card
### {icon:seal} The business verifies
A business validates an approval signature with a key it enrolled. A relay status alone is not evidence.
:::
::: card
### {icon:split} Tenant isolation
One business cannot read another's messages, results or audit events by changing an identifier.
:::
::: card
### {icon:sms} Nothing is approved by text
Security-sensitive requests are approved only by a device-signed decision in the app.
:::
::: card
### {icon:doc} Claims need evidence
The build of this site fails when a banned claim or an attestation term appears without documented evidence.
:::
:::
:::

::: section dark
::: section-head
::: kicker
{icon:lock} Encryption, plainly
:::
## What is protected, *and how.*

Ordinary SMS is not end-to-end encrypted. Viadere's relay handles operational metadata such as routing identifiers and delivery state, and distinguishes it from encrypted payloads.
:::

::: prose
::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

See the [architecture overview](/security/architecture/) for who holds which key and what protects each hop.
:::
:::

::: section
::: section-head
## Go deeper
:::

::: grid grid-2 gap-lg
::: card
### {icon:server} Architecture overview
Where keys live, what the relay sees and what protects each hop. [Architecture](/security/architecture/)
:::
::: card
### {icon:bolt} Responsible disclosure
How to report a vulnerability to us. [Report a vulnerability](/security/disclosure/)
:::
::: card
### {icon:seal} Verification badges
What “verified” does and does not mean. [Verification badges](/security/verification-badges/)
:::
::: card
### {icon:id} Identity assurance
What a verification result describes. [Assurance](/security/assurance/)
:::
::: card
### {icon:doc} Attestations
What is published, and what is not claimed. [Attestations](/security/attestations/)
:::
::: card
### {icon:eye-off} Privacy Center
Data categories, device-held versus server-held data and your controls. [Privacy Center](/privacy/)
:::
:::
:::
