---
title: Verify
layout: marketing
status: planned
order: 4
headline: Verify. *Prove one fact, share nothing else.*
tagline: Age thresholds and selected identity attributes, with the assurance stated.
description: Age thresholds and selected identity attributes, with the assurance stated.
disclosures: [age_verification, identity_verification]
hero_art: verify
---
::: section
::: prose
Verify lets a business confirm a specific fact about a person, such as “is at least 21”, without collecting more than it needs.

::: callout
**Built, not released.** Verify is built and tested, and it is switched off behind a release gate. While it is off, every Verify route answers `404`. It stays off in each market until legal and privacy validation for that market is recorded. There is no pricing and no launch date, and it has not been run on a physical device.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:id} What it answers
:::
## An answer, *not a document.*
:::

::: grid grid-2 gap-lg
::: card
### {icon:user} Age thresholds
::: disclosure
Where supported, Viadere can confirm that a person meets a specified age threshold without disclosing their date of birth. Availability and legal sufficiency vary by jurisdiction and service.
:::
:::
::: card
### {icon:id} Selected attributes
::: disclosure
Viadere may verify selected identity attributes using supported credentials or verification providers. A verification result describes the attribute and assurance evaluated; it is not a universal guarantee of identity or eligibility.
:::
:::
:::
:::

::: section
::: section-head
::: kicker
{icon:repeat} How a check runs
:::
## The customer sees the request *before anything is shared.*
:::

::: steps four
::: card
### Ask
A business with the capability asks for one fact. The capability is granted by Viadere after review, never by a plan or a badge.
:::
::: card
### Consent
The customer sees the verified business, the purpose, exactly what would be shared and when the request expires. They can decline.
:::
::: card
### Verify
The customer uses an ID in Apple Wallet, or scans an ID document with a liveness check and a face match by a verification provider.
:::
::: card
### Retrieve
The business gets a notice that the request ended, then fetches the result once. A second fetch is refused.
:::
:::

- **“Not verified” never says why.** Under the threshold, declined, abandoned, expired and a provider outage all look the same to the business.
- **An age result is a yes.** It carries no birthdate, no age, no name and no document number.
- **A selfie estimate is never reported as a verified age.**
- **A Verify with Viadere button** exists for websites and apps. On a computer, the web button's panel shows the [Viadere code](/products/viadere-code/) first, for the Viadere app's scanner, with an ordinary QR code one control away for a phone's own camera. The buttons inside iOS and Android apps still show a QR code first. With Verify off, the button has nothing to open.
:::

::: section alt
::: section-head
## Design principles
:::

::: grid grid-2
::: card
### {icon:eye-off} Verified age is not verified legal identity
An age result carries no name, address, birthdate or government ID number in the standard result.
:::
::: card
### {icon:chip} Evidence stays where it can
Raw identity evidence is preferably held by the issuer, the device or the provider, and kept briefly if Viadere must handle it at all.
:::
::: card
### {icon:wallet} Not every Wallet user can present an ID
Support depends on the credential, the issuer and the region. The Wallet method also depends on an entitlement from Apple that Viadere does not hold, and it does not yet check whether an ID was revoked after it was issued.
:::
::: card
### {icon:doc} No regulatory shortcut
A Verify result does not automatically satisfy a business's know-your-customer, anti-money-laundering, sanctions or age-assurance duties. [COUNSEL: confirm wording per jurisdiction.]
:::
:::

Related: [Verification services addendum](/legal/verification-services-addendum/) (draft), [identity assurance](/security/assurance/), [verification badges](/security/verification-badges/) and the [Verification API](/developers/api/verification/).
:::
