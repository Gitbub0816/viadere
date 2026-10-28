---
title: Verify
layout: marketing
status: planned
order: 3
headline: Verify. *Prove one fact, share nothing else.*
tagline: Age thresholds and selected identity attributes, with the assurance stated.
description: Age thresholds and selected identity attributes, with the assurance stated.
disclosures: [age_verification, identity_verification]
hero_art: verify
---
::: section
::: prose
Verify is designed to let a business confirm a specific fact about a person, such as “is at least 21”, without collecting more than it needs.

::: callout
**Planned. Not available.** There is no sandbox, no pricing and no launch date for Verify. This page describes intent so that you can judge it, not a feature you can use.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:id} Intent
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
Support depends on the credential, the issuer and the region.
:::
::: card
### {icon:doc} No regulatory shortcut
A Verify result does not automatically satisfy a business's know-your-customer, anti-money-laundering, sanctions or age-assurance duties. [COUNSEL: confirm wording per jurisdiction.]
:::
:::

Related: [Verification services addendum](/legal/verification-services-addendum/) (draft), [identity assurance](/security/assurance/) and [verification badges](/security/verification-badges/).
:::
