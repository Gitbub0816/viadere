---
title: Identity assurance
order: 3
description: How to read a verification result: the attribute, the assurance, and the limits.
disclosures: [identity_verification, mfa]
---
An assurance statement answers three questions: **what attribute** was evaluated, **what evidence** supported it, and **how strongly**. It never answers "is this person who they say they are" in general.

## How to read a result

- **Attribute.** For example "age is at least a stated threshold", not a name or birthdate. The standard age result discloses no birthdate, name, address or government ID number.
- **Evidence and assurance.** The result states what was evaluated and at what assurance. A result that arrives over a text channel carries no device assurance, and a business must treat it as such.
- **Expiry and purpose.** Results are purpose-bound and expire. They are not a standing credential.

::: disclosure
Viadere may verify selected identity attributes using supported credentials or verification providers. A verification result describes the attribute and assurance evaluated; it is not a universal guarantee of identity or eligibility.
:::

## What a result does not do

- It does not automatically satisfy a business's customer identification, anti-money-laundering, sanctions or age-assurance duties. [COUNSEL: reliance language.]
- It does not make a push approval phishing-resistant. A simple approve or deny prompt is a different assurance from a device-bound, phishing-resistant method, and results say which was used.
- It does not replace the business's own decision.

::: disclosure
Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.
:::
