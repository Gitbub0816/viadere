---
title: Approve
layout: marketing
status: beta
order: 2
headline: Approve. *“Is this you?”, answered on the device.*
tagline: Sign-in approvals and transaction authorization, signed on the customer's device.
description: Sign-in approvals and transaction authorization, signed on the customer's device.
disclosures: [mfa]
hero_art: signin
actions:
  - label: Read the quickstart
    href: /developers/quickstart/
  - label: Approve API
    href: /developers/api/interactions/
---
::: section
::: feature
::: feature-copy
::: kicker
{icon:faceid} Sign-in approval
:::
## A sign-in request with the context to judge it.

Approve lets a business ask “is this you?” for a sign-in. The customer sees the verified business, the browser, the approximate place and the time, and decides with Face ID or their passcode.

- {icon:check} **Expiry you can see.** An unanswered request expires; it never quietly succeeds.
- {icon:check} **“This was not me”** reports the attempt. Reports count toward the business's complaint rate.
- {icon:check} **Stronger UI where it matters.** Approving pauses while the screen is being recorded; denying never does.
:::
::: feature-art
{{ generate: mockup payment }}
:::
:::

::: callout
**Beta.** Approve works today for approved businesses. It has not completed independent penetration testing, and no assurance level is promised beyond what each result states.
:::
:::

::: section alt
::: section-head
::: kicker
{icon:signature} How a decision is made
:::
## Four steps, *and the business checks the last one.* {#how-a-decision-is-made}
:::

::: steps four
::: card
### Request
The business issues an `authenticate` or `authorize` request with the context to show.
:::
::: card
### Display
The customer's phone shows the business, purpose and context, with an expiry.
:::
::: card
### Sign
The phone signs the decision with a key in the Secure Enclave. Each business relationship has its own key, so one business cannot link a customer to another.
:::
::: card
### Verify
Viadere checks the signature, the context shown and the assurance, and sends a signed webhook. The business verifies the result against the request it created.
:::
:::
:::

::: section
::: feature flip
::: feature-copy
::: kicker
{icon:seal} The signed result
:::
## Evidence the business can check for itself.

An approval binds the business, the amount or payee, a single-use challenge and a short expiry. Replaying it, or substituting any of those, fails verification. A relay status alone is never the evidence.

[Read the security architecture](/security/architecture/){.more}
:::
::: feature-art bare
{{ generate: mockup signed-result }}
:::
:::
:::

::: section alt
::: grid grid-2 gap-lg
::: card
### {icon:store} What the business still owns
::: disclosure
Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.
:::

A simple approve or deny prompt is not the same as phishing-resistant authentication, and Approve does not present it as such. A business should treat expired, cancelled, denied and reported results as “do not proceed”.
:::
::: card
### {icon:x} What Approve does not do
- Face ID unlocks a key on the device. It does not prove legal identity.
- Text channels never carry an approval. A sensitive request sent by SMS or RCS becomes a secure link to the app.
- Approve does not by itself satisfy a business's customer identification, anti-money-laundering or banking obligations.
:::
:::

Related: [MFA and approval services addendum](/legal/mfa-approval-services-addendum/) (draft), [Business API](/developers/api/interactions/) and the [security architecture](/security/architecture/).
:::
