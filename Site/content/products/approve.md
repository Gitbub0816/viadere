---
title: Approve
status: beta
order: 2
tagline: Sign-in approvals and transaction authorization, signed on the customer's device.
description: Sign-in approvals and transaction authorization, signed on the customer's device.
disclosures: [mfa]
---
Approve lets a business ask "is this you?" for a sign-in or a transaction. The customer sees the business, the amount or context and the effect of approving, and decides with Face ID or their passcode.

::: callout
**Beta.** Approve works today for approved businesses. It has not completed independent penetration testing, and no assurance level is promised beyond what each result states.
:::

## How a decision is made

1. The business issues an `authenticate` or `authorize` request.
2. The customer's phone shows the business, purpose and context.
3. The phone signs the decision with a key held in the Secure Enclave. Each business relationship has its own key, so one business cannot link a customer to another.
4. Viadere verifies the signature, the context that was shown and the assurance, and sends the business a signed webhook.

## What the business still owns

::: disclosure
Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.
:::

A simple approve or deny prompt is not the same as phishing-resistant authentication, and Approve does not present it as such. A business should treat expired, cancelled, denied and reported results as "do not proceed".

## What Approve does not do

- Face ID unlocks a key on the device. It does not prove legal identity.
- Text channels never carry an approval. A sensitive request sent by SMS or RCS becomes a secure link to the app.
- Approve does not by itself satisfy a business's customer identification, anti-money-laundering or banking obligations.

## Related

[MFA and approval services addendum](/legal/mfa-approval-services-addendum/) (draft), [Business API](/developers/api/interactions/) and the [security architecture](/security/architecture/).
