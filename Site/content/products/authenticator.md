---
title: Authenticator
layout: marketing
status: planned
order: 4
headline: Authenticator. *Your credentials, kept by you.*
tagline: A credential vault for passkeys and codes, with recovery that does not depend on identity verification.
description: A credential vault for passkeys and codes, with recovery that does not depend on identity verification.
disclosures: [device_custody, encryption]
hero_art: authenticator
---
::: section
::: prose
Authenticator is designed as a place for a customer's own account credentials, with sync between their devices.

::: callout
**Planned. Not available.** Authenticator will not ship until an independent cryptography and recovery review has passed. No date is promised.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:passkey} Intent
:::
## Three commitments *before anything ships.*
:::

::: grid grid-3
::: card
### {icon:key} Keys stay with the customer
Private keys for third-party accounts are designed never to exist in server plaintext.
:::
::: card
### {icon:repeat} Sync, reviewed first
Synchronization is designed to use end-to-end encryption, gated on the independent review above.
:::
::: card
### {icon:lock} Recovery apart from identity
Unlocking and recovering the vault must not depend on passing a Verify check.
:::
:::
:::

::: section
::: prose
## Device custody and encryption

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

Related: [Credential vault terms](/legal/credential-vault-terms/) (draft) and the [Security overview](/security/).
:::
:::
