---
title: Authenticator
layout: marketing
status: planned
order: 5
headline: Authenticator. *Your credentials, kept by you.*
tagline: A credential vault for passkeys and codes, with recovery that does not depend on identity verification.
description: A credential vault for passkeys and codes, with recovery that does not depend on identity verification.
disclosures: [device_custody, encryption]
hero_art: authenticator
---
::: section
::: prose
Authenticator is a place for a customer's own account credentials: passkeys and one-time-code secrets for other services, with sync between their devices.

::: callout
**Built, not released.** The vault and its sync are built and tested, and sync is switched off behind a release gate. It stays off until an independent review of the vault's cryptography and recovery has passed. It has not been run on a physical device, and no date is promised.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:passkey} How it is built
:::
## Three commitments, *held in the design.*
:::

::: grid grid-3
::: card
### {icon:key} Keys stay with the customer
Private keys for third-party accounts are designed never to exist in server plaintext. The server stores ciphertext, signed public manifests and public keys, and never a key that opens them.
:::
::: card
### {icon:repeat} Sync, reviewed first
Synchronization is designed to use end-to-end encryption, gated on the independent review above. While sync is off, a device keeps working from its own encrypted vault.
:::
::: card
### {icon:lock} Recovery apart from identity
Unlocking and recovering the vault must not depend on passing a Verify check.
:::
:::
:::

::: section
::: section-head
::: kicker
{icon:clock} Recovery, slowed down on purpose
:::
## A wait, *and a warning to every device.*
:::

::: grid grid-2 gap-lg
::: card
### {icon:bell} A 72-hour hold
When a new device asks to restore the vault, the request waits 72 hours. Every other device on the account is told at once and can cancel it.
:::
::: card
### {icon:key} Useless without your recovery key
What the server releases after the hold is still sealed. It cannot be opened without the recovery key that only the customer holds.
:::
:::
:::

::: section alt
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
