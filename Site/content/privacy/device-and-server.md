---
title: Device and server
order: 2
description: What stays on your device and what Viadere stores.
disclosures: [device_custody]
---
## On your device

- Approval signing keys, one per business relationship, in the Secure Enclave.
- Your decision to unlock them (Face ID or passcode), handled by the operating system.
- For the planned Authenticator, your third-party credentials.

## On Viadere's servers

- Your account, linked devices and phone number, and your connections and consent records.
- Operational records needed for delivery, and security audit events.
- The public keys needed to verify your decisions. The raw device-signed decision is kept by Viadere for disputes and is not given to the business.

## Why it matters

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

Deleting data on Viadere's servers does not revoke a credential or record held by a third party. [COUNSEL: explain per credential type.]
