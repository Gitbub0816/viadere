---
title: Architecture overview
order: 4
description: Where keys live, what the relay sees and what protects each hop.
disclosures: [encryption, device_custody]
---
This is a plain-language summary of the design. Normative detail lives in the internal security specification.

## Who holds what

| Item | Held by | Notes |
|---|---|---|
| Approval signing keys | The customer's device (Secure Enclave) | One key per business relationship, so keys cannot be linked across businesses |
| Business approval public keys | The business | The business validates every signed result itself |
| Passkey private keys for third-party accounts | The customer's device or an encrypted vault | Designed never to exist in server plaintext. Authenticator is [planned](/products/authenticator/). |
| Routing identifiers, delivery state | Viadere | Operational metadata, minimized and isolated per business |
| Raw identity evidence | The issuer, device or provider where possible | Avoided centrally, short retention if unavoidable |

## Encryption by channel

- **App and API:** TLS in transit.
- **Sensitive identity disclosures and payloads:** designed to use HPKE (RFC 9180) end-to-end encryption between endpoints, with business keys published through an authenticated key directory so a relay cannot substitute a key unnoticed. These features depend on Verify and are not generally available.
- **SMS and RCS:** Ordinary SMS is not end-to-end encrypted. Carriers and messaging providers handle it, and Viadere's relay sees the text it forwards. Use the app for anything sensitive.

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

## Signed results and replay

An approval binds the business, the amount or payee, a nonce and an expiry. Replaying it, or substituting any of those, fails verification. Webhooks are signed with a timestamp so a stale delivery is rejected.

## Device loss

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

Replacing a device cannot silently replace an enrolled approval key.
