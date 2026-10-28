---
title: Device and server
order: 2
description: What stays on your device, what Viadere's servers hold, and how each is protected.
disclosures: [device_custody, encryption]
---
## On your device

- **Approval signing keys**, one per business relationship, created in the Secure Enclave. Using one requires Face ID, Touch ID or your passcode. The operating system handles that check, and Viadere never receives biometric data from it.
- **Your passkey private key**, which signs you in to Viadere.
- **Your data-export key.** When you ask to download your data, the app creates a fresh key for that export. The private half stays in the device Keychain until you read the file.
- **For the planned Authenticator:** your third-party passkeys and one-time-code secrets, in an encrypted vault.
- **Local app data** the app needs to work, kept in the app's container and protected by the operating system.

## On Viadere's servers

- **Account, device, relationship, consent and interaction records** as listed in [data categories](/privacy/data-categories/).
- **Public keys, signed decisions and audit events.** The raw device-signed decision is kept by Viadere for disputes and is not given to the business. The business receives a compact signed result.
- **Phone numbers, message bodies, request details and other sensitive fields as ciphertext.** They are encrypted with AES-256-GCM before they are written to the database, using keys bound to the table, column and row. The encryption key is held outside the database.
- **Hashes, not secrets.** Session tokens, API keys, recovery codes and one-time codes are stored only as keyed hashes.
- **For end-to-end requests:** an opaque envelope that Viadere cannot read. For server-visible requests, details are sealed in the database and cleared when the request ends.

## What is protected end to end, and what is not

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

| Feature | Protection model |
|---|---|
| Approval requests from a business that enrolls a key (end-to-end mode) | Sealed to your device's key. Viadere carries it and cannot read or change it |
| Approval requests in server-visible mode | Viadere's systems can read the details while the request is open. The app tells you. The decision is still signed by your device key |
| Identity results for name and address (Verify, planned) | Sealed to the business's published key when it has one |
| Your data export | Sealed to a key only your device holds. Viadere cannot read it |
| Authenticator vault (planned) | Ciphertext only, with keys that never leave your devices |
| Ordinary SMS | Not end-to-end encrypted. Carriers and providers can read it |
| In-app messages and delivery metadata | Encrypted in transit and at rest. Viadere can process them to deliver them. Routing and delivery metadata is visible to Viadere |

## Why it matters

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

- **Lost devices.** If you lose all your devices and your recovery codes, Viadere may be unable to restore your account. Keep your recovery codes somewhere safe.
- **New devices.** A newly registered device passes through a cool-down before it can approve high-risk requests, and your other devices are told so you can cancel.
- **Credentials held by others.** Deleting data on Viadere's servers does not revoke a credential, account or record held by a third party. It does not remove a business's own records about you, a Wallet pass already on your phone, or a passkey you registered at a website. Remove those with the party that holds them.

## Identity checks (planned)

If Verify launches:

- **Apple Wallet ID:** you present an eligible ID. Viadere checks it in memory, reduces it to the requested element (for an age check, only the yes or no for the threshold), and does not store or log the presentation.
- **Document and liveness check:** the camera captures your document, a selfie and liveness video on your device and sends them directly to the verification provider, Didit. Viadere does not receive them. The session is deleted after the result is read.
- **What Viadere keeps:** the request and result record, with no names, birthdates, document numbers, images or scores. The result payload is erased when the business retrieves it once, or after 15 minutes.
- **You can decline,** and use Wallet where available or not use Verify at all.

## Who can see what

| Party | Sees | Does not see |
|---|---|---|
| Viadere | Account, device and consent records, request metadata, delivery metadata, signed decisions, ciphertext of sensitive fields (and can decrypt those it must process to deliver) | Your private keys, your biometric data, end-to-end content, vault contents, your ID images |
| A business | Its own pairwise reference for you, your decisions, messages you send it, your consent state for it | Your Viadere identity, phone number, other connections, device identifiers |
| Apple | Push tokens and notification text, Wallet pass data, device attestation | Your Viadere account content |
| Carriers and SMS providers | Text message content and phone numbers on the text channel | App-only traffic |
| Verification provider (planned) | The evidence for one check | Anything else about you |
