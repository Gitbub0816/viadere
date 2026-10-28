---
title: Credential Vault Terms
order: 10
description: "Device custody, optional sync, recovery, device loss, limits and ending the service for Authenticator. Authenticator is planned."
version: 0.2.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete terms covering what the vault holds, device custody, optional end-to-end encrypted sync, recovery key and release hold, device add and removal, AutoFill, limits, responsibilities, export and import, ending the service, security, liability and disclaimers."
disclosures: [device_custody, encryption]
---
::: callout
Authenticator is [planned](/products/authenticator/) and not available. These terms are a draft for review. Statements about how the vault works describe its design, not a service in operation. The sync feature will not be enabled until an independent cryptography and recovery review has passed.
:::

::: draft-notice
**Draft for counsel review.** These terms are not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

These Credential Vault Terms (the "**Vault Terms**") are an additional agreement between you and [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") that applies when you use Authenticator, Viadere's passkey and one-time-code vault (the "**Vault**"). They supplement the [Consumer Terms of Service](/legal/consumer-terms/) and the [Privacy Notice](/legal/privacy-notice/). If they conflict, these Vault Terms apply to the Vault. You must accept them before you use the Vault.

## 1. What the Vault is

### 1.1 What it holds

The Vault is designed to store, on your devices, credentials you use to sign in to third-party websites and apps: passkeys (FIDO2 and WebAuthn credentials) that you create with Viadere as your credential provider, and time-based one-time-code (TOTP) secrets that you add. It works with the iOS credential-provider and AutoFill system. [PRODUCT: confirm credential types at launch; passwords and other types are not currently planned.]

### 1.2 What it is not

The Vault is not a password manager for all kinds of secrets, is not a government identity service, and does not issue sessions for any website. The website or app you sign in to (the "**relying party**") remains the authenticating party and controls your account there. Viadere does not control, recover or reset your account at any relying party. A passkey created in another manager is not automatically importable into the Vault, and a passkey in the Vault is not automatically exportable, because interoperability depends on what the other service supports.

### 1.3 Separate from Verify and from your Viadere account recovery

Unlocking or recovering the Vault does not depend on identity verification. Government-ID or selfie verification, and your Viadere account recovery codes, do not unlock the Vault, and Viadere will not recover a Vault or recreate keys on presentation of an identity document.

## 2. Device custody

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

### 2.1 Where credentials live

Your credentials are encrypted on your device and protected by Apple's Keychain and Secure Enclave where available. Passkey signing and the vault's device keys require user verification (Face ID, Touch ID or your device passcode). Viadere servers never receive a credential's private key or TOTP secret in a form Viadere can read.

### 2.2 Loss of device

If you lose or break a device that holds the only copy of a credential, and you have not turned on sync or kept your recovery key, the credential cannot be recovered by Viadere. You will need to use each relying party's own account-recovery process to regain access and to register a new passkey or TOTP secret. Some credentials are non-exportable and cannot be recreated by Viadere. Keep a way back into each important account that does not depend on the Vault alone.

### 2.3 Device security

You are responsible for keeping your device updated, protected by a passcode, and in your control. Anyone who can unlock your device and pass the user verification may be able to use credentials in the Vault. If a device is lost or stolen, remove it from the Vault from another device and change the credentials that were stored on it, because a removed device keeps anything it already copied.

## 3. Optional sync between your devices

### 3.1 Off by default

Sync is optional and is off unless you turn it on. If sync is off, the Vault lives only on the device it was created on.

### 3.2 How sync works

If you turn on sync, your credentials are encrypted on your device with keys that never leave your devices, and Viadere's servers store ciphertext, signed public structures and public keys only. The server cannot read an item, a name, a website or a device name, and does not receive a key that opens the Vault. Items are encrypted individually with fresh keys. Changes form a signed, chained history that your devices check, which protects against rollback, forks and substitution of devices.

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

### 3.3 What Viadere can still see

Even with sync on, Viadere's servers can see: how many items you have; each item's stable identifier and revision number, and therefore which items change and how often; the size of each item rounded to 256-byte steps; how many devices are enrolled, their role and when each was added; whether a recovery key is set; the times of changes; when a device joins, a key rotation, a recovery release or a restore happens; which account device made each change; and request details such as network addresses, as for any service. It does not see the contents.

### 3.4 Limits

A Vault can hold at most 2 MiB of encrypted item data, 2,000 items and 16 devices, and individual items are limited to 32 KiB. Writes over these limits are refused. [PRODUCT: confirm limits at launch.]

### 3.5 Adding a device

To add a device, an existing device generates a pairing secret that you give to the new device by QR code or a typed code. Both devices show a fingerprint that you compare before you approve. You must compare the fingerprints and approve only a device you control. A pairing request lasts ten minutes, and at most three can be open.

### 3.6 Removing a device

When you remove a device, the Vault key is replaced and every item is re-encrypted, so that the removed device cannot read later changes. A removed device keeps whatever it already had. Viadere ends the removed device's access at once and prevents the account device it belonged to from asking to rejoin or restore.

## 4. Recovery

### 4.1 Recovery key

When you turn on sync, you are shown a recovery key once, which looks like VRK1- followed by groups of characters. It is 256 bits and is not derived from your identity, your passcode or your Viadere account. You must type it back to confirm that you saved it before sync turns on. Store it offline in a safe place. You can replace it from a trusted device.

### 4.2 The recovery key is a bearer secret

Anyone who has your recovery key and access to your Viadere account can restore your Vault once the hold in section 4.3 passes uncancelled. There is no second factor on it, by design, because an independent factor must not be an identity check. Treat it like the key to your credentials. Do not share it, photograph it into a cloud album or store it in an account you cannot protect.

### 4.3 Release hold and notices

If you have no Vault device and want to restore on a new device, a trusted device on your account must ask for a release. Nothing is released for 72 hours. During that time every other device on your account receives an in-app notice and a push notification with a "Not you? Cancel" action, and any of them can cancel the request. After the hold, the recovery material is released for 24 hours to the requesting device only, and you are told when it opens and when a restore happens. Every fetch is logged. If you have no reachable device and no push notifications, you may not see the notice until you next open the app, so keep at least one device reachable and notifications on.

### 4.4 What a restore does

A restore replaces the Vault key, removes every other device, retires the used recovery key, and requires a new recovery key which you must save before the restore completes. The app shows you a preview of the last change (time and device), the device names and the item counts before anything is committed. If it does not look like your Vault, do not continue.

### 4.5 If you lose your recovery key and your devices

If you lose your recovery key and every device that holds the Vault, Viadere cannot recover your credentials, because Viadere does not have a key that opens them. You will need to recover each account at the relying party.

### 4.6 If you use the Vault without sync

Without sync there is no recovery. If you lose the device, the credentials are lost unless the relying party can recover them.

## 5. AutoFill and the operating system

### 5.1 What the system sees

To offer your credentials in AutoFill, the iOS system identity store receives the site, your account name, the credential identifier and the user handle for passkeys, and for one-time codes the label (issuer and account), only if you turn on "Suggest in AutoFill". It never receives keys, secrets or codes. Turning the setting off removes that information from the system store. Apple's handling is governed by Apple's terms.

### 5.2 Use of the extension

The credential-provider extension does not use the network. It needs user interaction for each use. A user verification older than 60 seconds is repeated before a passkey signs.

## 6. Importing and exporting

### 6.1 Import

You can import credentials from another provider only through the interfaces that the system and the other provider support. Do not import a plaintext credential file, because it can be stolen from storage and backups. [PRODUCT: Credential Exchange support, which is not yet connected.]

### 6.2 Export

[PRODUCT AND COUNSEL: export is not currently implemented. When it is, it will be encrypted and require user verification.] You can always recreate a credential with the relying party.

## 7. Your responsibilities

You will: use the Vault only for credentials you are entitled to use; keep your devices secure and updated; keep your recovery key safe and private; compare device fingerprints before you approve a device; respond to security notices; keep a way back to important accounts that does not depend on the Vault alone; and follow the terms of the relying parties whose credentials you store. You will not: store credentials that you do not have the right to use; try to extract or bypass the Vault's protections; or use the Vault for anything unlawful.

## 8. Third parties and platform terms

The Vault depends on Apple's operating system, Keychain, Secure Enclave, credential-provider and AutoFill technologies, and on each relying party's support for passkeys and TOTP. Changes by Apple or a relying party can affect the Vault. Relying parties may refuse a passkey from a provider they do not support, or may not allow a synced passkey. Viadere's passkeys report that they may sync, and have no signature counter. Some relying parties may reject them.

## 9. Security and limits

Viadere uses modern published constructions, described in the [security overview](/security/). No system is perfectly secure. Residual risks include: a compromised or unlocked device; a malicious server together with a removed device in some forked-history scenarios, which is mitigated by the restore preview and hold; metadata that Viadere can see; exposure of keys in device memory while unlocked; and loss of the recovery key. The Vault's synchronization and recovery will be released only after an independent review, and Viadere may disable sync at any time. If sync is disabled, your devices keep working from their local encrypted copies and nothing is deleted.

## 10. Beta, changes and availability

The Vault is a planned feature and may change before launch or be withdrawn. Viadere may change features, limits and formats with a new version number, never with an in-place change to the cryptography. Viadere may require updates of the app to continue using sync.

## 11. Fees

The Vault is free for consumers. [PRODUCT: confirm.]

## 12. Ending the service and deleting your Vault

### 12.1 You can delete

You can delete your Vault, which deletes the stored ciphertext and device records on Viadere's servers. You can delete your Viadere account, which deletes the Vault data on the servers whether or not sync is on. Local copies on your devices stay until you remove them.

### 12.2 What deletion does not do

Deleting the Vault does not delete the accounts you have at relying parties or the passkeys registered with them. You must remove those with the relying party.

### 12.3 By us

Viadere may suspend or end the Vault or your access to it for violation of these Terms, for security or legal reasons, or if it discontinues the feature, with notice where practicable. If Viadere discontinues the Vault, it will give you at least [90] days' notice and a way to retrieve your credentials where technically possible. [COUNSEL: confirm.]

## 13. Disclaimers and liability

THE VAULT IS PROVIDED "AS IS" AND "AS AVAILABLE". VIADERE DOES NOT PROMISE THAT YOU WILL BE ABLE TO ACCESS OR RECOVER YOUR CREDENTIALS, THAT THE VAULT WILL BE FREE OF ERRORS OR VULNERABILITIES, OR THAT A RELYING PARTY WILL ACCEPT A CREDENTIAL FROM THE VAULT. YOU ARE RESPONSIBLE FOR THE CREDENTIALS YOU STORE, AND VIADERE IS NOT RESPONSIBLE FOR LOSS OF ACCESS TO AN ACCOUNT, LOSS OF DATA, OR UNAUTHORIZED USE OF A CREDENTIAL THAT RESULTS FROM YOUR LOSS OF A DEVICE OR RECOVERY KEY, FROM YOUR COMPROMISED DEVICE, OR FROM A RELYING PARTY'S ACTS. The disclaimers, limitation of liability, indemnity, dispute-resolution and general terms in the Consumer Terms apply to the Vault. [COUNSEL: consider whether a separate liability cap is needed for loss of credentials and whether any limit is unenforceable for consumers in some places.]

## 14. Changes to these terms

Viadere may change these Vault Terms as the Consumer Terms allow. A change that affects how your credentials are protected or recovered will be notified before it takes effect.

## 15. Contact

Questions: [SUPPORT-CONTACT-PLACEHOLDER]. Security: [SECURITY-CONTACT-PLACEHOLDER].

## 16. Questions and answers

**Can Viadere see my passwords or passkeys?** No. The Vault is designed so that Viadere's servers store only ciphertext, and Viadere does not hold a key that opens it.

**What if I forget my passcode?** Your device passcode is controlled by Apple, not by Viadere. Viadere cannot reset it. Without it, you may lose access to the device's local data. If you turned on sync and kept your recovery key, you can restore the Vault on another device.

**Can I use the Vault without turning on sync?** Yes. Without sync the Vault is local to one device and there is no recovery.

**Does Viadere decide which sites can use my passkeys?** No. The relying party decides whether to accept a passkey. Viadere's role is to hold the credential and sign when you approve.

**What should I do if I think someone has my recovery key?** Replace it from a trusted device at once, check the device list for devices you do not recognize and remove them, and change the credentials that matter most.

**What should I do if I receive a recovery notice that I did not start?** Tap "Not you? Cancel" on any of your devices straight away, then review your devices and replace your recovery key.
