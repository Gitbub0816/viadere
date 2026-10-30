---
title: Data categories
order: 1
description: The kinds of data Viadere handles, where each comes from, why, who receives it and how it is protected.
health_prohibition: true
---
This page lists the data Viadere handles. The [Privacy Notice](/legal/privacy-notice/) is the binding version. Retention periods are in [Retention](/privacy/retention/).

## The seven classes

Viadere sorts data into classes and sets a default treatment for each.

| Data class | Examples | Preferred custody | Default treatment |
|---|---|---|---|
| Public | A verified business directory listing: name, handle, code, website | Viadere | Public, with review and correction |
| Operational | Message routing IDs, delivery state, conversation state | Viadere | Minimized, isolated per business, time-bound |
| Security metadata | Public keys, nonces, audit events, rate-limit counters | Viadere and the business | Integrity-protected and retained by policy |
| Identity assertions | An age-threshold result, proof metadata, consent receipts | Device and business, with minimal Viadere metadata | Purpose-bound, expiring, minimal correlation |
| Raw identity evidence | An ID image, birthdate, selfie | Issuer, device or verification provider | Not collected by Viadere. If Verify launches, deleted by the provider after the check |
| Passkey private keys | Third-party account credentials, approval keys | Your device or an encrypted vault | Never in server plaintext |
| Sensitive message payloads | Anything you choose to tell a business | Intended endpoints where feasible | Encrypted in the database; designed for end-to-end protection where the business supports it |

## What we hold about you

| Category | Examples | Where it comes from | Why we use it | Who receives it |
|---|---|---|---|---|
| Account | Display name you choose, passkey public key, account status | You, your device | Run your account and sign you in | Hosting and database providers |
| Phone number (optional) | Number (encrypted), a keyed hash for matching, a masked form, last four digits | You | Deliver texts, confirm it is yours, honor STOP | SMS and RCS providers, carriers |
| Devices | Device name, platform, public keys, App Attest key identifiers, cool-down state | Your device | Check decisions come from your devices, stop account takeover | Hosting and database providers; Apple for attestation |
| Sessions and recovery | Hashed tokens, hashes of recovery codes | You, our systems | Keep you signed in, let you regain access | None |
| Connections and consent | Which businesses you connected to, purposes allowed, wording version, source, time | You | Enforce your choices, keep evidence | The business sees only its own consent state |
| Requests and decisions | Request text, purpose, amount and context, your answer, signed decisions | Businesses, you | Deliver and record requests, resolve disputes | The business that sent the request |
| Messages | Text and attachments exchanged with a business | You, businesses | Deliver conversations, show history | The business; providers and carriers when the channel is text |
| Delivery records | Provider message ID, status, channel, time | Providers | Retry, order and troubleshoot delivery | SMS, RCS and email providers |
| Push and Live Activity | APNs token, activity token | Your device | Deliver notifications | Apple |
| Rewards and passes | Program membership, points, redemption code hash, Wallet pass serial and token hash | Businesses, you, Apple | Run rewards and passes you use | The business; Apple for Wallet |
| Loops (optional) | Whether Loops are on, businesses you allowed, what you chose or entered in a Loop, its state and outcome | You, businesses | Run a Loop you chose to use, show its history, keep evidence of your choices | The business that built the Loop |
| Shopify order status (optional) | Order reference, status, item titles, carrier and tracking number, timestamps. No name, address, phone or email from Shopify | A business's Shopify store | Show you where your order is | The business concerned |
| Household access | Grants, sealed labels, invitation code hash | You | Share the access you choose | The person you invite |
| Security and audit | Actor, action, outcome, internal IDs, redacted metadata | Our systems | Detect fraud, investigate incidents, show you notices | Businesses see a projection with only their own pseudonym for you |
| Network and abuse data | IP address (as a /64 range for IPv6), rate-limit counters, abuse counters | Automatic | Stop abuse and attacks | Cloudflare and Fly.io |
| Support and appeals | Ticket text (encrypted), status | You | Resolve your request | None |
| Verification (planned) | Request, minimized result, method, consent receipt, provider session ID | You, verification provider | Confirm one attribute you choose to share | The business receives only the requested attribute |

## What businesses receive

- A **pairwise reference**: a value computed for each business and you, stable for that business and unrelated to any other business's reference.
- Your **decisions** and replies, with the time, channel and assurance level. For approvals, a compact signed result from a key your device created for that business.
- **Messages** you send it and your **consent state** for its purposes.
- If you turned on Loops and allowed the business: what you choose or enter in its **Loops** and the outcome.
- For Verify (planned): only the **attribute** you agreed to share, with its provenance and validity.

A business does not receive your Viadere identity, phone number, other connections or device identifiers, unless you tell it.

## What we do not collect

- No advertising identifiers, no contacts, no device location, no browsing history.
- No raw identity documents, selfies, birthdates or face templates on our servers.
- No private keys.
- No plaintext phone numbers or message bodies at rest.
- No email address or password for consumer accounts.
- No payments: Viadere does not accept, process or hold payments or card details, and is never the seller. A business that uses Shopify sends you to its own checkout.
- No health information requested: healthcare providers may not use Viadere, and no business may use it to collect health information. Please do not send health details through Viadere.

## Biometrics

Face ID and Touch ID run in the operating system on your device, and Viadere never receives biometric data from them. If Verify launches and you choose the document method, a verification provider (Didit) captures a document photo, selfie and liveness video from your device, and Viadere does not receive them. See [device and server](/privacy/device-and-server/) and the [Privacy Notice](/legal/privacy-notice/).

## Text messages

SMS is not end-to-end encrypted. Carriers and our messaging providers can read ordinary text messages. We encrypt message text before it is stored in our database. See [controls](/privacy/controls/).
