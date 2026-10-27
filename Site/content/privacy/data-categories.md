---
title: Data categories
order: 1
description: The kinds of data Viadere handles and the default treatment of each.
---
| Data class | Examples | Preferred custody | Default treatment |
|---|---|---|---|
| Public | A verified business directory listing | Viadere | Public, with review and correction |
| Operational | Message routing IDs, delivery state | Viadere | Minimized, isolated per business, time-bound |
| Security metadata | Public keys, nonces, audit events | Viadere and the business | Integrity-protected and retained by policy |
| Identity assertions | An age-threshold result, proof metadata | Device and business, with minimal Viadere metadata | Purpose-bound, expiring, minimal correlation |
| Raw identity evidence | An ID image, birthdate, selfie | Issuer, device or provider | Avoided centrally; short retention if unavoidable |
| Passkey private keys | Third-party account credentials | The customer's device or an encrypted vault | Never in server plaintext |
| Sensitive message payloads | Health or financial details | Intended endpoints where feasible | Designed for end-to-end encryption; no plaintext relay logging |

## Account and contact data

Viadere also holds account data (for example a linked phone number and registered devices) needed to deliver requests. [COUNSEL: full list by processing activity, with controller and processor roles.]

## What businesses receive

A pseudonym per customer, the decisions the customer makes, and messages the customer sends them. They do not receive your Viadere identity or phone number. An approval result carries a device pseudonym and the server's attestation, not the raw device-signed record.

## What we try not to collect

Biometric templates and raw identity documents. Face ID is handled by the operating system on your device. If a verification provider is used, we will document whether Viadere ever receives biometric data. [COUNSEL: biometric privacy law assessment.]
