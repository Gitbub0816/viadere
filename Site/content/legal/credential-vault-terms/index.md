---
title: Credential Vault Terms
order: 10
description: "Recovery, device loss and synchronization for Authenticator. Authenticator is planned."
version: 0.1.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "First draft."
disclosures: [device_custody, encryption]
---
::: callout
Authenticator is [planned](/products/authenticator/) and not available. These terms are a draft for review.
:::

## 1. What the vault holds

[PRODUCT: credential types the vault will hold.]

## 2. Device custody

::: disclosure
Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.
:::

## 3. Synchronization and recovery

::: disclosure
Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.
:::

Unlocking and recovering the vault is designed to be independent of identity verification. Viadere cannot recover non-exportable keys. [COUNSEL AND ENGINEERING: recovery model, what happens when the recovery method is lost, and the release gate of an independent cryptography and recovery review.]

## 4. Responsibilities, limits and ending the service

[COUNSEL: customer responsibilities, liability limits, export, and what happens to vault data when the account ends.]
