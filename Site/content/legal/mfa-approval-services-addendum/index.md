---
title: MFA and Approval Services Addendum
order: 9
description: "Key enrollment, signature validation, fallback and dispute handling for Approve."
version: 0.1.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "First draft."
disclosures: [mfa]
---
## 1. Relying-party key enrollment

The customer's device creates a key for each business relationship at an enrollment the business authorizes. The business receives that public key and the key ID, and no device identifier is shared across businesses. [COUNSEL AND ENGINEERING: enrollment terms and key rotation.]

## 2. Signature validation

The business validates every signed result itself with the enrolled public key. A delivery or relay status alone is not evidence of approval. A decision made over a text channel carries no device assurance and is not an approval of a sensitive action.

## 3. Business responsibility

::: disclosure
Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.
:::

## 4. Fallback

A sensitive request is never downgraded to a yes or no text. [COUNSEL AND PRODUCT: fallback rules when the app is not available.]

## 5. Disputes

Viadere keeps the raw device-signed decision and can export it for a dispute. [COUNSEL: dispute process, evidence format and timelines.]

## 6. Limits

A simple approve or deny prompt is not phishing-resistant authentication. [COUNSEL: assurance statements permitted in marketing and contracts.]
