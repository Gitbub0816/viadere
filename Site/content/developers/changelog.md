---
title: Changelog
order: 80
description: Versions of the Business API and what changed.
wide: true
---
The API is versioned by date. The current version of the Business API contract is `{{api-version}}`.

## 2026-11-02: authentication delivery {#auth-delivery-2026-11-02}

A second contract, [authentication delivery](/developers/auth-delivery/), is documented at version `2026-11-02`. It is a staging pilot and off by default. It adds webhook [signature v2](/developers/webhooks/#signature-v2) and the `auth.delivery.*` events.

## 2026-10-28 {#v2026-10-28}

The contract at this version also documents, beyond the first version below:

- Capabilities: `GET /v1/business/capabilities`, and the `insufficient_scope`, `not_entitled`, `capability_disabled` and `policy_denied` errors.
- API key ids, expiry, allow-lists and rotation with overlap.
- Webhook endpoint verification, test events, pause and resume, and the `Viadere-Delivery-Id` and `Viadere-Key-Id` headers.
- Wallet passes: issue, list, update, void and scan.
- Approve v2, the key directory and link sessions. Built, and behind a release gate.
- Verification requests and sessions, and the `verification.completed` event. Built, and not released.
- Profile requests.
- `subjectRef` as the customer reference. The older `consumerId` and `consumerReference` are deprecated.

## 2026-10-27 {#v2026-10-27}

First documented version of the Business API (beta).

- Interactions: issue, read the outcome and cancel.
- Messages and ongoing-event statuses.
- Sandbox relationships for test keys.
- Webhook endpoints, signed deliveries and secret rotation.
- Loyalty program, rewards, points and redemption validation.
- Webhook events: `interaction.decided`, `interaction.expired`, `interaction.cancelled`, `message.received`, `relationship.connected`, `relationship.disconnected`, `consent.updated` and `reward.redeemed`.

## Migration guides

None yet. A migration guide will be published here before any breaking change takes effect.

## Subscribing to changes

[PRODUCT: a changelog feed or email list. None exists today.]
