---
title: Authentication
order: 2
description: API keys, scopes, capabilities and the sandbox.
wide: true
---
{{ generate: info-section Authentication }}

## Scopes

A scope says which routes a key may call.

| Scope | Allows |
|---|---|
| `interactions:write` | issue and cancel interactions |
| `interactions:read` | read outcomes |
| `messages:write` | send messages |
| `statuses:write` | publish ongoing-event statuses |
| `webhooks:manage` | manage webhook endpoints through the API |
| `rewards:write` | loyalty program, rewards, points and redemption validation |
| `wallet:write` | issue, list, update and void Wallet passes, and validate scanned pass codes. Live keys only |
| `approvals:manage` | Approve v2: enrollments, requests, results and freeze. Built, behind a release gate |
| `keydirectory:manage` | publish and read your key-directory entries for Approve v2 |
| `links:manage` | link sessions, which connect a customer from your own signed-in page |
| `profiles:read` | ask a customer for profile fields in a category Viadere allowed your business |
| `auth_deliveries:write`, `auth_deliveries:read` | [authentication delivery](/developers/auth-delivery/), a staging pilot that is off by default |

Give each key only the scopes it needs. Keep keys on your server: never ship one in an app or a web page.

## Capabilities {#capabilities}

{{ generate: info-section Capabilities and key scopes }}

| Capability | Granted | Needed for |
|---|---|---|
| `message.send` | By default | messages, statuses and every interaction kind except `authenticate` and `authorize` |
| `contact.reachable` | By default | checking that an existing connection can receive messages |
| `consent.request` | By default | asking a customer to grant a purpose |
| `auth.challenge` | After review | sign-in approvals |
| `transaction.approve` | After review | transaction approvals |
| `age.minimum`, `identity.name`, `identity.address`, `identity.verified` | After review | [Verify](/products/verify/), which is built and not released |

Use separate keys: one that carries only `message.send` for your notification service, and a distinct key for sign-in or payment approvals. A leaked messaging key then cannot approve anything.

## Key format and lifecycle {#key-lifecycle}

- **Format.** `vdk_<test|live>_<kid>.<secret>`. The 16-character `kid` is not secret: quote it in support requests and logs. The secret is shown once, when you create or rotate a key.
- **Expiry and allow-list.** A key can carry an optional expiry of 30, 90 or 365 days and an allow-list of up to 20 addresses or CIDR blocks.
- **Rotation with overlap.** Rotating issues a replacement with the same scopes and capabilities and keeps the old key working for the overlap you pick: none, 1 hour, 1 day, 7 days or 30 days.
- **Revocation** takes effect on the next request.
- **If a key leaks:** revoke it, create a replacement, and rotate any webhook secret that key could manage.

## Customer references {#customer-references}

{{ generate: info-section Customer references }}

## Test mode (sandbox) {#sandbox}

{{ generate: info-section Test mode }}

## Security model

{{ generate: info-section Security model }}
