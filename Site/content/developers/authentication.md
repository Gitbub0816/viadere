---
title: Authentication
order: 2
description: API keys, scopes and the sandbox.
wide: true
---
{{ generate: info-section Authentication }}

## Scopes

| Scope | Allows |
|---|---|
| `interactions:write` | issue and cancel interactions |
| `interactions:read` | read outcomes |
| `messages:write` | send messages |
| `statuses:write` | publish ongoing-event statuses |
| `webhooks:manage` | manage webhook endpoints through the API |
| `rewards:write` | loyalty program, rewards, points and redemption validation |

Give each key only the scopes it needs. Keep keys on your server: never ship one in an app or a web page.

## Test mode (sandbox) {#sandbox}

{{ generate: info-section Test mode }}

## Security model

{{ generate: info-section Security model }}
