---
title: Onboarding
order: 1
description: How a business gets verified, receives credentials and goes live.
---
## 1. Apply

Create an organization. It starts as pending. A Viadere reviewer verifies it, and your handle and permanent code are issued only on approval. Until then you cannot create API keys or webhooks, and you cannot issue requests.

[COUNSEL AND PRODUCT: business verification checks, evidence required and renewal cadence by risk tier.]

## 2. Sign in without a password

The dashboard uses passkeys. There are no passwords. Dashboard roles are least privilege: owner, admin, developer, support and analyst.

## 3. Create keys with the least scope

Each key has only the scopes it needs, is revocable and is shown once. Use `vdk_test_` keys while building and `vdk_live_` keys in production. See [authentication](/developers/authentication/).

## 4. Add a webhook endpoint

The signing secret is shown once. Your URL must be a public `https` address, and redirects are never followed. See [webhooks](/developers/webhooks/).

## 5. Test, then go live

Use the sandbox to rehearse every outcome. When you are ready, follow the [go-live checklist](/developers/quickstart/#go-live-checklist).

## Responsibilities

You remain responsible for your own access decisions, for the content of your messages, and for the consent you hold. See the draft [Business Services Agreement](/legal/business-services-agreement/) and [Acceptable Use Policy](/legal/acceptable-use-policy/).
