---
title: Onboarding
layout: marketing
order: 1
headline: From application *to first live request.*
description: How a business gets verified, receives credentials and goes live.
actions:
  - label: Read the quickstart
    href: /developers/quickstart/
---
::: section
::: steps
::: card
### Apply
Create an organization. It starts as pending. A Viadere reviewer verifies it, and your handle and permanent code are issued only on approval. Until then you cannot create API keys or webhooks, and you cannot issue requests.

[COUNSEL AND PRODUCT: business verification checks, evidence required and renewal cadence by risk tier.]
:::
::: card
### Sign in without a password
The dashboard uses passkeys. There are no passwords. Dashboard roles are least privilege: owner, admin, developer, support and analyst.
:::
::: card
### Create keys with the least scope
Each key has only the scopes it needs, is revocable and is shown once. Use `vdk_test_` keys while building and `vdk_live_` keys in production. See [authentication](/developers/authentication/).
:::
::: card
### Add a webhook endpoint
The signing secret is shown once. Your URL must be a public `https` address, and redirects are never followed. See [webhooks](/developers/webhooks/).
:::
::: card
### Test every outcome
Use the sandbox to rehearse approve, deny, expiry, cancellation and “not me”. A test key can never reach a real customer.
:::
::: card
### Go live
When you are ready, follow the [go-live checklist](/developers/quickstart/#go-live-checklist).
:::
:::
:::

::: section alt
::: prose
## Responsibilities

You remain responsible for your own access decisions, for the content of your messages, and for the consent you hold. See the draft [Business Services Agreement](/legal/business-services-agreement/) and [Acceptable Use Policy](/legal/acceptable-use-policy/).
:::
:::
