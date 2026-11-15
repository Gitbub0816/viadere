---
title: Products
layout: marketing
headline: One platform. *Each part with its real status.*
description: Messaging, Approve, Wallet passes, Verify, Authenticator and the rest share one verified business registry, one consent model and one delivery layer. Each carries its real status.
order: 0
hero_art: stage
actions:
  - label: For businesses
    href: /businesses/
  - label: Developer docs
    href: /developers/
---
::: section
::: section-head
## Each product, *with its real status.*

Messaging, Approve and Wallet passes are in beta: built, in pre-release testing and not generally available. Everything marked planned is not available, including what is already built and held behind a release gate.
:::

{{ generate: product-cards }}
:::

::: section alt
::: feature
::: feature-copy
::: kicker
{icon:seal} What the badges mean
:::
## Nothing is called available unless it is.

Status badges on this site follow one rule, and the build of this site fails if a product page is missing one or overstates it.

- {badge:live} **Generally available** to eligible businesses and customers.
- {badge:beta} **Built and in pre-release testing.** Not generally available. Interfaces, limits and pricing may change, and no availability commitment is published yet.
- {badge:planned} **Not available.** Some planned products are already built and held behind a release gate until their reviews pass. Each page says how far it has got, and nothing on it is a promise of a date or a feature.
:::
::: feature-art
{{ generate: mockup signin }}
:::
:::
:::

::: section
::: section-head
::: kicker
{icon:repeat} One platform
:::
## Integrate once. *Every product follows.*

Every product relies on the same verified business registry, purpose-scoped consent and signed results. Businesses integrate once through the [Business API](/developers/).
:::

{{ generate: mockup flow }}
:::

::: section alt
::: section-head
::: kicker
{icon:message} Channels
:::
## The right channel, never a weaker answer.

Messaging can fall back to text when the app is not available. Ordinary SMS is not end-to-end encrypted, and a sensitive request is never approved by text.
:::

{{ generate: mockup channels }}
:::
