---
title: Products
layout: marketing
headline: Four products. *One verified identity.*
description: Messaging, Approve, Verify and Authenticator share one verified business registry, one consent model and one delivery layer. Each carries its real status.
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

Messaging and Approve are in beta for approved businesses. Verify and Authenticator are planned and not available.
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
- {badge:beta} **Working and in use by approved businesses.** Interfaces, limits and pricing may change, and no availability commitment is published yet.
- {badge:planned} **Designed but not available.** Nothing on a planned product page is a promise of a date or a feature.
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

All four products rely on the same verified business registry, purpose-scoped consent and signed results. Businesses integrate once through the [Business API](/developers/).
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
