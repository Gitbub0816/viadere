---
title: Auth delivery schemas
nav_title: "Auth delivery: Schemas"
order: 49
api: auth-delivery
eyebrow: Auth delivery reference
description: Every request and response type of the authentication-delivery contract, generated from its OpenAPI file.
wide: true
---
These types belong to the [authentication delivery](/developers/auth-delivery/) contract, version `{{api-version}}`. The Business API has its own [schemas](/developers/schemas/). There is no `sms` channel here, and `email` is refused until its fallback gate is met.

{{ generate: schemas }}
