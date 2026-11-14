---
title: API reference
nav_title: API reference
order: 20
description: Every operation of the Business API, generated from the OpenAPI contract.
wide: true
---
All paths are relative to `https://viadere.com`. Authenticate with `Authorization: Bearer vdk_live_…` or `vdk_test_…`. See [authentication](/developers/authentication/), [errors](/developers/errors/), [rate limits](/developers/rate-limits/) and [idempotency](/developers/idempotency/). Data types are listed under [schemas](/developers/schemas/).

Not every tag below is released. Approve, KeyDirectory and LinkSessions belong to Approve v2, which is built and held behind a release gate. Verification is built and not released. While a feature is switched off, its routes answer `404`.

Magic-link, one-time-code and security-notice delivery is a separate contract with its own reference: [authentication delivery](/developers/auth-delivery/).

{{ generate: api-index }}
