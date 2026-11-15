---
title: Rate limits
order: 60
description: Request rates, daily quotas and the controls that reduce them.
wide: true
---
{{ generate: info-section Rate limits }}

## Quotas and trust

- **API rate:** per business, default burst 120 and 600 requests per minute.
- **Daily quota:** live interactions per UTC day. The free tier default is 1,000.
- **Abuse controls:** each business has a complaint rate ("not me" reports divided by interactions) and an opt-out rate. Above the configured thresholds, your quota and API rate are automatically cut until the rates recover. Operators can also throttle, lower priority or suspend a business.
- **Redemption validation** is limited to 60 requests per minute, burst 30, per business, because that bounds code guessing.

Test-key traffic is never counted against your quota or billed. When a limit is hit, honour `Retry-After`. The Swift SDK does this for you.
