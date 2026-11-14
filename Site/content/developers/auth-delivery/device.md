---
title: Device endpoints
nav_title: "Auth delivery: Device"
order: 47
api: auth-delivery
eyebrow: Auth delivery reference
description: The operations the Viadere app calls to list, open and deny a delivery. Listed so you can see the whole contract. Your server never calls them.
wide: true
---
::: callout
**Called by the Viadere app, not by your server.** These operations take a device-signed bearer, which a business key cannot produce. They are part of the contract, so they are shown here. The secret is revealed once, to the customer's own device.
:::

{{ generate: api-tag Device }}
