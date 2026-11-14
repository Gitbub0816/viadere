---
title: Wallet and rewards
nav_title: Wallet and rewards
layout: marketing
status: beta
order: 3
icon: wallet
headline: Wallet and rewards. *Passes that stay current.*
tagline: Points, perks and single-use codes, with Apple Wallet passes that Viadere signs and keeps up to date.
description: Points, perks and single-use codes, with Apple Wallet passes that Viadere signs and keeps up to date.
hero_art: wallet
actions:
  - label: Wallet API
    href: /developers/api/wallet/
  - label: Rewards API
    href: /developers/api/rewards/
---
::: section
::: section-head
::: kicker
{icon:gift} What it does
:::
## A loyalty program *without a second app.*

A business can run points, status levels, coupons and recurring perks, such as a free coffee on Tuesdays. The customer sees them in Viadere and can add a pass to Apple Wallet.
:::

::: grid grid-3
::: card
### {icon:server} Decided on the server
Eligibility is decided on Viadere's servers, never on the phone. The app shows a reward's state and offers its button only when the server says so.
:::
::: card
### {icon:check} Used exactly once
Validating a code and consuming it are one step. If two tills submit the same code at once, exactly one succeeds.
:::
::: card
### {icon:bell} Never a marketing channel
A pass update can change only the venue, the seat, the start time or the code, at most six times a day. No other text on a pass can be changed.
:::
:::

::: callout
**Beta.** Rewards and Wallet passes are built and in pre-release testing. They are not generally available. Issuing a pass depends on Viadere's Apple pass certificate, which is an outstanding setup step, and the pass flow has not yet been tested on a physical device. By default every pass carries a “Beta” label.
:::
:::

::: section alt
::: section-head
::: kicker
{icon:wallet} Passes
:::
## Every pass, *one signer.*

Viadere signs every pass with its own certificate and keeps it up to date. A business never handles a pass file.
:::

| Pass | Comes from | Kept current by |
|---|---|---|
| Loyalty card | The customer's membership | Points and status, when the business adjusts points |
| Coupon | A reward the customer can see | Voided when it is redeemed, or when the business withdraws the reward |
| Event ticket or boarding pass | A ticket the business sent | Venue, seat or start time changes; voided when the ticket is cancelled |
| Reservation or appointment | A ticket the business sent | The same three fields; checked in once |
:::

::: section
::: prose
::: kicker
{icon:scan} At the till or the door
:::
## One scan, *one clear answer.*

The code on a pass is a signed presentation code, not the pass's serial number. The business scans it and sends it to the Business API.

- {icon:check} **A coupon** is redeemed, exactly once, and its pass is voided.
- {icon:check} **A ticket or reservation** is checked in once, inside its validity window.
- {icon:check} **A loyalty card** returns the member and the balance.
- {icon:x} **Anything else** gets one identical answer: forged, altered, rotated, or another business's code.

If a business suspects a code was copied, it can rotate it. The old code stops working and the customer's pass updates.
:::
:::

::: section alt
::: grid grid-2 gap-lg
::: card
### {icon:eye-off} What a pass never contains
- No phone number, email address or name, not even the ticket holder's.
- No member number and no redemption code.
- No location data.

A business is never told whether a customer added a pass to Wallet.
:::
::: card
### {icon:x} What it does not do
- Rewards and marketing never exceed normal priority, and they are a separate consent from security and service messages.
- There is no tap-to-redeem by NFC. That needs an entitlement from Apple that Viadere does not hold.
- A pass keeps Viadere's colours and icon. A business's [Brand Kit](/products/brand-kits/) does not style the signed pass.
- A voided pass shows as void in Wallet only after its next refresh. Its code is refused at once.
:::
:::

Related: [Messaging](/products/messaging/), the [Wallet API](/developers/api/wallet/) and the [Rewards API](/developers/api/rewards/).
:::
