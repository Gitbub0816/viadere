---
title: Sign in with Viadere
nav_title: Sign in
layout: marketing
status: planned
order: 6
icon: key
headline: Sign in with Viadere. *A sign-in you confirm yourself.*
tagline: An OpenID Connect sign-in that a website can offer, confirmed with a passkey or in the Viadere app. It exists in staging only.
description: An OpenID Connect sign-in that a website can offer, confirmed with a passkey or in the Viadere app. It exists in staging only.
---
::: section
::: prose
Sign in with Viadere is an OpenID Connect provider. A website that is registered with Viadere sends a visitor to a Viadere sign-in page, the visitor confirms there, and the website receives a signed token with an identifier made for that website alone.

::: callout
**Staging only. Not available.** The provider is built and tested, and it is switched off by default. It cannot be switched on in a production environment. There is no way for a website to sign up for it, and no date is promised.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:key} Two ways to confirm
:::
## A passkey first, *the app as the other option.*
:::

::: grid grid-2 gap-lg
::: card
### {icon:passkey} Your Viadere passkey
Offered first. The browser asks for the passkey with user verification, and the sign-in page accepts it only for Viadere's own sign-in address.
:::
::: card
### {icon:phone} The Viadere app
The page shows a two-digit number and a [Viadere code](/products/viadere-code/). The app shows which website is asking and where you will be sent, asks for the number from the page, and signs with a key that needs Face ID or your passcode.
:::
:::

::: callout
**Not the same as phishing-resistant sign-in.** Confirming in the app, even with the number, can be relayed: someone can show you a genuine code for a sign-in they started. The number reduces that risk and does not remove it. Scan a code only on a page you opened yourself, and check the website the app names.
:::
:::

::: section
::: section-head
::: kicker
{icon:split} What the website receives
:::
## An identifier for that website, *and little else.*
:::

::: grid grid-3
::: card
### {icon:split} A pairwise identifier
Each website gets its own identifier for you. Two websites cannot match you by comparing them.
:::
::: card
### {icon:eye-off} No profile
The only scope is `openid`. The user-info answer contains that identifier and nothing more: no name, no email address, no phone number.
:::
::: card
### {icon:clock} Short-lived
The sign-in code is single use and lasts 60 seconds. The identity token lasts five minutes. There is no refresh token.
:::
:::
:::

::: section alt
::: grid grid-2 gap-lg
::: card
### {icon:server} A separate signer
Tokens are signed by a private authority that runs apart from the main service and signs only what its own records say. A refused attempt gets one generic answer, and the reason goes to an append-only audit log.
:::
::: card
### {icon:code} For the website
The authorization code flow with PKCE, a required `nonce`, and client authentication with a signed assertion from a registered key. A website is registered only through a reviewed step. There is no self-service registration.
:::
:::

This is a different thing from [Approve](/products/approve/), where a business you already use asks “is this you?”. Related: the [Viadere code](/products/viadere-code/) and the [security architecture](/security/architecture/).
:::
