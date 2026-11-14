---
title: The Viadere code
nav_title: Viadere code
layout: marketing
status: planned
order: 7
icon: scan
headline: The Viadere code. *A code that carries a link, and no secret.*
tagline: The optical code on the Sign in with Viadere page and in the Verify web button, read by the scanner in the Viadere app. Not released.
description: The optical code on the Sign in with Viadere page and in the Verify web button, read by the scanner in the Viadere app. Not released.
---
::: section
::: prose
The Viadere code is the optical code shown on the [Sign in with Viadere](/products/sign-in/) page and in the panel of the Verify with Viadere web button. It is drawn in the CKey optical code format, in place of a QR code. The app's scanner reads it, and reads QR codes too.

::: callout
**Built, not released.** The code is drawn on the staging sign-in page and by the Verify web button, neither of which is released, and the scanner is written. The scanner has not been run on a physical device, so how reliably it reads from real screens is unmeasured. No date is promised.
:::
:::
:::

::: section alt
::: section-head
::: kicker
{icon:scan} What it is
:::
## The same link a QR code would hold.
:::

::: grid grid-3
::: card
### {icon:eye-off} No secret inside
The code holds one sign-in link and nothing else: no number, no account, no website name and no secret.
:::
::: card
### {icon:seal} It changes nothing about trust
Scanning only tells the app which sign-in to look up. The app then fetches a signed statement, shows the website from that statement, and still asks for the number on the page.
:::
::: card
### {icon:repeat} A QR code stays one link away
The same link is offered as an ordinary QR code on the same page, for a phone whose camera opens it directly. That fallback stays until testing on devices passes.
:::
:::
:::

::: section
::: feature
::: feature-copy
::: kicker
{icon:lock} The scanner
:::
## One gate between the camera *and the app.*

Everything the scanner reads is treated as hostile text and passes one check before any other part of the app sees it.

- {icon:check} **Viadere links only.** A link must be an `https` link on Viadere's own link domain. Every other scheme is refused. A bare business handle or code is accepted only from a QR code, and is only looked up.
- {icon:check} **Nothing runs by itself.** CKey can carry actions meant to run without a prompt. The scanner refuses all of them. Every request is reviewed on screen.
- {icon:check} **A screen, never a decision.** An accepted code opens a review screen. It approves nothing.
- {icon:check} **Scanned text stays put.** The scanner never shows, copies, logs or opens what it read.
:::
::: feature-copy
::: kicker
{icon:x} Limits we state
:::
## What is not done yet.

- The decoder for the code is third-party code that works on camera frames, and its format is still a draft. It is pinned to one exact reviewed version.
- That decoder is not written in a memory-safe language. Its input is bounded, and it is not sandboxed. Moving it out of the app's process is open work.
- The Verify with Viadere button for websites, in its current version, also opens on the Viadere code, with the QR code one control away. The buttons inside iOS and Android apps still show a QR code first.
- Connect links and dashboard codes remain QR codes. They are read by a phone's own camera, often without the app installed.
- The Viadere code depends on its own colours. In a high-contrast display mode the web button shows the QR code only.
- A copied or relayed code can still name a real sign-in. The number on the page and the website the app names are what protect you.
:::
:::
:::

::: section alt
::: prose
Related: [Sign in with Viadere](/products/sign-in/), [safety and reporting](/consumers/safety/) and the [security architecture](/security/architecture/).
:::
:::
