# Verify with Viadere — integration guide (web, iOS, Android)

Let a customer prove something about themselves (that they are 18 or 21 or older, their verified name or address, or simply that they have a
verified identity) by tapping **Verify with Viadere** on your website or in your app. The customer sees in their Viadere app which verified
business is asking, on which site, and exactly what you would learn; nothing is shared until they approve. Your **server** receives a result
signed by Viadere.

Security model and wire formats: `docs/SECURITY.md` §2.100 (sessions), §2.60 (Verify) and §2.104 (the Viadere code). Artwork and usage
rules: `Design/embeds/index.html`.

## How it works

```
your server ──POST /v1/business/verification-sessions──▶ Viadere      (capability, purpose, origin; live API key, server side only)
your server ◀──── {session_id, code, link, expires_at} ─────────────── (link = https://viadere.io/v/{CODE}, valid ≤ 5 min, single use)
your page/app ── shows the button with `link` ──▶ customer taps it
   phone:     the OS hands the link to the Viadere app (universal link / App Link)
   computer:  panel → the Viadere code first, "Scan with the Viadere app"  [Use your phone's camera instead: the same link as a QR code]
              [Choose another option: open here · enter code · send to my phone · get the app]
Viadere app ── shows the verified business, its domain, the origin, what is shared ── customer continues, consents, verifies (Wallet ID or document)
your server ◀── verification.completed webhook (optional) / poll GET /v1/business/verification-sessions/{id}
your server ── verifies Viadere's signed VerificationSessionResult ──▶ decides (never trust the browser or your app)
```

Rules that keep it phishing-resistant — follow them:

1. **Create the session on your server, right when you show the button**, for the origin the page is on (`https://shop.example`). The origin
   must be one of your verified domains (dashboard → Domains) or a subdomain. A session lives at most five minutes and is used once; create a
   new one when the page is shown again or `onExpired` fires.
2. **Keep `session_id` on your server**, tied to the visitor's own session (cookie or app session). Never accept a session id from the
   browser as proof of anything.
3. **Decide only from the signed result**, verified on your server (`verifiedVerificationSession` in the Swift SDK, or the same checks in your
   language: §2.100 step 5). A click, a return to your page or anything your front end says is not a verification.
4. **Never send the link by email, SMS or chat, and never put the button in an email.** The app tells people to stop when the site they are
   on is not the one the request names.
5. A verification is not a login. Do not sign anyone in, or link an account, because a session completed.

## 1. Your server

### Swift (`ViadereBusinessSDK`)

```swift
let client = try ViadereBusinessClient(apiKey: liveKey)                       // live keys only
let ticket = try await client.createVerificationSession(CreateVerificationSessionRequest(
    capability: .ageMinimum, parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase",
    origin: "https://shop.northwind.example", returnURL: "https://shop.northwind.example/checkout",
    callbackId: verificationWebhookId))                                        // optional: a registered webhook endpoint id
// Store ticket.sessionId with the visitor's session; give ticket.link (and ticket.expiresAt) to the page or app.

// Later (webhook `verification.completed`, or polling every 2–3 s while the panel is open):
let verified = try await client.verifiedVerificationSession(id: ticket.sessionId, businessId: myBusinessId,
    origin: "https://shop.northwind.example", capability: .ageMinimum, viadereKeys: pinnedLinkDescriptorKeys)
if verified.outcome == .verified { /* allow the purchase for this visitor's session */ }
// identity.name / identity.address: the values come once from client.verificationResult(ref: verified.resultRef).
```

`verifiedVerificationSession` throws `notCompleted(status)` until the person finished, and `resultInvalid` / `resultRefMismatch` when the
result is not Viadere's or not this session's. `viadereKeys` are the `link-descriptor` public keys Viadere publishes for your environment
(the same keys you pin for link sessions).

### HTTP

| Call | Body / answer |
|---|---|
| `POST /v1/business/verification-sessions` | `{capability, parameters?, purpose_code, origin, return_url?, callback_id?, expires_in_seconds? (60–300)}` → `201 {session_id, code, link, expires_at}` |
| `GET /v1/business/verification-sessions/{id}` | `{session_id, status, capability, purpose_code, origin, created_at, expires_at, request_id?, subject_ref?, result_ref?, result?, completed_at?}` |
| `POST /v1/business/verification-sessions/{id}/cancel` | ends an `open` session |

`status`: `open` → `accepted` (the person continued in the app) → `completed` (`result` present), or `expired` / `cancelled`. `result` is a
`{kid, payload, signature}` statement: verify the ES256 signature over `"VIADERE-VERIFY-SESSION-RESULT-V1\n" ‖ payload` with a pinned key, then
check `session_id`, `business_id`, `origin`, `capability` and `SHA-256(result_ref) == result_ref_digest` (§2.100).

## 2. Web

Two static files, no dependencies, no build step, served immutable with CORS for Subresource Integrity. They make **no network requests**, use
no cookies or storage, no `innerHTML`, no inline styles and no `eval`, so they work under a strict Content Security Policy with Trusted Types.

```html
<link rel="stylesheet" href="https://viadere.io/verify-button/v2/viadere-verify.css"
      integrity="sha384-XtMMnzTRtL0QFL0OME+vtc3hVosP+uUo7CMRClSuFFDGRBXn+BIlxoyVfzcPmZMX" crossorigin="anonymous">
<script src="https://viadere.io/verify-button/v2/viadere-verify.js" defer
        integrity="sha384-DUA1uh14Jmon7lYsHvBm/riJrkLlLT+utjm+BQNTTXG2DlKbSddAoW5Kj714F6xL" crossorigin="anonymous"></script>

<viadere-verify link="https://viadere.io/v/K7QFM2XA" expires-at="2026-11-02T10:05:00Z">
  <!-- Fallback without JavaScript: the same link, styled by the stylesheet. -->
  <a class="vdv-btn vdv-filled vdv-md" href="https://viadere.io/v/K7QFM2XA" rel="noopener noreferrer" referrerpolicy="no-referrer">Verify with Viadere</a>
</viadere-verify>
```

`GET https://viadere.io/verify-button/v2/integrity.json` publishes the hashes; a published file never changes in place, a change ships
under a new version path (see "Versions" below). You may also self-host the two files (pin them by hash in your build). CSP for the page: `script-src` and `style-src` must allow the files'
origin (`https://viadere.io`, or `'self'` when self-hosted); nothing else is needed (`connect-src`, `frame-src`, `img-src` stay closed).

| Attribute | Values |
|---|---|
| `link` | **Required.** The ticket's `link`. Anything that is not exactly `https://viadere.io/v/{CODE}` (or the staging `https://staging.viadere.io/v/{CODE}`) renders nothing |
| `variant` | `filled` (default: charcoal, ivory in dark mode), `ivory` (dark or photographic backgrounds), `outline` |
| `size` | `sm` (36 px), `md` (44 px, default), `lg` (52 px) |
| `display` | `label` (default) or `icon` (mark only; the accessible name stays "Verify with Viadere") |
| `theme` | `auto` (default: follows the visitor), `light`, `dark` |
| `expires-at` | ISO 8601; the panel says until when the code works |
| `send-to-phone` | Boolean. Offer "Send to my phone" (see below) |

Behaviour: on a phone or tablet the button is an ordinary link to the session, so iOS and Android hand it to the Viadere app (or open the
landing page, which offers the app). On a computer it opens a modal panel with the **Viadere code first** ("Scan with the Viadere app"): the
session link drawn as a CKey optical code, which the Viadere app's scanner reads. One control below it, **"Use your phone's camera
instead"**, swaps it for the same link as a **QR code** ("Scan with your phone's camera"), which any phone camera reads, also when the app is
not installed yet; "Back to the Viadere code" swaps back. Then "Choose another option": open Viadere on this device, enter the code in the
app (`ABCD-EFGH`, announced to screen readers), send to my phone (only with `send-to-phone`), get the app. Keyboard and screen-reader
accessible: a native modal `<dialog>` with a focus trap, both codes have an accessible name, a change of code is announced, Escape and the
close button return focus to the button. In forced-colours (high contrast) mode the panel shows the QR code only, black on white, and says
why: the Viadere code depends on its own colours. Modified clicks (new tab) keep the browser's behaviour.

Both codes carry exactly the `link` attribute after validation and nothing else: no secret, nothing about your business or the visitor. The
Viadere code is drawn in the browser by the script (shapes, gradients and filters as SVG elements; no image, no request); its colours are the
CKey "concept" preset's and do not follow `theme` or your page.

Events (bubbling): `viadere-verify-open`, `viadere-verify-close`, `viadere-verify-send` (`detail.link`). Methods: `open()`, `close()` — call
`close()` when your server sees the session completed (for example from a page that polls **your** server).

**Send to my phone.** Only for a visitor who is already a connected customer whose `subject_ref` your server knows (a signed-in customer):
on `viadere-verify-send`, ask your server to create an ordinary verification request for that `subject_ref`
(`POST /v1/verification-requests`), which Viadere delivers to their phone as a notification. The button never sends anything itself, and
there is deliberately no way to push to a phone number or handle a visitor types in.

A complete page that needs no inline script or style: [`docs/examples/verify-button.html`](examples/verify-button.html).

### Versions

| Version | Panel on a computer | Files | Size |
|---|---|---|---|
| **v2** (current) | Viadere code (CKey) first; QR code one control away; other options | `/verify-button/v2/` | script 47 KB (16 KB gzip), stylesheet 9 KB |
| v1 | QR code first; other options | `/verify-button/v1/` | script 23 KB, stylesheet 8 KB |

What changed in v2: the panel opens on the Viadere code, with "Use your phone's camera instead" / "Back to the Viadere code" to swap between
the two codes; the button in the options view that returns to the code reads "Back to the code" (v1: "Back to the QR code"); the forced-colours
behaviour above. Nothing else: the same element name, attributes, events, methods, link validation, button appearance, phone hand-off, CSP
requirements and Trusted Types compatibility. The script is larger because it contains the CKey encoder and renderer (a port of the CKey
reference core, MIT licence, notice in the file and in `docs/THIRD-PARTY-NOTICES.md`).

**Migrating from v1.** Change the two URLs from `/v1/` to `/v2/` and replace both `integrity` values; nothing in your markup, your CSP or your
server changes. **v1 keeps working and stays QR-only**: its files are immutable and stay served at the same URLs with the same hashes, so a
page that pinned v1 is unaffected until you choose to move. v1 was frozen before the production domain was chosen and still matches the placeholder host and the retired staging host (`viadere.cksites.dev`) it was published with, so since staging moved to `staging.viadere.io` (2026-11-16) it renders no current link at all: every page uses v2 (an owner decision on v1 is pending). Do not mix the versions on one page (they define the same element).

v1, for reference ([example page](examples/verify-button-v1.html); hashes at `GET https://viadere.io/verify-button/v1/integrity.json`):

```html
<link rel="stylesheet" href="https://viadere.io/verify-button/v1/viadere-verify.css"
      integrity="sha384-7B8nwhugpRQh8Dv3bHED/l1CVZzyssS+AABdibXE3TEPHKXRjPLLq4v2VxPDYhDP" crossorigin="anonymous">
<script src="https://viadere.io/verify-button/v1/viadere-verify.js" defer
        integrity="sha384-vT7Sg9sIvngk1wVF56Jez/Zj9uoaJRKxrxbv76xNd8qG7oQqjvm/blG5iyeezM+Y" crossorigin="anonymous"></script>
```

The native buttons (sections 3 and 4) **still show a QR code first for now**; the Viadere code in the iOS and Android SDK panels is not built
yet. The Viadere app reads both codes, so a session started from any of the buttons can be scanned with the app.

## 3. iOS (`ViadereBusinessSDK`, SwiftUI and UIKit)

The button runs in your app and never holds an API key: get the link from your server.

```swift
import ViadereBusinessSDK

let session = VerifyButtonSession(link: linkFromMyServer, expiresAt: expiryFromMyServer)!   // nil unless it is a session link
VerifyWithViadereButton(session: session, variant: .filled, size: .medium,
                        onSendToPhone: { await myServer.sendVerificationToPhone() },        // optional
                        onExpired: { Task { await reloadSession() } })

// UIKit
let button = VerifyWithViadereUIButton(session: session)
button.onExpired = { reloadSession() }
```

On an iPhone or iPad the button opens the link with `universalLinksOnly`, so it goes straight to the Viadere app when installed and never to
Safari; otherwise (or on a Mac) it presents the QR-first panel as a sheet (a QR code for now, not yet the Viadere code: see "Versions"). To come back after verifying, set `return_url` to one of your
app's universal links on the session's origin; the Viadere app offers "Return to {site}" and opens it only if it is on that origin. On return,
ask your server for the result.

The decisions are pure Swift and tested on Linux: `VerifyHandoffPlanner`, `VerifyPanelState`, `VerifyButtonSession`, `VerifyButtonColors`.

## 4. Android (`Packages/android/viadere-verify`)

```kotlin
val session = VerifySession.parse(linkFromMyServer, expiresAtMillis = expiryFromMyServer) ?: return
VerifyWithViadereButton(
    session = session,
    variant = VerifyVariant.FILLED,
    size = VerifySize.MEDIUM,
    onSendToPhone = { myServer.sendVerificationToPhone() },   // optional
    onExpired = { reloadSession() },
)
```

On a phone the button opens the link with `FLAG_ACTIVITY_REQUIRE_NON_BROWSER`: only an app verified for the link domain (the Viadere app)
can take it, never a browser tab. When none can (no Viadere app on this phone, a ChromeOS window), it shows the QR-first panel (a QR code
for now, not yet the Viadere code); most Android
users will scan the QR with the phone that has Viadere. `VerifyReturn.isReturn(uri, expectedReturnUrl)` recognises your return App Link.
`minSdk 30`. Build status and toolchain: `Packages/android/viadere-verify/README.md`.

## Hand-off table (all platforms)

| Where the button runs | Viadere app reachable | What happens |
|---|---|---|
| Phone / tablet | yes | Hand-off to the app (universal link / App Link), no panel |
| Phone / tablet | no | iOS/Android SDK: QR-first panel. Web: the OS opens the `/v/` landing page, which offers the app and the typed code |
| Computer (web v2) | — | Panel with the Viadere code first, the QR code one control away |
| Computer (web v1, Mac, ChromeOS) | — | QR-first panel |
| Any | code expired | `onExpired` (SDKs); get a new session |

Panel options, in order: **Open Viadere on this device**, **Enter a code in the app**, **Send to my phone** (only when enabled), **Get the
Viadere app**; and **Back to the code** (web v2) or **Back to the QR code** (web v1, iOS, Android).

## Generic by design

The components take a *flow* (`flow` attribute on the web, `VerifyButtonFlow` on iOS, `VerifyFlow` on Android). Only `verify` exists. A
later "Sign in with Viadere" adds a flow with its own label and copy; the button, the hand-off and the panel stay the same.
