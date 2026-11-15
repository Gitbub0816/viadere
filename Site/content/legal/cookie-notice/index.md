---
title: Cookie Notice
order: 15
description: "This website sets no cookies. This notice says what that means, what the business dashboard stores to keep you signed in, and what the app does."
version: 0.2.0
effective_date: ""
owner: "Privacy lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete notice covering the website, the business dashboard and operator console cookies, the app, how to control them, legal bases, signals and changes."
---
::: draft-notice
**Draft for counsel review.** This notice is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This Cookie Notice explains how [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") uses cookies and similar technologies, such as local storage, pixels, software development kits and device identifiers, on the viadere.com website, the business dashboard and the Viadere app. It supplements the [Privacy Notice](/legal/privacy-notice/).

## 1. At a glance

- **The website sets no cookies.** It uses no analytics, advertising or social-media trackers, loads no scripts, fonts, images or code from other companies and uses no browser storage.
- **The business dashboard uses one essential cookie** to keep a signed-in team member signed in. It is not used for analytics or advertising.
- **The Viadere app does not use cookies or advertising identifiers.** It does not track you across other companies' apps and websites.
- Because we use only what is strictly necessary to provide what you ask for, we do not show a cookie banner. If we ever add anything else, we will update this notice first and ask for your consent where the law requires it.

## 2. What the terms mean

A **cookie** is a small text file that a website puts in your browser. **Similar technologies** include local storage and session storage in a browser, tracking pixels, fingerprinting and mobile software development kits (SDKs). A technology is **strictly necessary** when it is essential to deliver a service you have requested, for example to keep you signed in or to keep a connection secure.

## 3. The viadere.com website

The public website at viadere.com and its developer portal:

| Technology | Used? | Notes |
|---|---|---|
| Cookies (first-party or third-party) | No | None is set |
| Local storage, session storage or IndexedDB | No | None is used |
| Scripts | No | The pages run no scripts, and they carry a content security policy that blocks scripts and inline styles |
| Analytics or advertising trackers, pixels, fingerprinting | No | None |
| Fonts, images, video, maps or other content from other companies | No | Fonts and images are served from viadere.com |
| Embedded social-media or video widgets | No | None |
| Server logs | Yes | Our hosting provider, Cloudflare, receives your IP address and request headers to deliver the pages, as any web host does, and may keep short-lived logs for security and reliability |

Links to other sites are ordinary links. Nothing is loaded from the destination until you follow it. Their cookies are governed by their own notices.

## 4. The business dashboard and operator console

The business dashboard is where a business manages its integration, and is separate from the public website. When a team member signs in with a passkey, the dashboard sets a cookie.

| Name | Purpose | Type | Duration | Attributes |
|---|---|---|---|---|
| `__Host-vd_session` | Keeps a signed-in business user signed in and identifies the session | Strictly necessary, first party | A session that ends at sign-out, after [30 minutes of inactivity] or after [12 hours] at most | Secure, HttpOnly, SameSite=Strict, no Domain, Path=/ |
| `__Host-vd_operator` | The same, for Viadere staff who use the operator console | Strictly necessary, first party. Used by staff only | [15 minutes of inactivity] or [8 hours] at most | Secure, HttpOnly, SameSite=Strict, no Domain, Path=/ |

The cookie value is a random token that we store only as a hash. The cookie name's `__Host-` prefix means the browser will accept it only over a secure connection and only from our host, and it cannot be set by another site. Pages carry a per-session request-forgery token that is derived from the cookie and is not stored in the browser. The dashboard also uses a small script of its own, with no outside dependencies, to run the passkey sign-in in your browser. It does not use analytics or advertising, and uses no other cookies or browser storage. [PRIVACY: re-check this list at each dashboard release.]

If you block this cookie, you cannot sign in to the dashboard.

## 5. The Viadere app, App Clip and Apple Watch app

The apps do not use cookies. They store data on your device in ways the operating system provides, for example the Keychain and the Secure Enclave for keys, an app container for the data they need to work offline and, for the credential extension, an encrypted store shared between the app and the extension. These are needed to provide the app and are not used for tracking.

- The apps do not read your advertising identifier, do not use an app-tracking prompt and declare no tracking in Apple's privacy manifest.
- The apps include no third-party analytics or crash-reporting SDK. [PRODUCT: re-confirm before each release.]
- Push notifications use a device token that Apple provides. See the Privacy Notice.
- You can delete the data an app stores by deleting your account or deleting the app.

## 6. Legal basis and your choices

Where a law requires consent for storing or reading information on your device (such as the EU ePrivacy Directive and its national laws, and the UK Privacy and Electronic Communications Regulations), an exemption applies to information that is strictly necessary to provide a service you have asked for. The dashboard cookie is in that category, and we do not ask for consent for it. If we ever used a technology that needed consent, we would ask you first, with a clear choice to refuse that is as easy as the choice to accept, and would not use it until you agreed. [COUNSEL: confirm exemption analysis by region.]

You can control cookies in your browser settings: block or delete them, or have your browser warn you. Doing so for the dashboard cookie will stop you from signing in. To manage cookies, see your browser's help pages.

## 7. Browser signals

The website has nothing for a "Do Not Track" or Global Privacy Control (GPC) signal to switch off, because it sets no tracking technology. We do not sell or share personal information for cross-context behavioral advertising, and we treat a GPC signal as a valid opt-out request for any account associated with the browser, which is relevant only to the dashboard.

## 8. Changes

If we add a cookie or similar technology, we will first update this notice, publish a new version at its own address and, where the law requires, ask for your consent before using the technology. The change history is on this page.

## 9. Contact

For questions about this notice, write to [PRIVACY-CONTACT-PLACEHOLDER].
