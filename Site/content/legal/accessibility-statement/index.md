---
title: Accessibility Statement
order: 14
description: "Our accessibility goal, what we have done and checked, known limits, assistive-technology support and how to tell us about a problem."
version: 0.2.0
effective_date: ""
owner: "Design lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete statement with goal, scope, measures taken, what has and has not been verified, known limitations, compatibility, feedback process with response times, alternative formats and enforcement contacts."
---
::: draft-notice
**Draft for counsel review.** This statement is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

[COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") wants everyone to be able to use its website, developer portal and apps. This statement describes our goal, what we have done, what we have not yet verified and how to tell us about a barrier. It was prepared on [DATE].

## 1. Our goal

We aim for the viadere.com website and the Viadere apps (iPhone, Apple Watch and App Clip) to conform to the Web Content Accessibility Guidelines (WCAG) 2.2 at level AA, and for the apps to follow Apple's accessibility guidance. We have not claimed that we conform. [COUNSEL: whether and how to state a conformance claim, and whether to use the EN 301 549 and Section 508 formats.]

## 2. Scope

This statement covers: the public website at viadere.com, including the developer portal and legal pages; the Viadere app, App Clip and watchOS app; and the business dashboard. It does not cover third-party sites that we link to, the third-party services that we use (such as Apple's system screens, Wallet or the operating system's passkey prompts) or content that businesses send through Viadere.

## 3. What we have done on the website

- A **skip link** to the main content, a consistent heading structure and landmark regions, and a table of contents on long pages.
- **Keyboard access:** all navigation and interactive controls can be reached and operated with a keyboard, with a clearly visible focus style.
- **Navigation that works without scripts.** The site runs no scripts.
- **Colour and contrast:** light and dark colour schemes with text and interface colours designed for AA contrast, calculated from the design tokens. Meaning is not conveyed by colour alone.
- **Reduced motion:** the site respects the reduced-motion setting.
- **Responsive layout:** the pages work from a 360 pixel width without horizontal page scrolling and without loss of content. Wide tables scroll inside a labelled region.
- **Text and zoom:** the layout uses relative units so that it adapts to browser zoom and text size. [DESIGN: verify at 200 percent zoom and record.]
- **Plain language:** we write for a general audience and avoid jargon where we can.
- **Links and images:** link text describes its destination, and images that carry meaning have text alternatives. Decorative images are hidden from assistive technology.
- **No time limits or flashing content,** and no content that changes without your input.
- **No tracking and no cookie banner,** so there is no consent dialog to navigate.
- **Forms and errors:** where we have forms, they have labels, and errors are described in text.

## 4. Our approach in the app

The app is built with Apple's standard interface frameworks, and we design it to use the system's accessibility features. Some screens carry VoiceOver labels today. We have not yet audited every screen, so the list below states what we are working toward and not a claim of conformance. [DESIGN: confirm each item by screen and record the result and date.]

- Text that follows Dynamic Type, and respect for the system settings for reduced motion, increased contrast, bold text and dark mode.
- VoiceOver labels, traits and a logical reading order for every control.
- Notification actions that work with VoiceOver, Switch Control and Voice Control through the operating system's standard controls.
- Touch targets of a usable size, and no reliance on gestures that have no alternative.
- Face ID or the device passcode, through the operating system, so that a person who cannot use biometrics can use the passcode.
- Approval prompts that state the business, the action and the expiry in text, so that assistive technology can read them.

## 5. What we have not yet verified

- The site has **not had an independent accessibility audit** and has not been tested with a full range of assistive technology. Our checks so far are our own: we have verified, by calculation, text contrast for the colour tokens, checked that every page works at 360 pixels without horizontal scrolling, and confirmed the skip link, focus styles and reduced-motion behaviour. [DESIGN: record manual screen reader and keyboard testing here, with the date, the tool and version and the result.]
- The apps and the dashboard are assessed separately and have not had an independent audit either. [DESIGN: record results.]
- We have not tested every combination of browser, operating system and assistive technology.

## 6. Known limitations

| Area | Limitation | What we are doing |
|---|---|---|
| Tables | Wide tables on the developer reference scroll horizontally inside their own region on narrow screens | Keep them labelled and keyboard-focusable. [DESIGN: review] |
| Code samples | Code blocks may be hard to read with some screen readers | Provide the sample in text and describe it |
| Passkey sign-in on the dashboard | Depends on the browser's and operating system's passkey interface, which we do not control | Document alternatives where the platform provides them |
| Identity verification (planned) | Document and selfie capture can be hard for some people. A face-based check may not suit everyone | We aim to provide an alternative path (for example an eligible Apple Wallet ID) and the businesses that use Verify must offer an alternative for people who cannot use it |
| Text messages | Text menus use numbers, which suit many but not all users | The app offers a full alternative |
| Third-party content | Content a business sends may not be accessible | We ask businesses to follow accessibility laws in the terms |

## 7. Compatibility

The website is designed to work with current versions of Safari, Chrome, Firefox and Edge, with screen readers such as VoiceOver, TalkBack, NVDA and JAWS, and with browser zoom and text-only magnification. The app is designed for current and recent iOS and watchOS versions and their built-in assistive features. [DESIGN: list the versions tested.]

## 8. Tell us about a problem

If you find a barrier or need information in a different format, tell us:

- By writing to [ACCESSIBILITY-CONTACT-PLACEHOLDER], or using the contact details on the [Company page](/company/contact/).
- Please say what page or screen it is, what you were trying to do, the browser or device and assistive technology you use, and how we can reach you. You do not have to give your name.

We aim to acknowledge your message within [2] business days, tell you what we can do within [10] business days, and fix problems according to their severity, with a goal of [30] days for a barrier that stops you from using a feature. If we cannot fix it, we will offer another way to get the information or complete the task. Because consumer accounts have no email address, you can also contact us from the app.

## 9. Alternative formats

On request we will provide the content of any legal or help page in a plain-text, large-print, audio or other reasonable format. [COUNSEL AND DESIGN: confirm formats and timeline.]

## 10. Enforcement and complaints

If you are not satisfied with our response, you may contact the authority in your region: in the United States, the Department of Justice or the Federal Trade Commission as applicable, and a state agency; in the European Union, the national enforcement body for the European Accessibility Act or the Web Accessibility Directive [COUNSEL: if applicable]; in the United Kingdom, the Equality Advisory and Support Service; in Canada, the Accessibility Standards Canada or the relevant provincial body. [COUNSEL: confirm applicable regimes and contacts.]

## 11. Technical specifications

The accessibility of the website relies on HTML, CSS and WAI-ARIA only where needed. We do not rely on scripts for navigation. The apps rely on the accessibility features of iOS and watchOS.

## 12. Updates

We review this statement at least [once a year] and whenever we make a significant change to the site or apps. Earlier versions are kept at stable addresses.
