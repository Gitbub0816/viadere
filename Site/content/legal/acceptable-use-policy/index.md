---
title: Acceptable Use Policy
order: 4
description: "What businesses may not do with Viadere, how restricted uses are handled, and how Viadere enforces these rules."
version: 0.2.0
effective_date: ""
owner: "Trust and Safety lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete policy with general rules, platform integrity, messaging and approval rules, content rules, restricted and prohibited categories, enforcement ladder, reporting and appeal."
---
::: draft-notice
**Draft for counsel review.** This policy is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This Acceptable Use Policy (the "**AUP**") applies to every business, organization or person that uses the Viadere Business API, Dashboard or other business services ("**you**", "**Customer**"), and to everyone who uses them on your behalf. It is part of the [Business Services Agreement](/legal/business-services-agreement/) with [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") and works with the [Messaging Consent and Content Policy Addendum](/legal/messaging-consent-content-policy-addendum/). Viadere is a trust network: people connect to verified businesses, and the rules below protect them and protect the businesses that follow them.

## 1. Principles

1. **People choose who reaches them.** You may contact a person through Viadere only after they have connected to you and allowed the purpose.
2. **Be who you say you are.** Everything a person sees must truthfully identify you and what you are asking.
3. **Do not weaken protections.** Security controls, limits and consent checks exist for the people on the other end.
4. **Money does not buy priority or consent.** No plan or payment changes the priority of a message or bypasses a person's choices.
5. **The business is responsible.** You are responsible for what you send, the consent you hold and the laws that apply to your communications.

## 2. Prohibited conduct

You will not, and will not allow others to:

### 2.1 Identity and impersonation

- Impersonate another business, a person, Viadere, a government agency, a bank or any other entity, or use a verified identity, handle, code or domain that is not yours.
- Show text on an approval screen, a notification or a message that is misleading, that starts with or contains "Viadere" in a name, or that looks like a Viadere system message.
- Use hidden, invisible, bidirectional or other control characters, look-alike characters or any technique to disguise text.
- Register a handle, code or business name that is deceptive, infringes a mark, impersonates another business, or is confusingly similar to another business's.
- Misrepresent your verification status or use a verified badge to imply endorsement, licensing or that Viadere guarantees you.

### 2.2 Consent and unwanted messages

- Send messages to people who have not connected to you and allowed the purpose.
- Present a promotional message as an authentication, security or transactional message to avoid consent rules.
- Ignore STOP, opt-out or revoked consent, or contact a person on another channel to avoid an opt-out.
- Buy, rent, scrape or share lists of phone numbers or contacts for use through Viadere.
- Send messages that are not what the person expects, or at a frequency they would not reasonably expect.

### 2.3 Security approvals and authentication

- Ask for or accept an approval by text that must be approved in the app.
- Send approval requests that are unclear, that hide the amount, merchant, action or consequence, or that have been created to trick or pressure a person (including by repeated "prompt bombing").
- Use the approval service for something you did not originate, or relay another party's requests to a person.
- Fail to validate the signed approval result yourself before acting.
- Use Viadere to collect passwords, one-time codes for other services, recovery codes, payment details or identity documents under false pretenses.

### 2.4 Platform integrity

- Probe, scan or test other businesses' data, accounts or tenants, or attempt to access data you are not authorized to see.
- Attempt to correlate people across businesses, re-identify a pairwise reference, or build a cross-business profile of a person.
- Attempt to bypass, disable or manipulate rate limits, quotas, priority caps, cool-downs, freezes, consent checks or other protections, including by creating multiple accounts or workspaces to evade a limit or a suspension.
- Share, sell or expose API keys, webhook secrets, certificates or Dashboard sessions, or put keys in client-side code or public repositories.
- Use the sandbox with production personal data, or production keys in test.
- Interfere with, overload or disrupt the services or other customers' use of them.
- Reverse engineer, scrape or enumerate the directory, handles or codes.
- Use the Business API to build a competing service or for purposes it was not designed for.

### 2.5 Unlawful and harmful use

- Use Viadere in violation of law, including laws on communications, privacy, consumer protection, advertising, sanctions and export.
- Send, host or link to malware, phishing, spam or content that is fraudulent, deceptive, defamatory, harassing, threatening, hateful, sexually explicit or that exploits or endangers children.
- Facilitate fraud, money laundering, extortion, stalking, human trafficking, or violence.
- Infringe intellectual property or privacy rights.
- Use Viadere for emergency or safety-critical communications, or for activities where a failure could result in death or serious injury.

### 2.6 Data misuse

- Sell, share for cross-context advertising, or use data received through Viadere to discriminate against a person for exercising a right.
- Use the information you receive through Viadere for a purpose that is incompatible with the purpose the person allowed.
- Keep a verification result or sensitive attribute longer than your agreement allows, or use it for another purpose.

## 3. Restricted and prohibited uses

### 3.1 Prohibited

Viadere does not allow the following. [COUNSEL AND TRUST AND SAFETY: confirm this list and align it with provider and carrier policies.]

- Content or services that promote or sell illegal drugs and unlawful products or services.
- Adult sexual content and services.
- Weapons, ammunition and explosives, except as Viadere has approved in writing for a licensed seller and a permitted channel.
- Counterfeit goods, stolen data, hacking tools, and the sale of verification or identity documents.
- Services designed to evade or defeat Viadere's controls, carrier rules or consent.
- Gambling, sweepstakes and lotteries through the text channels, unless approved in writing for a licensed operator.
- Debt collection, payday and high-cost short-term loans, and similar through the text channels, unless approved in writing.
- Pyramid and multi-level marketing schemes, get-rich-quick and work-from-home schemes.
- Anything else that a carrier or provider has prohibited for the channel.

### 3.2 Restricted: approval needed

The following uses are restricted. They may be available only after a documented review, in a higher risk tier, with an addendum, and with conditions. A category label alone is never the access decision.

| Use | Condition |
|---|---|
| Financial institutions and payments (sign-in, transaction authorization) | Tier A review, an enrolled approval key, incident-response readiness and the MFA and Approval Services Addendum. Viadere verification does not satisfy your KYC, anti-money-laundering or sanctions duties |
| Healthcare, and protected health information | Written agreement and, where required, a business-associate agreement before any protected health information is handled. Not available by default |
| Age-restricted goods and services (alcohol, tobacco and vaping, cannabis where legal, gambling where legal) | Tier V review for age checks, a documented lawful purpose and jurisdiction rules. Verify availability varies by place |
| Government and public-sector services | Enhanced review |
| Identity attributes (name, address, verified identity) | Tier V purpose assessment, heightened review, a stated purpose and customer consent at each request. The default is threshold-only disclosure |
| Services to or for children | Not available by default. [COUNSEL: COPPA and state child-privacy laws] |
| Cryptocurrency and digital assets | Enhanced review [COUNSEL: confirm] |
| Political, advocacy and fundraising messages | Consent and registration requirements apply; carriers require registration |

### 3.3 Why a category is not the only test

Viadere decides on documented lawful purpose and risk, not on a label. An approved use in one category does not approve another, and verified status does not imply approval for every Capability.

## 4. Responsibilities for your users and integrations

You are responsible for the acts and omissions of your personnel, contractors, resellers and any third party that uses your credentials or your integration. If you provide services to other businesses, you may not use the Services on their behalf unless you have an agreement with Viadere that allows it. Your customers' use of Viadere through you must also follow this AUP, and you must be able to identify them to Viadere on request.

## 5. Monitoring and enforcement

### 5.1 How Viadere monitors

Viadere monitors the services for abuse using signals such as complaint, opt-out, denial and blocked-message rates, suspicious-request reports, unusual volumes or origins, failed verification and reports from people, carriers and providers. Viadere does not read message content to enforce this AUP except as needed to investigate a report, a security matter, a legal obligation or a carrier or provider request, and tries to limit what it looks at.

### 5.2 Responses

Viadere decides how to respond according to the seriousness, risk, history and intent. It may, without limiting other rights:

1. Warn you and ask for a fix.
2. Throttle your rate, reduce your quotas or lower your priority ceiling.
3. Require a corrective plan, extra verification, or an additional review.
4. Remove or reject content, a handle, a code or a template.
5. Pause a Capability, a campaign, a channel or a key, or revoke keys.
6. Suspend your access to part or all of the services.
7. Terminate your account.
8. Notify affected people, carriers, providers or authorities, and cooperate with investigations.
9. Take legal action.

Viadere may act at once, without notice, where there is a risk to people or the service. Otherwise it will, where practical, tell you why and give you a chance to respond. Suspensions and terminations are also governed by section 8 and section 18 of the Business Services Agreement.

### 5.3 Handles and codes

Viadere may withdraw a handle for violation of this policy. A business code is never reassigned to another business.

### 5.4 Appeal

You may appeal an enforcement action by writing to [TRUST-CONTACT-PLACEHOLDER] within [14] days, with the reasons and supporting evidence. A reviewer who was not involved in the decision will respond within [10] business days. An appeal does not suspend the action unless Viadere agrees.

### 5.5 Repeat violations

Repeat or serious violations may lead to permanent termination. Viadere may refuse a new application from a person whose account was terminated for a serious violation.

## 6. Reporting

- **Abuse, spam and impersonation.** Report from a Business's screen in the Viadere app, or write to [TRUST-CONTACT-PLACEHOLDER] or via the [Company contact page](/company/contact/). Include the Business name, handle and what happened. Do not send passwords or codes.
- **Security vulnerabilities.** Report under the [Vulnerability Disclosure Policy](/legal/vulnerability-disclosure-policy/).
- **Law enforcement.** See the [Law-Enforcement Request Policy](/legal/law-enforcement-request-policy/).
- **Copyright.** Send a notice to our designated agent: [COUNSEL: DMCA agent contact].

We will never ask you for a password, a code or an approval by text or email.

## 7. Changes

Viadere may update this AUP. Material changes are published as a new version at a stable address and announced as the Business Services Agreement describes. Continuing to use the services after the effective date is acceptance.

## 8. Examples

These examples illustrate the rules. They are not a complete list.

| Situation | Allowed? | Why |
|---|---|---|
| A bank asks a customer to approve a sign-in, showing the device, approximate location and time | Yes | A clear security request, with the customer's connection and consent |
| A retailer sends an order-shipped update to a customer who connected for transactional messages | Yes | Within the purpose the customer allowed |
| A retailer adds a 20 percent coupon to a sign-in approval request | No | Marketing combined with a security request, which hides a promotion in an authentication message |
| A business texts a coupon to a customer who allowed only transactional messages | No | Marketing needs separate consent for the channel |
| A business sets its display name to "Viadere Support" | No | Impersonates Viadere |
| A business sends 20 approval requests in an hour to one customer | No | Prompt bombing; Viadere refuses more than the hourly limit |
| A support agent replies to a customer's question through the Viadere thread | Yes | A reply in a conversation the customer started |
| A developer tests with a `vdk_test_` key and sandbox customers | Yes | The sandbox is for testing |
| A developer posts a `vdk_live_` key in a public repository | No | Exposes a credential; rotate it at once and tell Viadere |
| A researcher tests their own account under the Vulnerability Disclosure Policy | Yes | Good-faith research within the rules |

## 9. Good practice

You are encouraged to: tell people at connection what you will send and how often; keep your handle, contacts and domain verification current; keep suppression and consent records; monitor your own complaint and opt-out rates in the Dashboard; use the least scope for each key; rotate keys on a schedule; and review your integration against the Documentation before you go live.

## 10. Contact

Questions about this policy: [TRUST-CONTACT-PLACEHOLDER].
