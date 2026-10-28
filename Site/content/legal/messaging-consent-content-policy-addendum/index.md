---
title: Messaging Consent and Content Policy Addendum
order: 7
description: "Consent, opt-out, content and sender-responsibility rules for messages sent through Viadere on the app, SMS and RCS channels."
version: 0.2.0
effective_date: ""
owner: "Trust and Safety lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete addendum covering scope, sender roles, consent by purpose, keywords and suppression, content and identity rules, channel limits, registration and carrier rules, quiet hours, complaint thresholds, records, enforcement and a consumer-facing summary."
---
::: draft-notice
**Draft for counsel review.** This addendum is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This Messaging Consent and Content Policy Addendum (the "**Messaging Addendum**") is part of the [Business Services Agreement](/legal/business-services-agreement/) between [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") and the business that accepted it ("**Customer**"). Terms defined in the Agreement have the same meaning here. It applies to every message, request and notification that Customer sends to a Consumer through the Services on any channel.

Messaging is a beta feature. RCS is not yet available. Where this addendum mentions a channel that is not yet available, it describes the rules that will apply when it is.

## 1. Scope and channels

### 1.1 Channels covered

| Channel | What it is | Status |
|---|---|---|
| Viadere app | Actionable push notifications, the in-app inbox and conversations, Live Activities, Apple Watch notifications and Wallet pass updates | Beta |
| SMS and MMS | Messages from the shared Viadere number, in a single thread that can switch between Businesses | Beta |
| RCS | Rich messages and suggested replies from an RCS agent | Planned |
| Email | Not used for Consumers, who have no email address. Email is used only for Dashboard users | Not applicable |

### 1.2 What is not covered

This addendum does not cover Customer's own communications to its customers outside Viadere, which are Customer's responsibility under Applicable Law.

### 1.3 Relationship to other documents

This addendum is subject to the Agreement and supplements the [Acceptable Use Policy](/legal/acceptable-use-policy/). If they conflict, the stricter rule for Consumer protection applies.

## 2. Roles and responsibility for each message

### 2.1 Sender and initiator

For each message type, the roles are as follows. [COUNSEL: confirm each allocation with the messaging providers' terms and applicable law.]

| Message type | Who decides to send it | Who is the "sender" or "initiator" for communications laws | Who must hold consent |
|---|---|---|---|
| Security and sign-in approval requests | Customer, at the time of a sign-in or action | Customer | Customer, by the Consumer's connection and purpose consent |
| Transactional and account-service messages | Customer | Customer | Customer, for the purpose the Consumer allowed |
| Customer-support replies | Customer | Customer | The Consumer started or joined the conversation |
| Marketing and promotional messages | Customer | Customer | Customer: prior express written consent where the law requires it |
| Rewards and offers | Customer | Customer | Customer: as marketing where the law treats them so |
| Gateway messages (menus, link, help and opt-out confirmations) | Viadere | Viadere | Viadere: the Consumer started the conversation or opted in |

### 2.2 Viadere's role

Viadere operates the shared sender number and the delivery network, records the Consumer's consent choices and enforces them in the Services. Viadere does not decide whether Customer's program is lawful. Customer is responsible for the content of its messages and for its own compliance. A Consumer's consent recorded in Viadere is a record of the Consumer's choice. It does not replace the consent that Applicable Law requires Customer to hold for its program, and Customer must keep its own records.

### 2.3 Contractual allocation

As between Viadere and Customer, Customer is responsible for claims, fines and penalties arising from its messages, as the Agreement provides. Viadere is responsible for the gateway messages it sends and for operating the registered campaigns.

## 3. Consent

### 3.1 Consent is by purpose

Viadere records consent for each Business and each purpose: security, account service, transactional, support, marketing and rewards. A message must use the purpose that truly describes it. Customer may send a message only for a purpose the Consumer has allowed for it. Consent for one purpose is not consent for another. Revoking marketing does not turn off security or account-service messages that the Consumer still needs.

### 3.2 How a Consumer connects

A Consumer connects to Customer by its handle, permanent business code, QR code, link or "Connect with Viadere" button, or by selecting it in a text conversation. Customer cannot message a Consumer through Viadere until the Consumer has connected. Connecting does not by itself authorize marketing: marketing needs its own, separate consent covering the channel.

### 3.2A Consent standard

Where Customer relies on the Consumer's consent for marketing text messages or RCS messages, it must obtain it before the first message, in a way that: names Customer; describes the types of messages and their frequency; states that consent is not a condition of purchase; includes how to opt out; is clear, conspicuous, and not pre-checked; and keeps a record of the date, time, text and source. Customer may not buy, rent or use lists of numbers to message through Viadere, and may not use consent obtained for another sender or purpose. [COUNSEL: align with the FCC's one-to-one consent requirement as in force and with carrier rules.]

### 3.3 Provenance and records

Viadere records, per consent: the Business, the Consumer's pairwise reference, the purpose, the channels covered, the version of the wording shown, the source (for example the app or a text) and the time. The current consent is kept for as long as the Consumer's account exists, and superseded versions are kept for the period in the retention schedule. These are evidence of what the Consumer chose. Customer must keep its own consent records for [five] years.

### 3.4 No bypass

Customer will not: send a promotional message as a transactional or security message; use a security or approval request to carry marketing; use a Consumer's phone number obtained elsewhere to message them on a channel for which they have not consented; combine a marketing message with an authentication request; or ask a Consumer to give consent in a way that is misleading or buried. Promotional messages cannot be presented as authentication or transactional messages to avoid consent rules.

### 3.5 Consumer-initiated conversations

When a Consumer texts the Viadere number first, Viadere may reply with menus, help and a link to connect. The Consumer's contact initiates the conversation, but it does not give any Business consent to send marketing.

## 4. Opt-out, STOP and HELP

### 4.1 Keywords

The Viadere text channels handle these keywords, case-insensitively, after trimming spaces and a trailing period or exclamation mark:

| Keywords | Effect |
|---|---|
| STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT, OPTOUT, REVOKE | Opt out of text messages, in every state. It cannot be escaped, and a leading backslash does not prevent it |
| HELP, INFO | Help text, in every state, including after opt-out. It cannot be escaped and does not re-subscribe |
| START, UNSTOP, YES | Opt back in, only after an opt-out. In any other state they are ordinary content |
| MENU, BACK | Controls for the gateway. A Consumer who needs to send these words to a connected Business can put a backslash before them |

### 4.2 What happens on STOP

When a Consumer replies STOP, Viadere stops sending text messages from the shared number to that phone number, sends one confirmation (as the carriers allow), records the opt-out as a suppression with a keyed hash of the number and the time, and keeps the suppression even if the Consumer deletes their account, so that the opt-out is honored. The opt-out applies to the Text Service as a whole and cannot be used to opt out of one Business only. A Consumer can still receive app notifications, and can manage individual Business consents in the app. Where a carrier reports that a recipient has opted out, Viadere treats it as an opt-out.

### 4.3 Customer's duties

Customer will not message a Consumer by another text channel to avoid a STOP; will honor the opt-out signal even if it receives it from another source; will not ask a Consumer to reconsider, other than as the law permits in a single confirmation; and will not remove or alter the opt-out text that Viadere adds. Customer will process the opt-out and consent events that Viadere delivers by webhook promptly and no later than [24 hours], and in the interval will not send messages to that Consumer.

### 4.4 Timing

Viadere honors an opt-out immediately and in any event within the time the law allows, [no more than ten business days and normally instantly].

### 4.5 Help

Viadere answers HELP with a description of the service, a contact for support and the opt-out instructions. Customer's support contact must be available to Consumers who ask for it.

### 4.6 Required disclosures in the program description

Messages from Viadere's registered campaigns contain, or link to, the disclosures that carriers require: the program name, a description, message frequency, "message and data rates may apply", how to opt out and get help, and a link to the [Consumer Terms](/legal/consumer-terms/) and [Privacy Notice](/legal/privacy-notice/).

## 5. Content rules

### 5.1 Identification and attribution

Every message and request must clearly identify Customer. Viadere shows business text after the Business's verified name, in a single line. A Business message may not impersonate Viadere, another Business, a government, a bank or any other person, or misrepresent its identity, purpose or the effect of an action.

### 5.2 Display text validation

The Services validate business display text and reject any that: contains control, invisible, bidirectional-override or other formatting characters, or characters that are unassigned or in private use; contains a line break outside a long free-text field; exceeds the length limits for its field; or starts with, or in a name field contains, the word "Viadere" or a look-alike of it. Customer must not try to evade these checks.

### 5.3 Prohibited content

Customer will not send content that: is illegal or promotes illegal activity; is fraudulent, deceptive or phishing; asks a Consumer for a password, a one-time code for another service, an approval by text or a payment card number; contains malware or a link to it; is harassing, threatening, hateful or abusive; is sexually explicit; promotes or sells [COUNSEL AND TRUST AND SAFETY: prohibited and restricted categories, for example illegal drugs, firearms, tobacco and vaping, high-risk financial products such as payday loans, debt collection, gambling, cannabis, adult content and "SHAFT" categories under carrier rules]; infringes intellectual property; or would violate carrier or provider policies.

### 5.4 Shortened links

Customer will not use public link shorteners, or links that hide the destination, in messages through the shared number. Links must go to a domain that Customer has verified with Viadere.

### 5.5 Sensitive information

Customer will not use text messages to ask for or send sensitive information, including government identifiers, financial account numbers, health information, authentication secrets or precise location. Where a task needs it, Customer must use a secure link or a request in the app.

### 5.6 Message limits

Customer must send only what the Consumer expects, at a reasonable frequency. Viadere applies per-Business quotas and rate limits and may reduce them under the Agreement.

### 5.7 Language and accuracy

Messages must be accurate, in a language the Consumer understands, and must not use misleading urgency or fake countdowns.

## 6. Channel limits, security and the shared thread

### 6.1 No sensitive approval by text

A text channel carries only unauthenticated replies. A security-sensitive request, including a sign-in approval, a transaction authorization or a change to account security, is never approved by SMS or RCS. Viadere replaces it with a secure link to the app. Viadere does not accept a text reply of "YES" or "NO" as a high-assurance approval, and Customer must not treat a text reply as one.

### 6.2 SMS fallback and encryption

When a request or notice falls back to SMS because a richer channel is unavailable, the fallback is limited to what is safe in text. SMS is not end-to-end encrypted: carriers, messaging providers and others on the route can read ordinary text messages. Viadere will never silently downgrade a sensitive authorization to a text. Customer must not include sensitive information in a message that may fall back to SMS.

### 6.3 Shared thread

All of a Consumer's text conversations with Viadere are in one thread, but histories are kept separate per Business. While a Consumer is connected to one Business, another Business cannot send a text into that thread: the Consumer instead receives a notice naming both Businesses, with no content. The Consumer must select the Business to see its message. Business replies are clearly attributed. A Consumer's number or a reply to a menu never routes a message to a Business that the Consumer has not confirmed.

### 6.4 Menus and numeric replies

Numbered menus offer up to four choices. A number is treated as a menu choice only while an unexpired menu is active and not within a short interval after the menu was shown. Otherwise, numbers, order numbers and any other text pass as ordinary message content to the connected Business.

### 6.5 Phone numbers are routing, not identity

A phone number or a sender number is a routing identifier and not proof of identity or account ownership. Customer must not rely on a text from a number as authentication.

### 6.6 Delivery

Delivery depends on carriers and providers. Viadere deduplicates inbound deliveries, orders outbound messages, retries and records failures, but does not guarantee delivery, timing or ordering on carriers.

## 7. Registration, carriers and providers

### 7.1 Viadere's registrations

Viadere registers its sender numbers and campaigns with its providers and carriers as required, including US application-to-person (A2P) 10DLC brand and campaign registration or toll-free verification, and any registrations needed in Canada. Customer's messages must fit within the campaign use cases that Viadere has registered.

### 7.2 Customer's registrations

Where a channel or Capability requires Customer itself to register, such as an RCS agent, a dedicated sender number or a short code, Customer will complete the registration accurately and promptly and will tell Viadere of changes.

### 7.3 Carrier and CTIA rules

Customer will follow the carriers' and CTIA's messaging principles and best practices, and Viadere's providers' policies that Viadere flows down. Carriers can block, filter or limit messages and can change rules without notice. Customer is responsible for fines, surcharges and charges that result from its content or conduct.

### 7.4 Regional rules

Different rules apply in other countries. Customer will not send messages to Consumers in a country that Viadere has not enabled for it. [COUNSEL: launch regions and the rules for each, including Canada's anti-spam law and the opt-in rules for numbers outside the United States.]

### 7.5 Quiet hours

Customer will not send marketing messages to a Consumer outside the hours the law allows, which in the United States is generally between 8 a.m. and 9 p.m. in the recipient's local time, and some states are stricter. Viadere may defer or hold marketing messages that fall outside permitted hours. [COUNSEL: state-specific rules and Viadere's enforcement of time zones.] Security and transactional messages are not deferred merely because of the time.

### 7.6 Number reassignment

Customer will take reasonable steps to avoid messaging a number that has been reassigned to another person since consent was given, including by using Viadere's connection records and any reassigned-numbers database the law requires. Viadere may block a number it knows to have been reassigned.

## 8. Complaints, quality and enforcement

### 8.1 Measures

Viadere monitors, for each Business, the rate of Consumer complaints, opt-outs, blocked-message reports, suspicious-request reports and denied requests. Viadere publishes the thresholds for action to Customers in the Dashboard. [TRUST AND SAFETY: set thresholds, for example a complaint rate above [0.1%] or an opt-out rate above [2%] over [7] days.]

### 8.2 Prompt-fatigue protection

To protect Consumers from repeated prompts, Viadere limits the number of approval requests a Business can send a Consumer in an hour, warns the Consumer after the third, refuses more than the hourly limit, pauses a Business's requests to a Consumer who has denied or reported several in a row, and limits the number pending at once. Customer must not try to circumvent these limits.

### 8.3 Actions Viadere may take

Where a threshold is exceeded or a rule is broken, Viadere may: warn Customer; throttle or reduce Customer's quotas; lower its priority ceiling; require a corrective plan; pause a Capability, a campaign or a channel; suspend Customer's access under section 8 of the Agreement; and notify affected Consumers, carriers or regulators. Customer may appeal under section 8.3 of the Agreement.

### 8.4 Cooperation

Customer will respond within [two] business days to a carrier, provider or Viadere request for proof of consent, copies of messages or an explanation of a campaign, and will cooperate with investigations.

### 8.5 Priority

Fees never buy priority over security requests and never bypass consent. Marketing and rewards never exceed normal priority.

## 9. Records and retention

### 9.1 What Viadere keeps

Viadere keeps consent provenance, opt-out suppressions, delivery records (provider message identifier, status, channel and time) and message content for the periods in its retention schedule: finished outbound send records for 30 days, message bodies for 730 days by default (Customer may shorten this for its own data), and opt-out suppression records for as long as needed to honor them. [COUNSEL: evidence period for consent and opt-out records under the TCPA and carrier rules; the current setting keeps suppression indefinitely.]

### 9.2 Access

Customer may see consent state and events for its own relationships in the Dashboard. A Consumer may see their consent history in the app. Viadere may provide records to a carrier, provider or regulator as the law and its agreements require.

### 9.3 Message content

Message content is encrypted at the field level in Viadere's database and is not placed in general telemetry. Providers and carriers keep content under their own terms.

## 10. Consumer summary

The following describes the Viadere text service to Consumers. It is shown with the first message.

- Viadere is a verified way to connect with businesses. Text the Viadere number to find a business, link your account and send messages.
- You choose each business. Businesses can only message you after you connect. Marketing needs your separate consent.
- Message frequency varies. Message and data rates may apply.
- Reply STOP to opt out, HELP for help. Reply START to resume after you opt out.
- SMS is not end-to-end encrypted. Do not send sensitive information by text. Approvals of sensitive actions happen in the app.
- Terms: [Consumer Terms](/legal/consumer-terms/). Privacy: [Privacy Notice](/legal/privacy-notice/). Support: [SUPPORT-CONTACT-PLACEHOLDER].

## 11. Changes

Viadere may update this addendum as the Agreement describes. Changes required by carriers, providers or law may take effect on shorter notice.
