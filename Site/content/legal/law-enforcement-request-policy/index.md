---
title: Law-Enforcement Request Policy
order: 13
description: "How Viadere handles requests from government and law enforcement for user data, what it holds, and how it reports on them."
version: 0.2.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete policy with principles, what Viadere holds and cannot provide, accepted legal process by type, review standards, notice to users, emergency requests, preservation, international requests, business data, cost and transparency reporting."
---
::: draft-notice
**Draft for counsel review.** This policy is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This policy describes how [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") responds to requests from government agencies, law enforcement and courts ("**authorities**") for information about people who use Viadere and about businesses that use it. Viadere carries sign-in approvals, authorizations and private messages, and takes seriously the trust that people place in it. This policy is for authorities. A person who wants to know what Viadere holds about them should read the [Privacy Notice](/legal/privacy-notice/).

## 1. Principles

1. **Legal process is required.** Viadere discloses personal data to authorities only when it receives valid legal process, or in a genuine emergency as described in section 7, or where the law otherwise requires.
2. **Requests are reviewed.** Counsel reviews each request for validity, jurisdiction, scope and proportionality.
3. **Disclosure is narrow.** Viadere discloses the minimum that the process requires, and pushes back on requests that are overbroad, vague or unlawful, and where appropriate challenges them.
4. **People are told.** Unless prohibited by law or a court order, or in an exceptional case described in section 6, Viadere tells the affected person or business before it discloses, so that they can object.
5. **Records are kept and reported.** Viadere keeps a record of requests and publishes aggregate transparency information as section 12 states.
6. **Minimization by design.** Viadere is designed to hold as little as it can, as section 2 explains.

## 2. What Viadere holds

### 2.1 What Viadere does not have

- Viadere does not have a person's approval signing keys or passkey private keys. They are created and kept on the person's device.
- Viadere cannot read content that is protected end to end, such as approval requests sent in end-to-end mode, identity results sealed to a business key, a person's data export, or the planned credential vault. It holds only ciphertext.
- Viadere does not store raw identity documents, selfies, face templates or birthdates. If the identity-verification service is offered, such evidence goes to the verification provider and is deleted after the result is read.
- Viadere does not store plaintext phone numbers or plaintext message bodies at rest. They are encrypted in the database, and Viadere can decrypt them in its systems.
- Consumer accounts have no email address, name beyond a display name that the person chose, or password.
- Viadere does not collect device location, contacts, advertising identifiers or browsing history.

### 2.2 What Viadere may hold

Depending on the person and the service, and subject to the retention periods in the Privacy Notice:

| Data | Notes |
|---|---|
| Account record | Display name the person chose, account status, passkey public key |
| Phone number | If the person linked one: ciphertext, masked form, last four digits and a keyed hash |
| Device records | Device name, platform, public keys, enrollment and push-token records |
| Connections and consent | Which businesses a person connected to and which purposes they allowed, with times |
| Interaction and decision records | Request text, the person's decision or reply, signed decisions, the channel and times, for the retention period |
| Message content | Text exchanged with a business, for the retention period, until deleted |
| Delivery records | Provider message identifiers, status and times (30 days for finished sends) |
| Security and audit events | Actor, action, outcome and internal identifiers, in a tamper-evident log, for a long period |
| Network data | IP address ranges used for rate limiting and server logs, kept for short periods |
| Business records | Business name, handle, code, verified legal-entity details, dashboard users and their work emails, API-key metadata, usage and billing records |

Viadere may be able to link records for one person across businesses, because it holds the data that maps a person to the pairwise reference each business sees. A business sees only its own pairwise reference and cannot link a person across businesses.

### 2.3 Providers

Some data is held by Viadere's service providers and carriers, such as text-message content and delivery records at the messaging provider and carriers, and push tokens at Apple. Authorities should direct requests for that data to those parties where appropriate. Viadere will tell an authority which provider it uses where that is not confidential. The [subprocessor list](/legal/subprocessors/) is public.

## 3. How to submit a request

### 3.1 Where to send

Send requests, in English, from an official government address, to **[LAW-ENFORCEMENT-CONTACT-PLACEHOLDER]** or to Viadere's registered agent at [COUNSEL: postal address and registered agent]. Please use the subject line "Legal process" and include a reply address. Viadere does not accept legal process through the app, the support mailbox, social media or text messages. [COUNSEL: whether to use an online portal for authorities.]

### 3.2 What a request must include

- The issuing agency, the name, title and official contact details of the requester, and a case or reference number.
- A copy of the signed legal process, with its legal basis, the court or authority and the date.
- A specific description of the account or business and of the information sought, with enough detail for Viadere to find it: for a person, a phone number that Viadere can search for, a display name, a recovery identifier or a business handle; for a business, its handle or business code. Viadere searches for a phone number by a keyed hash, so an exact number is needed. Viadere cannot search by a person's real name or other attributes it does not hold.
- The date range, which should be as narrow as possible.
- The format in which the requester wants the response.
- Whether non-disclosure is requested, with its legal basis.

### 3.3 Verification of the requester

Viadere verifies that a request comes from an authority, for example by calling back through an official number or by checking the issuing court. A request that cannot be authenticated will not be processed.

## 4. Legal process Viadere accepts

The following describes Viadere's approach to United States process. [COUNSEL: expand for other launch regions and add a policy for each.]

| Information sought | Process required |
|---|---|
| Basic subscriber information (account existence, display name, linked-phone status, account dates, business registration details) | Subpoena or equivalent |
| Records other than content (connection and consent history, delivery records, audit events, device and network records) | A court order under 18 U.S.C. 2703(d) or a warrant, or the equivalent |
| Content that Viadere holds (message text, interaction content) | A search warrant issued on probable cause by a court of competent jurisdiction, and, where the law gives it, the protections of the Stored Communications Act |
| Real-time interception or prospective collection of metadata | A wiretap order or a pen register or trap-and-trace order, as the law requires |
| Anything protected end to end | Not available: Viadere holds only ciphertext and does not have the keys |

Viadere may require more than the minimum where the law or a court has set a higher standard. Where a statute or a court has set an evidentiary standard, Viadere follows the stricter standard. Viadere does not accept an informal request, a letter without legal process or an administrative request for content.

## 5. Review and response

### 5.1 Review

Viadere will review each request to decide whether it is valid, was served on the correct entity, is specific enough, is within the authority's jurisdiction, is proportionate and complies with law. Viadere may object to, narrow or decline requests that it considers unlawful, overbroad, vague, unduly burdensome, or that seek information that Viadere does not hold, and will explain why.

### 5.2 Response time

Viadere aims to respond within [10] business days to a valid request, longer for complex requests. A response may be to disclose, partly disclose, object or ask for clarification.

### 5.3 Format

Viadere will provide records in a readable electronic format, with a statement of the date and method of collection, delivered by a secure method. [COUNSEL: business records certification.]

### 5.4 Conflicts of law

If a request conflicts with the law of another country, or with a binding contract, Viadere will raise the conflict with the authority and, if needed, ask a court to resolve it.

### 5.5 Challenges

Viadere may challenge a request in court, and will inform the affected person or business where it does.

## 6. Notice to affected people

Viadere will give an affected person or business notice of a request for their information before it discloses, with a copy of the request, and a reasonable period of [14] days, where practicable, so that they can seek legal protection, unless: (a) a court order or the law prohibits notice, in which case Viadere will ask that the non-disclosure order be specific and time-limited and will challenge an indefinite one; (b) Viadere in good faith believes that notice would endanger someone or an investigation into child exploitation, or that there is an imminent threat to life; or (c) the account was used to commit the offense and notice would be futile, as to which Viadere will provide notice once the reason ceases. When a non-disclosure period ends, Viadere will tell the person. [COUNSEL: confirm.] Because consumer accounts have no email address, Viadere will give notice by an in-app notice and a push notification.

## 7. Emergency requests

Viadere may disclose information, without legal process, when it believes in good faith that there is an emergency involving danger of death or serious physical injury to a person that requires disclosure without delay, in line with 18 U.S.C. 2702(b)(8) and (c)(4). A request must come from an authority through **[EMERGENCY-CONTACT-PLACEHOLDER]**, describe the emergency and the information needed, and state why delay would be dangerous. Viadere reviews the request immediately, discloses only what is needed to address the emergency, and asks the authority to follow up with legal process. Viadere records each emergency disclosure. Viadere will not release information for an emergency that is not credible.

## 8. Preservation requests

On receipt of a valid request from an authority, Viadere will preserve the records that it holds relating to a specified account for [90] days (renewable once for another [90] days) while the authority obtains legal process. A preservation request is not a disclosure and does not oblige Viadere to create records that it does not hold. Viadere will give notice to the person as section 6 states unless prohibited. Note that Viadere's ordinary retention jobs may delete some data earlier, and a preservation takes effect as a hold on deletion from the date Viadere implements it.

## 9. Requests from outside the United States

Viadere will respond to a request from a foreign authority if it is made through a mutual legal assistance treaty, a letter rogatory or another process that a United States court would honor, or under an international agreement such as an executive agreement under the CLOUD Act, and is valid under the law of the United States. Viadere may ask that the request be made through the appropriate channel. Where the GDPR or UK GDPR applies to data, Viadere will consider the transfer rules and the protections of the data subject before disclosure. [COUNSEL: add a policy for EU, UK and Canadian requests.]

## 10. Requests about businesses

Business records, such as the business's name, handle, code, verified legal-entity information and dashboard users, are treated as described in this policy, with the business given notice as in section 6. Viadere does not hold the business's own customer data apart from what flows through the service, and refers an authority to the business for the data it holds. Viadere will not disclose a business's API keys, webhook secrets or other secrets, which it does not hold in readable form.

## 11. Cost and abuse

Viadere may seek reimbursement for the reasonable cost of responding to a request, where the law allows. Viadere does not provide the authority with access to its systems, or with a way to search by a person's name or other attributes it does not hold, and does not create a back door or weaken encryption or its security controls in response to a request. Viadere will not build a capability that it would not otherwise have to respond to a request, unless a court has validly ordered it, and then only after challenging it where reasonable.

## 12. Transparency

Viadere will publish a transparency report [COUNSEL: set the cadence, for example every six months] showing, in aggregate, the number and type of requests received, the number where data was disclosed, partly disclosed or refused, the number of emergency requests, the number of accounts affected, and the country or type of authority. Viadere will report in ranges where the law restricts exact numbers. Viadere will not publish the details of individual requests unless the law and the matter allow. It will explain any gap in reporting that a legal restriction causes.

## 13. Records

Viadere keeps a log of each request, the response and the review, for [at least five years] or as the law requires. The log is kept confidential and is accessible only to the legal team.

## 14. Changes

Viadere may update this policy. It will keep earlier versions at stable addresses. This policy is a statement of how Viadere intends to act and does not create a right for any person or a duty enforceable by a third party beyond the law.

## 15. Related

[Privacy Notice](/legal/privacy-notice/), [Incident Notification Policy](/legal/incident-notification-policy/), and [subprocessors](/legal/subprocessors/).
