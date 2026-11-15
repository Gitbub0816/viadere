---
title: Business Services Agreement
order: 3
description: "The agreement between Viadere and a business that uses the Business API, the dashboard and Viadere's messaging, approval and verification services."
version: 0.3.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
health_prohibition: true
change_summary: "Third draft: healthcare and Health Information are prohibited platform-wide (new section 5.10, termination right in 18.3, no business-associate agreement); new terms for Business Workflows (\"Loops\", a working name pending trademark clearance) with mandatory Viadere review, Brand Kits, and Shopify-only commerce in which Viadere never accepts payments and is never the merchant of record; related definitions, licences, third-party service, accountability and indemnity text. Counsel choices remain bracketed."
disclosures: [business_verification, mfa]
---
::: draft-notice
**Draft for counsel review.** This agreement is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This Business Services Agreement (the "**Agreement**") is between [COUNSEL: LEGAL ENTITY NAME], a [STATE] [corporation] with its registered office at [ADDRESS] ("**Viadere**"), and the business or organization that accepts it, identified in the applicable Order Form or on the dashboard acceptance record ("**Customer**", "**you**"). It takes effect on the date you accept it in the dashboard or sign an Order Form, whichever is first (the "**Effective Date**"). If you accept on behalf of an organization, you confirm that you have authority to bind it.

## 1. Definitions

- "**Account**" or "**Organization**" means the Customer's workspace in the Dashboard.
- "**Affiliate**" means an entity that controls, is controlled by or is under common control with a party.
- "**Applicable Law**" means all laws, regulations, binding guidance and industry rules that apply to a party's performance or use of the Services, including privacy, data-protection, consumer-protection, telemarketing and anti-spam laws.
- "**Approval Services**" or "**Approve**" means Viadere's services for delivering authentication and transaction-authorization requests to Customers' end users and returning their signed decisions.
- "**Business API**" means the application programming interfaces, SDKs, webhooks and related documentation that Viadere makes available at the Developer Portal, including the sandbox.
- "**Brand Kit**" means the optional appearance settings (colours, logo and artwork, frames and similar styling chosen from options Viadere provides) that Customer configures for how its name appears in Viadere-owned screens, as described in section 3.8.
- "**Business Content**" means all content, data and materials Customer submits or transmits through the Services, including requests, messages, offers, attachments, templates, display text and metadata, and including Loop Content and Brand Kit assets.
- "**Business Workflow**" or "**Loop**" means an optional interactive workflow that Customer designs from components and registered actions that Viadere provides and that, once Viadere has approved and published it, a Consumer who has opted in can open, as described in section 3.7. [COUNSEL: "Loops" is a working name pending trademark and marketplace clearance; the defined term "Business Workflow" may replace it throughout.]
- "**Capability**" means a typed function of the Services, such as message.send, auth.challenge, transaction.approve, age.minimum or identity.verified, each with its own policy and entitlement.
- "**Consumer**" means an individual who uses the Viadere app or the Viadere text number.
- "**Consumer Data**" means personal information about a Consumer that Viadere processes on Customer's behalf or that Customer receives through the Services.
- "**Dashboard**" means Viadere's web console for Customer's workspace.
- "**Documentation**" means the developer documentation, specifications (including the OpenAPI definition), policies and guides at the Developer Portal, as updated.
- "**Fees**" means the charges in the Order Form and Exhibit C.
- "**Health Information**" means any information that relates to the past, present or future physical or mental health or condition of an individual, to the provision of health care to an individual, or to the payment for health care, and any information that is protected health information under the U.S. Health Insurance Portability and Accountability Act of 1996 and its regulations ("**HIPAA**") or is health or medical data under another Applicable Law. [COUNSEL: confirm the definition, including state consumer-health-data laws.]
- "**Healthcare Provider**" means a person or organization that provides, arranges, bills for or is paid for health care, including a physician or dental practice, clinic, hospital, pharmacy, laboratory, telehealth service, health plan or health-care clearinghouse, a business associate of any of them, and any other business whose use of the Services would involve Health Information. [COUNSEL: confirm the scope, including wellness and fitness businesses.]
- "**Loop Content**" means everything Customer places in, or collects or sends through, a Loop, including text, labels, options, fields, attachments, images, the data Consumers enter, and the actions Customer connects to it.
- "**Messaging Policy**" means the [Messaging Consent and Content Policy Addendum](/legal/messaging-consent-content-policy-addendum/).
- "**Order Form**" means an ordering document or Dashboard plan selection that references this Agreement.
- "**Personal Data**" has the meaning given in the [Data Processing Addendum](/legal/data-processing-addendum/) (the "**DPA**").
- "**Security Incident**" has the meaning given in the DPA.
- "**Services**" means the Business API, the Dashboard, Business Workflows, Brand Kits, the commerce features described in section 3.9, the Approval Services, the Verification Services, the messaging services and any other Viadere service ordered by Customer or made available to it.
- "**Shopify**" means Shopify Inc. and its affiliates, and "**Shopify Store**" means a store that Customer operates on Shopify's platform under Customer's own agreement with Shopify.
- "**Verification Services**" or "**Verify**" means Viadere's services for confirming an attribute about a Consumer at Customer's request, as set out in the [Verification Services Addendum](/legal/verification-services-addendum/).

## 2. Structure and order of precedence

### 2.1 Documents

This Agreement consists of: (a) these terms; (b) each Order Form; (c) the Exhibits; (d) the following addenda, which apply as stated: the [Data Processing Addendum](/legal/data-processing-addendum/) (all Customers that give Viadere Personal Data to process), the [Messaging Consent and Content Policy Addendum](/legal/messaging-consent-content-policy-addendum/) (all Customers), the [MFA and Approval Services Addendum](/legal/mfa-approval-services-addendum/) (Customers using Approve), the [Verification Services Addendum](/legal/verification-services-addendum/) (Customers using Verify); and (e) the [Acceptable Use Policy](/legal/acceptable-use-policy/), the [Subprocessors](/legal/subprocessors/) list and the Documentation.

### 2.2 Precedence

If there is a conflict, the order of priority is: (1) the DPA, for Personal Data matters; (2) the applicable addendum for the service it covers; (3) the Order Form, but only where it expressly states that it overrides a specific section of this Agreement; (4) these terms and the Exhibits; (5) the Acceptable Use Policy; and (6) the Documentation. Purchase orders, vendor forms and other terms from Customer do not apply, even if Viadere signs or acknowledges them.

### 2.3 Material changes

Viadere may update the addenda, the Acceptable Use Policy and the Documentation. A change to a legal document that is material is published as a new version at a stable address and takes effect for Customer on the date set in the notice. Customer must accept the current version in the Dashboard to keep production access (section 6.5). Viadere will give at least [30] days' notice of a material change, except where a shorter period is needed for security, legal or safety reasons. If Customer does not accept a material change that adversely affects it, Customer may terminate the affected Services under section 18.4.

## 3. The Services

### 3.1 Provision

Subject to this Agreement, Viadere grants Customer a non-exclusive, non-transferable (except under section 25.2), non-sublicensable, revocable right during the Term to access and use the Services, for its own internal business purposes, to communicate with Consumers who have connected to Customer and to request approvals and verifications from them. Viadere will provide the Services in accordance with the Documentation and this Agreement.

### 3.2 Nature of the Services

Viadere is a connection and delivery layer. Viadere does not decide whether a Consumer may access Customer's systems, complete a purchase or receive a benefit. Customer remains the authoritative system of record for its customers and is solely responsible for its access, risk, fraud and transaction decisions. Viadere does not accept, process or hold payments, and is not the merchant of record for any sale (section 3.9). An approval that a Consumer gives through the Services is a record of the Consumer's consent and does not charge or move money. Viadere is not Customer's agent and does not give legal, financial or compliance advice.

### 3.3 Product status

Messaging and Approve are in beta, and Verify and Authenticator are planned. Customer acknowledges that beta features may change, be interrupted or be withdrawn, that Planned features are not available and may not launch, and that Viadere's roadmap statements are not commitments. Beta features are provided under section 3.4, and the support and service levels in Exhibit B do not apply to them unless the Order Form says so.

### 3.4 Beta and sandbox

Beta features and the sandbox (test keys) are provided "as is" and for evaluation. Sandbox activity is not delivered to real Consumers, is not billed and may be reset or deleted at any time. Customer must not put production Personal Data in the sandbox.

### 3.5 Changes to the Services

Viadere may improve, change or discontinue features. Viadere will use reasonable efforts to give [90] days' notice of the discontinuation of a generally available Capability or a version of the Business API that Customer uses, and will maintain a deprecation timetable in the Documentation, except where a shorter period is needed for security or legal reasons. Customer's remedies for a discontinuation of a paid Service are in section 18.5.

### 3.6 Priority and neutrality

Fees buy quotas and plan features only. Payment never changes the priority of a message, never allows a business to override a Consumer's consent and never buys priority over security or authorization requests. Urgent priority is reserved for security sign-in and authorization requests. Marketing and rewards are never given more than normal priority.

### 3.7 Business Workflows ("Loops")

(a) **What they are.** A Business Workflow is optional. Customer builds it only from the components and registered actions that Viadere provides; Customer cannot add code, scripts, markup or links of its own. Core features of the Services do not depend on a Loop.

(b) **Viadere review before publication.** Every Loop, and every revision of a Loop, is reviewed by Viadere before it is published. Review includes automated checks and review by Viadere personnel, and a second reviewer for higher-risk actions. A Loop that has not been approved is not shown to any Consumer. Approval is not a representation that a Loop is lawful, accurate or suitable, and does not shift any responsibility under this Agreement from Customer to Viadere.

(c) **Viadere's discretion.** Viadere may refuse to approve, decline to publish, pause, suspend or remove any Loop, or suspend Customer's ability to use Loops, at its discretion and at any time, including where Viadere believes the Loop or its use conflicts with the Acceptable Use Policy, creates risk for Consumers, or draws Consumer reports. Viadere will where practical tell Customer why. Section 8.3 (appeal) applies, but Viadere may keep a Loop paused while an appeal is pending.

(d) **Customer is accountable for its Loops.** Customer is responsible for all Loop Content, for what it promises or asks of Consumers through a Loop, and for everything that happens after a Consumer completes an action in a Loop, including fulfilment, appointments, orders, follow-up communications, record-keeping, and its handling of any data it receives (together, "**Downstream Operations**"). Viadere delivers the Loop and records the Consumer's action; Customer performs the service. Customer will be named to Consumers as the author of each Loop (section 3.7(f)).

(e) **Consumer opt-in.** Loops are off by default. A Consumer must turn on Loops in the Viadere app and separately authorize Customer's Loops before any of Customer's Loops is available to that Consumer, and may withdraw either choice at any time. Customer will not request or imply that a Consumer must use a Loop to receive a core service, and will not circumvent or pressure a Consumer's choice.

(f) **Attribution.** Every Loop displays "Built by" followed by Customer's verified business name. Customer will not alter, hide or imitate that attribution or any Viadere security language, and will not present a Loop as made or endorsed by Viadere.

(g) **No Health Information, no payments.** Customer will not use a Loop to ask for, collect, send or act on Health Information (section 5.10), and will not use a Loop to accept, request or process payment or card details. A Loop may refer a Consumer to Customer's own Shopify checkout only through the feature described in section 3.9.

(h) **Viadere's role.** Viadere is accountable for operating the Business Workflow platform as this Agreement describes. Viadere is not responsible for Customer's Downstream Operations or for the accuracy or legality of Loop Content. Nothing in this section 3.7 excludes or limits an obligation or liability that cannot be excluded or limited under Applicable Law. [COUNSEL: confirm allocation and consumer-law carve-outs.]

### 3.8 Brand Kits

(a) A Brand Kit is optional and changes only how Customer's name and surfaces look in Viadere-owned screens. It cannot change the text, buttons or security indicators of an approval, sign-in or other security screen.

(b) Customer may upload logos and artwork only as PNG or JPEG files. Viadere re-encodes every upload, removes embedded metadata, may resize it, and may reject a file that fails its checks. Other file types, including SVG, are not accepted.

(c) Viadere may override, limit, replace or disable any part of a Brand Kit at any time, including to maintain readable contrast and accessibility, to protect Consumers from confusion or deception, or for safety or security reasons, and may show Customer's surfaces in Viadere's neutral style instead.

(d) Customer represents and warrants that it owns, or has all rights necessary to use and to license, every mark, name, image and other material in its Brand Kit, and that their use through the Services does not infringe or violate the rights of any person or any Applicable Law.

(e) Customer grants Viadere a worldwide, non-exclusive, royalty-free licence during the Term (and afterwards as needed to complete deletion and legal duties) to host, store, re-encode, reproduce, cache and display Brand Kit materials to Consumers and in the Dashboard as part of the Services.

(f) Viadere may remove Brand Kit materials on a good-faith complaint of infringement or other harm, and will handle notices under section 6 of the Acceptable Use Policy. Customer will provide any information Viadere reasonably asks for in a complaint.

### 3.9 Commerce through Shopify

(a) **Shopify only.** Customer may connect its own Shopify Store to the Services. Viadere supports no other commerce connector.

(b) **What Viadere does.** Through the connection Viadere may show a Consumer Customer's products and the status of the Consumer's orders, and may hand the Consumer over to Customer's own Shopify checkout page. Viadere does not offer a checkout of its own.

(c) **Viadere never accepts or holds payment and is never the merchant of record.** Viadere does not accept, process, transmit or hold payments, payment credentials or funds, and is not a party to any sale between Customer and a Consumer. Customer is the seller and the merchant of record. The sale, the price (as Customer sets it in Shopify), payment, refunds, returns, taxes, shipping, fulfilment, warranty and disputes are matters between Customer and the Consumer, and for payment, Shopify and its payment providers apply. Customer is solely responsible for them and for compliance with all consumer-protection, tax and commerce laws that apply to its sales.

(d) **Shopify terms.** Customer's use of Shopify is governed by Customer's agreement with Shopify and Shopify's terms, which Customer must follow. Viadere is not a party to them and is not responsible for Shopify's services, availability or acts. Customer authorizes Viadere to access its Shopify Store with the read permissions Customer grants in the connection flow and may revoke that authorization in Shopify or in the Dashboard.

(e) **Data.** Viadere receives order-status information from Shopify as set out in the [DPA](/legal/data-processing-addendum/). Customer is responsible for the lawfulness of making that information available and for telling Consumers about it.

(f) **Digital goods and in-app products.** Customer will use the commerce features only for physical goods and for services that are used outside the Viadere app, and not for digital content or functionality used in the app. [COUNSEL AND PRODUCT: confirm against current app-store rules.]

(g) **Estimates and approvals.** An approval of an estimate, quote or terms through the Services is a record of the Consumer's consent. It is not a payment, does not charge or move money, and does not make Viadere a party to the transaction.

## 4. Onboarding, verification and ongoing assurance

### 4.1 Application and business verification

Customer starts as pending. To obtain a handle, a permanent business code and production access, Customer must complete Viadere's onboarding and provide accurate and complete information. Onboarding includes (a) creating an Organization with a verified work email address and passkey sign-in; (b) proving control of its domain by a DNS record or a file at a well-known address; (c) validating its legal entity by supplying a registry number, jurisdiction and references to the evidence; (d) additional review for sensitive categories such as banking and government, and a screen that refuses businesses in the categories listed in section 5.10; (e) accepting this Agreement and the applicable addenda; (f) configuring and testing an integration in the sandbox; and (g) a go-live review that considers the use case, security posture and abuse limits. Viadere may request more information at any time and may refuse an application, or limit or condition access, at its discretion. A category label alone is not an access decision.

::: disclosure
A verified business has completed Viadere's business-identity checks. Verification does not constitute an endorsement, guarantee of legitimacy, or confirmation of regulatory licensing.
:::

### 4.2 Handles and codes

A business handle and permanent business code identify Customer within Viadere. A code is never reassigned to a different business, even if Customer leaves. Handles and codes are licensed to Customer for use with the Services, are not property, and may not be transferred or sold. Viadere may reject, reserve or withdraw a handle or code that infringes a trademark, impersonates another person, or is confusingly similar to another business's handle or to Viadere's marks.

### 4.3 Accuracy and updates

Customer will keep its registration, legal-entity, domain, contact and security-contact information accurate and up to date and will tell Viadere within [10] business days of a change of control, of its legal name or of its security contact. Customer will answer Viadere's reasonable requests for verification information within [10] business days.

### 4.4 Ongoing assurance

Viadere may periodically re-verify domain control and legal-entity status and may require re-acceptance of current legal documents. If a check fails, Viadere will notify Customer's owners and allow a grace period of [14] days to fix it. If it is not fixed, Viadere may suspend Customer's production access until it is.

### 4.5 Risk tiers

Capabilities are made available by risk tier: messaging (Tier M), approvals (Tier A), verified attributes (Tier V) and enterprise or regulated (Tier E). Access to a higher tier needs an additional review and acceptance of the relevant addendum. Viadere may grant, limit, review or revoke a Capability or tier for a Customer, with a recorded justification. A verified badge never implies that Customer is approved for every Capability.

### 4.6 Names and verification marks

Customer may state, accurately, that it is a "verified business on Viadere". It may not say or imply that Viadere endorses it, guarantees its legitimacy or has confirmed its licensing, and may not use the Viadere marks except in accordance with Viadere's brand guidelines and section 23.

## 5. Customer's responsibilities

### 5.1 General

Customer is responsible for: (a) all activity under its Account, keys and endpoints; (b) its Business Content, including its accuracy, legality and the right to send it; (c) its use of the Services in compliance with this Agreement and Applicable Law; (d) its end-user communications and its decisions about its customers; and (e) the acts and omissions of its personnel, contractors and service providers who use the Services for it.

### 5.2 Consent and lawful basis

Customer must have, and must be able to prove on request, a valid lawful basis and, where the law requires, the Consumer's prior express consent, for each message and request it sends through the Services, for each purpose (security, account service, transactional, support, marketing and rewards). Customer will use only the purposes the Consumer has allowed in Viadere. Viadere's recording of a Consumer's consent in the app is a record of that choice; it is not a representation that the consent satisfies any particular law as applied to Customer's program.

### 5.3 Lawful content

Customer will not send content that is unlawful, deceptive, defamatory, infringing, harassing, obscene or discriminatory, that violates the Acceptable Use Policy, or that contains malware or phishing. Display text must not impersonate Viadere or another business, and the Services will reject text that does. Customer must clearly identify itself in each message and request.

### 5.4 Opt-out handling

Customer will honor opt-out and revocation of consent immediately and in any event within the time the law and carrier rules allow. The Services handle opt-out keywords (such as STOP and its variants) on the Viadere text channels and the consent states in the Viadere app. Customer must also honor a Consumer's opt-out received from any other source and must not message a Consumer through another channel to avoid an opt-out. Customer must keep its own suppression records and must not rely on Viadere's records as its only record.

### 5.5 Registration and carrier compliance

Viadere will register and operate the Viadere sender numbers and campaigns with its providers and carriers. Where a Capability or channel requires a registration of Customer itself, such as an A2P 10DLC brand and campaign, a toll-free verification, an RCS agent or other carrier or aggregator registration, Customer will complete it accurately and promptly. Customer will comply with the carriers' and the Cellular Telecommunications Industry Association's (CTIA) messaging principles and with the policies of Viadere's providers that Viadere flows down to Customer. Customer acknowledges that carriers can block or filter messages, change rules and impose fines or fees, and that Viadere does not guarantee delivery. Customer is responsible for fines and penalties imposed by a carrier or provider that result from Customer's content or conduct.

### 5.6 Security-sensitive actions

Customer will not request approval by text for anything that must be approved in the app, will not accept a text reply as an authorization of a security-sensitive action, and will verify the signed approval result itself as stated in the MFA and Approval Services Addendum. A delivery or relay status alone is not evidence of approval.

### 5.7 Reasonable use and no circumvention

Customer will not exceed or circumvent rate limits, quotas, priority caps, consent checks, cool-downs, freezes or other protections; will not probe other businesses' data or attempt to correlate Consumers across businesses; and will not use the Services to build a profile of a Consumer across businesses.

### 5.8 Cooperation

Customer will provide reasonable cooperation to Viadere in investigating abuse, complaints, regulatory inquiries and Security Incidents.

### 5.9 Regulated and high-risk use

Customer will not use the Services for a regulated or high-risk purpose, including financial services, gambling, age-restricted goods and services, or services to children, unless the relevant Capability, tier and addendum have been approved in writing for that purpose. Verification does not by itself satisfy Customer's know-your-customer, anti-money-laundering, sanctions, age-assurance or other regulatory duties. Healthcare is not a use that can be approved: section 5.10 applies.

### 5.10 Healthcare and Health Information are prohibited

(a) **Healthcare Providers may not use the Services.** No Healthcare Provider, and no other business whose use of the Services would involve Health Information, may use the Services for any purpose, including messaging, approvals, verification, rewards, Business Workflows, Brand Kits and commerce features. Customer represents that it is not, and will promptly tell Viadere if it becomes, a Healthcare Provider or a business whose use involves Health Information.

(b) **No Health Information through any feature.** Customer will not collect, request, store, send or act on Health Information through the Services, including in any Business Content, message, Loop, form field, attachment, template, display text or metadata, and will not design any workflow that invites a Consumer to supply it. Customer will tell Consumers not to share health details through the Services where a free-text field or message could otherwise invite them to.

(c) **No business-associate role.** Viadere does not want, and is not authorized to receive, Health Information. Viadere is not a "business associate" of Customer, does not act as one, and will not enter into a business-associate agreement or any similar agreement for Health Information with Customer. Nothing in this Agreement, any Order Form or any other document creates such a role, and no statement to the contrary by any person is effective unless it is in a document signed by an authorized officer of Viadere that expressly refers to this section 5.10. [COUNSEL: confirm wording and HIPAA position.]

(d) **Screening and refusal.** Viadere may screen applications, Business Content and use, automatically and by review, for Healthcare Providers and Health Information, and may refuse an application, decline to approve a Loop or other content, or reclassify a Customer on that basis. Viadere is not obliged to find a breach of this section.

(e) **Offboarding.** If Viadere reasonably believes Customer is a Healthcare Provider, or that Customer or its Business Content involves Health Information, Viadere may immediately suspend the Services in whole or part and remove the Business Content concerned, and may terminate this Agreement under section 18.3, with or without notice where it considers delay would create risk. Viadere will where practical give Customer a short period to export its Business Content (other than Health Information, which Viadere may delete without return) and will end all Customer's Business Workflows. Fees prepaid for the period after termination under this section are refunded pro rata [COUNSEL: confirm].

(f) **If it happens anyway.** If Health Information reaches the Services despite this section, Customer must tell Viadere at once, stop the activity, and cooperate in deleting it. Viadere may delete it, and any fee, loss or liability that results is Customer's responsibility to the extent the law allows.

## 6. API, credentials and endpoints

### 6.1 Credentials

Viadere gives Customer API keys and webhook signing secrets. Each key has only the scopes needed and is shown once at creation. Customer will keep keys, secrets, certificates and passkeys confidential; will use the least scope needed; will store keys securely (not in client-side code, source control, logs or tickets); will use test keys (vdk_test_) in the sandbox and live keys (vdk_live_) only in production; and will rotate keys on a regular schedule and at least [every 12 months]. Customer will tell Viadere within [24 hours] of becoming aware of a suspected compromise of a key, secret or Dashboard account, and will revoke it. Customer is responsible for all use of its credentials until it has revoked them.

### 6.2 Viadere's control of credentials

Viadere may revoke, restrict or require rotation of a key or secret at any time if it believes it has been compromised, is being misused or poses a risk, and may restrict a key to an IP allow-list or require a client certificate for higher tiers. Viadere will use reasonable efforts to tell Customer promptly.

### 6.3 Webhooks

Customer's webhook endpoints must be public https addresses that Customer controls and has proven, must verify the signature of each event, must respond promptly, and must treat events as at-least-once delivery that can be repeated or arrive out of order. Viadere does not follow redirects and may pause or disable an endpoint that repeatedly fails or is unsafe. Event delivery bodies are retained for a limited time as stated in the DPA.

### 6.4 Use of the API and documentation

Customer will use the Business API only through the interfaces and versions described in the Documentation, will follow versioning and deprecation rules, will set an idempotency key where required and will respect rate limits. Viadere may impose reasonable limits and change them with notice. Customer will not use the Business API to build a competing service or to benchmark it for public release without Viadere's written consent [COUNSEL: confirm].

### 6.5 Acceptance of current documents

Customer's Owner or Organization Admin must accept the then-current version of the Agreement and the required addenda in the Dashboard. If Customer does not accept a current material version within the notice period, Viadere may restrict production access until it does.

### 6.6 Sandbox and test data

The sandbox mimics the production API but is not production. Customer will not rely on sandbox behavior as a guarantee of production behavior.

### 6.7 Dashboard users

Customer will manage its Dashboard users, assign roles on a least-privilege basis, remove access promptly when a person leaves, enable the available security settings (such as an IP allow-list, a two-person rule and client certificates for higher tiers) and keep its security contacts current. Each user must sign in with their own passkey and must not share credentials.

## 7. Fees, taxes and payment

### 7.1 Fees

Customer will pay the Fees. The Fee categories are: a platform fee for metered interactions; a per-message fee; a verification fee, once Verify is available; carrier fees passed through for SMS and RCS delivery, which vary by carrier, content and direction; provider fees passed through for messaging and verification providers; and an overage fee for use beyond the quota or plan limits. Amounts are in the Order Form and Exhibit C. Until Viadere publishes a price, Customer is not charged for the unpriced category. [PRODUCT: pricing is not set.] Sandbox traffic is not billed.

### 7.2 Free tier

The default free tier includes a daily limit on live interactions (currently 1,000). Viadere may change the free tier on [30] days' notice.

### 7.3 Invoicing and payment

Viadere will invoice [monthly in arrears]. Customer will pay undisputed amounts within [30] days of the invoice date, in [US dollars], by [the method in the Order Form]. Late amounts bear interest at the lower of [1.0% per month] and the maximum the law allows, and Viadere may suspend the Services on [10] days' notice for non-payment of undisputed amounts. Customer will pay Viadere's reasonable costs of collection.

### 7.4 Disputes

Customer may dispute an invoice in good faith by notifying Viadere within [30] days of the invoice date, with details. The parties will work to resolve it within [30] days. Customer will pay the undisputed part on time.

### 7.5 Taxes

Fees exclude taxes, duties and levies, including sales, use, value-added and goods-and-services taxes, and regulatory and carrier surcharges. Customer will pay them, other than taxes on Viadere's net income. If Customer must withhold tax, it will gross up the payment so that Viadere receives the amount it would have received without withholding, unless it gives a valid exemption certificate.

### 7.6 Fee changes and carrier pass-through

Viadere may change prices on [60] days' notice, effective at the next renewal or billing period. Carrier and provider fees may change with the underlying charges on shorter notice, and Viadere will pass on the change without markup beyond that stated in Exhibit C.

### 7.7 No offset

Fees are non-cancellable and non-refundable except as this Agreement says. Customer may not set off amounts it claims against amounts it owes.

## 8. Trust controls, limits and suspension

### 8.1 Limits and quotas

Viadere applies rate limits, daily quotas, priority caps and complaint-based controls. Viadere may reduce a Customer's limits when complaint, opt-out, blocked-message or abuse rates exceed thresholds that Viadere sets [COUNSEL AND TRUST AND SAFETY: publish thresholds, for example a complaint rate above [0.1%] or an opt-out rate above [2%] over [7] days] and may throttle, pause a type of request to a Consumer who has denied or reported several requests, or temporarily pause a Capability.

### 8.2 Suspension

Viadere may suspend all or part of the Services, for as long as needed, if: (a) Customer breaches this Agreement or the Acceptable Use Policy; (b) Viadere reasonably believes there is a Security Incident, fraud, abuse, a threat to Consumers, a legal requirement or an order of a regulator, carrier or provider; (c) Customer's verification lapses and is not fixed within the grace period; or (d) Customer does not pay undisputed Fees as in section 7.3. Viadere will give notice and an opportunity to fix where it can and where doing so does not increase risk, and will restore the Services promptly when the cause is resolved. Viadere may do so without prior notice where urgent.

### 8.3 Appeal

Customer may appeal a suspension or restriction by writing to [TRUST-CONTACT-PLACEHOLDER] with its reasons. Viadere will review the appeal with a reviewer who was not involved in the decision and respond within [10] business days. [COUNSEL: confirm process.]

### 8.4 Operator measures

Viadere may disable a Capability globally or for a Customer, revoke a key or all keys without suspending the Customer, and send notices to Customers. It may do this to protect Consumers or the service.

### 8.5 Business Workflows and Brand Kits

Viadere may pause, suspend or remove a Loop, a Loop revision or a Brand Kit, or switch off Loops or Brand Kits for Customer, under sections 3.7(c) and 3.8(c), and under section 5.10(e). A pause shows Consumers a neutral message. It does not delete Customer's data.

## 9. Security

### 9.1 Viadere's security program

Viadere maintains a security program with administrative, technical and organizational measures designed to protect the Services and Consumer Data, described in the [security overview](/security/) and in Annex II of the DPA. These include encryption in transit and at rest, field-level encryption of sensitive data, key management in a hardware-backed service, least-privilege access, tamper-evident audit logs, vulnerability management and incident response. Viadere may update the measures, but will not materially reduce the overall level of protection during the Term.

### 9.2 Customer's security

Customer will maintain reasonable security for its systems, credentials, endpoints and personnel that interact with the Services, consistent with industry practice for the risk, and will implement the integration security requirements of the Documentation for the tiers it uses.

### 9.3 Security incidents

Each party will notify the other of a Security Incident that affects the other as stated in the DPA and the [Incident Notification Policy](/legal/incident-notification-policy/).

### 9.4 Testing

Customer may test only the sandbox and its own integration. Customer will not scan, probe or penetration-test Viadere's production systems except as the [Vulnerability Disclosure Policy](/legal/vulnerability-disclosure-policy/) allows. Customer may not test another Customer's data or Consumers' accounts.

### 9.5 Approval evidence

::: disclosure
Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.
:::

The details of signature validation, key enrollment, fallback and dispute handling are in the MFA and Approval Services Addendum.

## 10. Data protection and privacy

### 10.1 Roles and DPA

For Consumer Data that Viadere processes on Customer's behalf to provide the Services, Viadere acts as Customer's processor or service provider, and the DPA applies and is incorporated into this Agreement. For the data Viadere handles for its own purposes, namely operating Consumers' accounts, devices and consent records, preventing fraud and abuse and keeping security and dispute records, Viadere acts as an independent controller, as described in the [Privacy Notice](/legal/privacy-notice/). The parties acknowledge that each is responsible for its own compliance with data-protection laws. [COUNSEL: confirm the roles for each Capability.]

### 10.2 What Customer receives

Customer receives for each Consumer a pairwise reference that is unique to Customer, the decisions the Consumer makes, the messages the Consumer sends it and the Consumer's consent state. Customer does not receive a Consumer's Viadere identity, phone number or other connections through the Services unless the Consumer chooses to give it. Customer will not attempt to re-identify, link, enrich or correlate a Consumer across businesses by using the Services, and will not use Consumer Data received through the Services to build a cross-business profile.

### 10.3 Customer's use of Consumer Data

Customer is an independent controller (or business) of Consumer Data it receives and holds, and will use it only in line with its own privacy notice, the purposes the Consumer allowed and Applicable Law. Customer will not sell or share it for cross-context behavioral advertising, and will not use it to discriminate against a Consumer for using a privacy right.

### 10.4 Verified attributes

If Customer uses Verify, it will request only the attribute it needs, state an accurate purpose, display the required consent text, retrieve the result once within its short validity period, and keep or delete the result as the Verification Services Addendum requires.

### 10.5 Retention settings

Customer may shorten, but not lengthen, the platform retention period for its own data in the classes the Dashboard allows. Viadere may keep records needed for security, disputes, billing, legal holds and legal duties as the Privacy Notice and the DPA describe.

### 10.6 Consumer requests

Each party will help the other to respond to Consumer requests under data-protection laws as the DPA states. Viadere is not responsible for data that Customer holds about a Consumer.

### 10.7 Government requests

Viadere handles government requests as stated in the [Law-Enforcement Request Policy](/legal/law-enforcement-request-policy/).

### 10.8 No Health Information; order-status data

Customer will not send Health Information to Viadere, and the DPA does not cover it (section 5.10). Where Customer connects a Shopify Store, Viadere processes order-status data for Customer as the DPA describes, and Shopify is a service Customer chooses and contracts with directly, not a Viadere subprocessor. [COUNSEL: confirm roles for Shopify data.]

## 11. Compliance with laws

### 11.1 General

Each party will comply with the laws that apply to it in connection with this Agreement. Customer is responsible for determining that its use of the Services complies with the laws that apply to its business and its communications. Viadere is not responsible for deciding whether Customer may lawfully contact a person.

### 11.2 Communications laws

Customer will comply with Applicable Law about electronic communications, including in the United States the Telephone Consumer Protection Act and Federal Communications Commission rules, state telemarketing and "mini-TCPA" laws, the CAN-SPAM Act for email, the Telemarketing Sales Rule and the carriers' and CTIA's messaging rules; in Canada Canada's Anti-Spam Legislation; and elsewhere, the laws that apply to its recipients. It will honor quiet hours and time-of-day rules that apply, will identify itself and will include opt-out instructions where required. Messages through Viadere's shared text number are sent under a program and campaign registered by Viadere, and Customer's messages must fit within that registered use case.

### 11.3 Privacy laws

Each party will comply with the privacy and data-protection laws that apply to it, which may include the GDPR and UK GDPR, the California Consumer Privacy Act as amended, other US state privacy laws and Canadian federal and provincial laws. Customer will provide any notices and obtain any consents those laws require for its own processing.

### 11.4 Anti-corruption, sanctions and export

Each party will comply with applicable anti-bribery laws. Customer represents that neither it nor its owners, directors or end users are subject to sanctions or located in an embargoed jurisdiction, and will not use or export the Services in violation of export laws.

### 11.5 Accessibility and consumer protection

Customer will provide Consumer-facing content in a way that meets the accessibility and consumer-protection laws that apply to it, and will not use deceptive or misleading design in a request or message.

## 12. Confidentiality

### 12.1 Definition

"**Confidential Information**" means non-public information that a party ("**Discloser**") gives to the other ("**Recipient**") that is marked confidential or that a reasonable person would consider confidential given its nature and the circumstances, including Customer's keys, secrets and non-public business information and Viadere's non-public technical, security, roadmap and pricing information. It does not include information that: (a) is or becomes public through no fault of the Recipient; (b) was known to the Recipient without confidentiality before disclosure; (c) is received from a third party without a duty of confidentiality; or (d) is independently developed without use of the Discloser's information. Consumer Data is governed by section 10 and the DPA, and is Customer's Confidential Information only as and to the extent stated there.

### 12.2 Obligations

The Recipient will use Confidential Information only to perform or use the Services under this Agreement, will protect it with at least the care it uses for its own similar information and not less than reasonable care, and will disclose it only to its and its Affiliates' employees, contractors, advisers and subprocessors who need to know it and are bound by duties at least as protective.

### 12.3 Compelled disclosure

The Recipient may disclose Confidential Information if required by law, regulation or court order, if it gives the Discloser prompt notice where lawful and cooperates, at the Discloser's expense, in seeking protection, and discloses only what is legally required.

### 12.4 Duration and return

These duties last during the Term and for [five] years after it ends (and for trade secrets and keys, as long as they remain secret). On request after termination, the Recipient will return or delete the Discloser's Confidential Information, except for copies in routine backups or that it is required by law to keep, which stay subject to this section.

### 12.5 Injunctive relief

A breach of this section may cause harm for which damages are not adequate, and the Discloser may seek injunctive relief without proof of actual damages.

## 13. Intellectual property

### 13.1 Viadere's property

Viadere and its licensors own all rights in the Services, the Documentation, the software, the SDKs, the marks and anything derived from them, including improvements. Except for the rights expressly granted, no rights are granted. The Viadere SDKs are licensed to Customer under the licence that accompanies them for use with the Services.

### 13.2 Customer's property

Customer owns its Business Content and its marks and grants Viadere a worldwide, non-exclusive, royalty-free licence during the Term (and afterwards as needed to complete deletion and legal duties) to host, process, transmit, display and reproduce Business Content to provide, secure and support the Services and as this Agreement and the DPA allow, including making Business Content visible to Consumers. Section 3.8(e) adds the licence for Brand Kit materials. Customer is responsible for having the rights to grant these licences, and Viadere does not acquire ownership of Customer's marks or Loop Content.

### 13.3 Usage data

Viadere may collect and use technical and usage data about the operation of the Services, such as counts, latency, errors and abuse signals, which does not identify Customer or a Consumer, to operate, secure, improve and develop the Services. [COUNSEL: define "aggregated and de-identified" consistently with the DPA.]

### 13.4 Feedback

If Customer gives feedback, Viadere may use it without restriction or payment.

### 13.5 Restrictions

Customer will not copy, modify, reverse engineer, decompile or attempt to derive the source code of the Services (except where the law does not allow this restriction), will not use the Services to build a competing service, will not sublicense, resell or provide the Services to third parties except as expressly permitted, and will not remove proprietary notices.

## 14. Third-party services and providers

The Services depend on third-party services, including carriers, messaging and RCS providers, Apple and verification providers. Viadere is not responsible for those third parties' acts or omissions beyond its obligations in the DPA, and Customer acknowledges that their requirements, outages and changes may affect the Services. Viadere will use providers on commercially reasonable terms and will list its subprocessors on the [Subprocessors](/legal/subprocessors/) page. Customer is responsible for its own third-party services, including any customer-support platform or CRM that receives messages from Viadere. Shopify is a third-party service that Customer chooses to connect (section 3.9). Customer's agreement and relationship with Shopify are its own, and Shopify's own terms apply to Shopify's services.

## 15. Warranties and disclaimers

### 15.1 Mutual

Each party represents that: it has the power and authority to enter this Agreement; entering it does not breach any other agreement or order that binds it; and it will comply with the laws that apply to it in performing it.

### 15.2 Viadere

Viadere warrants that it will provide the Services (other than beta features and the sandbox) in a professional manner in all material respects as described in the Documentation, and that it will not materially decrease the overall functionality of a generally available Service during a paid Term. Customer's exclusive remedy, and Viadere's entire liability, for a breach of this warranty is for Viadere to use commercially reasonable efforts to correct the non-conformity or, if it cannot do so within [30] days, for either party to terminate the affected Service with a pro-rata refund of prepaid Fees for the remainder of the Term.

### 15.3 Customer

Customer represents and warrants that: the information in its application is accurate and complete; it has all rights, notices and consents needed to send its Business Content and to use the Services as it does; its Business Content does not infringe a third party's rights or violate Applicable Law or the Acceptable Use Policy; and it will obtain and keep valid any registrations and licences it needs for its business.

### 15.4 Disclaimer

EXCEPT AS EXPRESSLY STATED IN THIS AGREEMENT, THE SERVICES, THE SANDBOX, BETA FEATURES AND THE DOCUMENTATION ARE PROVIDED "AS IS" AND "AS AVAILABLE", AND EACH PARTY DISCLAIMS ALL OTHER WARRANTIES, EXPRESS, IMPLIED OR STATUTORY, INCLUDING MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT AND ANY WARRANTY ARISING FROM COURSE OF DEALING OR USAGE. VIADERE DOES NOT WARRANT THAT THE SERVICES WILL BE UNINTERRUPTED OR ERROR-FREE, THAT ANY MESSAGE, NOTIFICATION OR REQUEST WILL BE DELIVERED, OR DELIVERED WITHIN A PARTICULAR TIME, THAT A CARRIER WILL NOT BLOCK OR FILTER A MESSAGE, THAT A CONSUMER WILL RESPOND, OR THAT A VERIFICATION OR APPROVAL RESULT IS A GUARANTEE OF A PERSON'S IDENTITY, AGE, ELIGIBILITY OR INTENT. SMS IS NOT END-TO-END ENCRYPTED, AND VIADERE DOES NOT WARRANT THE CONFIDENTIALITY OF CONTENT SENT BY SMS.

## 16. Indemnification

### 16.1 By Viadere

Viadere will defend Customer and its officers, directors and employees (the "**Customer Indemnitees**") against any third-party claim, suit or proceeding to the extent it alleges that the Services, as provided by Viadere and used in accordance with this Agreement, infringe or misappropriate a third party's patent, copyright, trademark or trade secret (an "**IP Claim**"), and will pay the damages, costs and reasonable legal fees finally awarded or agreed in settlement. Viadere has no obligation to the extent the claim arises from Business Content, from combination with items Viadere did not supply, from use not permitted by this Agreement or from Customer's specifications. If an IP Claim occurs or is likely, Viadere may procure the right to continue, modify the Services so they do not infringe, or terminate the affected Service and refund prepaid Fees for the remainder of the Term. This section states Viadere's entire liability and Customer's exclusive remedy for IP Claims.

Viadere's review and approval of a Loop, a Brand Kit or any Business Content is a platform safeguard for Consumers and is not a warranty, an endorsement or an assumption of Customer's responsibilities. [COUNSEL: confirm placement.]

### 16.2 By Customer

Customer will defend Viadere, its Affiliates and their officers, directors, employees and agents (the "**Viadere Indemnitees**") against any third-party claim, suit, investigation or proceeding (including by a Consumer, a regulator, a carrier or a provider) arising from: (a) Business Content; (b) Customer's breach of section 5 (including consent, lawful content, opt-out and carrier compliance), section 10.2 or 10.3 or the Acceptable Use Policy; (c) Customer's violation of Applicable Law; (d) a decision Customer makes about a Consumer, access, a transaction or an account, including one based on an Approval or Verify result; (e) Loop Content or Customer's Downstream Operations; (f) Brand Kit materials, including any claim that they infringe or violate a third party's rights; (g) Customer's sales through Shopify, including payment, refunds, taxes, shipping and disputes, or Customer's breach of its agreement with Shopify; (h) Health Information sent through the Services in breach of section 5.10; or (i) a fine, penalty or charge imposed by a carrier or provider because of Customer's content or conduct. Customer will pay the damages, fines, costs and reasonable legal fees finally awarded or agreed in settlement.

### 16.3 Procedure

The indemnified party will (a) give prompt written notice of the claim (a delay relieves the indemnifying party only to the extent it is prejudiced); (b) give the indemnifying party sole control of the defense and settlement (but it may not settle in a way that imposes liability or an admission on the indemnified party without its consent, not to be unreasonably withheld); and (c) give reasonable assistance at the indemnifying party's expense. The indemnified party may take part with its own counsel at its own cost.

## 17. Limitation of liability

### 17.1 Exclusion

TO THE FULLEST EXTENT PERMITTED BY LAW, NEITHER PARTY WILL BE LIABLE TO THE OTHER, UNDER ANY THEORY (CONTRACT, TORT INCLUDING NEGLIGENCE, STRICT LIABILITY OR OTHERWISE), FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY OR PUNITIVE DAMAGES, OR FOR LOST PROFITS, REVENUE, GOODWILL, BUSINESS OPPORTUNITY OR ANTICIPATED SAVINGS, OR LOSS OR CORRUPTION OF DATA, ARISING OUT OF THIS AGREEMENT, EVEN IF ADVISED OF THEIR POSSIBILITY.

### 17.2 Cap

TO THE FULLEST EXTENT PERMITTED BY LAW, EACH PARTY'S TOTAL AGGREGATE LIABILITY ARISING OUT OF THIS AGREEMENT WILL NOT EXCEED THE GREATER OF (A) THE FEES PAID AND PAYABLE BY CUSTOMER TO VIADERE FOR THE SERVICES GIVING RISE TO THE CLAIM IN THE [12] MONTHS BEFORE THE FIRST EVENT GIVING RISE TO LIABILITY, AND (B) [US$ AMOUNT] (THE "**GENERAL CAP**").

### 17.3 Enhanced cap

VIADERE'S TOTAL AGGREGATE LIABILITY FOR A BREACH OF ITS DATA-PROTECTION OBLIGATIONS IN THE DPA OR OF ITS SECURITY OBLIGATIONS IN SECTION 9 THAT RESULTS IN A SECURITY INCIDENT, AND FOR ITS CONFIDENTIALITY OBLIGATIONS, WILL NOT EXCEED [TWO] TIMES THE GENERAL CAP (THE "**ENHANCED CAP**"), WHICH IS IN PLACE OF AND NOT IN ADDITION TO THE GENERAL CAP. [COUNSEL: confirm the multiple and whether a super-cap applies at all.]

### 17.4 Exceptions

THE LIMITATIONS IN THIS SECTION DO NOT APPLY TO: (A) A PARTY'S LIABILITY FOR FRAUD, GROSS NEGLIGENCE OR WILLFUL MISCONDUCT; (B) A PARTY'S LIABILITY FOR DEATH OR PERSONAL INJURY CAUSED BY ITS NEGLIGENCE; (C) CUSTOMER'S PAYMENT OBLIGATIONS; (D) A PARTY'S INDEMNIFICATION OBLIGATIONS FOR THIRD-PARTY CLAIMS UNDER SECTION 16 [COUNSEL: confirm whether Customer's indemnity for consent and communications-law claims is uncapped and Viadere's IP indemnity is capped or uncapped]; (E) CUSTOMER'S MISUSE OR INFRINGEMENT OF VIADERE'S INTELLECTUAL PROPERTY; (F) CUSTOMER'S LIABILITY FOR FINES AND PENALTIES IMPOSED BY A CARRIER OR REGULATOR BECAUSE OF ITS CONTENT OR CONDUCT; OR (G) LIABILITY THAT CANNOT BE LIMITED BY LAW.

### 17.5 Basis of the bargain

The parties agree that these allocations of risk reflect the Fees and are a fundamental part of the bargain. Amounts paid under an indemnity do not reduce the cap, unless the Order Form says so. The limits apply in aggregate to all claims under this Agreement.

## 18. Term, renewal, termination and suspension

### 18.1 Term

This Agreement starts on the Effective Date and continues until all Order Forms have expired or are terminated (the "**Term**"). Each Order Form states its initial term. Unless the Order Form says otherwise, it renews for successive periods equal to the initial term (or one year, if shorter) unless either party gives notice of non-renewal at least [30] days before the end of the then-current term. Customers on the free tier or on monthly plans may stop at any time by closing the Account.

### 18.2 Termination for cause

Either party may terminate this Agreement or an Order Form by notice if the other: (a) materially breaches it and does not cure the breach within [30] days of notice (or [10] days for non-payment); or (b) becomes insolvent, makes an assignment for the benefit of creditors, has a receiver appointed or is subject to bankruptcy proceedings that are not dismissed within [60] days.

### 18.3 Termination by Viadere

Viadere may terminate immediately by notice if: (a) Customer's use of the Services creates a material risk to Consumers, Viadere or other customers that is not resolved after a suspension; (b) Customer repeatedly or seriously breaches the Acceptable Use Policy or the Messaging Policy; (c) Customer provides materially false verification information; (d) a carrier, provider, Apple or a regulator requires Viadere to stop providing a Service to Customer; (e) Customer is or becomes a Healthcare Provider, or Customer or its Business Content involves Health Information, in breach of section 5.10; or (f) continuing the Services would violate law.

### 18.4 Termination for a material change

If Viadere makes a material change under section 2.3 that adversely affects Customer and Customer does not accept it, Customer may terminate the affected Service on notice given within the notice period and will receive a pro-rata refund of prepaid Fees for the remainder of the Term.

### 18.5 Termination for convenience

[COUNSEL AND PRODUCT: whether either party may terminate for convenience on [60] days' notice. Recommended default: Viadere may discontinue a Service on [90] days' notice, refunding prepaid Fees for the unused period.]

### 18.6 Effect of termination

On termination or expiry: (a) Customer's rights to use the Services end and Customer will stop using them and, within [30] days, remove Viadere keys from its systems; (b) Viadere will revoke Customer's keys, delete webhooks and delivery bodies, remove Customer's Dashboard users and end the Account, as the DPA describes, and will retain handles and codes as reserved so that they are never reassigned; (c) Customer will pay all Fees owed through the effective date, and, for a termination by Viadere under section 18.3 or by Customer's breach, the Fees for the remainder of any committed term; (d) for a termination by Customer for Viadere's uncured breach, Viadere will refund prepaid Fees for the period after termination; and (e) each party will return or delete Confidential Information under section 12.4.

### 18.7 Data export on termination

For [30] days after termination or expiry (the "**Export Period**"), Customer may request, through the Dashboard, an export of its Account profile, team, credential metadata, webhooks, domains, agreements, settings, audit events and usage totals. The export never contains a secret or customer-level data. It is sealed at rest and available for [24 hours] after it is ready. At the end of the Export Period, Viadere will delete or de-identify the Account's data as the DPA describes, subject to retention for legal duties, security and disputes. Consumers' own data is not Customer's to request through Viadere. Customer's data held by Customer is Customer's responsibility.

### 18.8 Survival

Sections that by their nature should survive will survive, including 5.2 to 5.4 (as to past conduct), 7 (as to unpaid amounts), 10, 12, 13, 15.4, 16, 17, 18.6 to 18.8, 19 to 25 and Exhibit C (as to unpaid amounts).

## 19. Audit and records

### 19.1 Customer records

Customer will keep complete and accurate records of consents, opt-outs, the content of its messages and its use of the Services for at least [five] years or the period the law requires, and will give Viadere, on reasonable request, evidence of consent and of compliance with this Agreement within [10] business days, or sooner where a carrier, provider or regulator requires it.

### 19.2 Viadere's audit of Customer

Viadere (or an independent auditor bound by confidentiality) may audit Customer's compliance with sections 5, 10 and 11, on [10] business days' notice, no more than [once a year] except after a Security Incident, a regulatory inquiry or a material complaint, during normal business hours and in a way that does not unreasonably interrupt Customer's business.

### 19.3 Customer's audit of Viadere

Customer's audit rights relating to Personal Data are in the DPA. Viadere will, on reasonable written request and not more than once a year, respond to a reasonable security questionnaire and give a summary of its most recent independent security assessment where one exists. [COUNSEL AND SECURITY: audit and assurance reports. No external attestation is claimed today.]

## 20. Insurance

During the Term and for [one year] after it, each party will maintain, with insurers of good standing, insurance of the types and with at least the limits below, and will give a certificate on request: commercial general liability of [US$1,000,000] per occurrence; technology errors and omissions (professional liability) of [US$ amount]; and cyber and network-security and privacy liability of [US$ amount]. If Customer sends marketing messages or handles regulated data, Customer will maintain cover appropriate to that activity [COUNSEL: telephone-consumer-protection coverage]. Insurance does not limit a party's liability.

## 21. Publicity

Neither party will issue a press release about the other or use the other's name or logo in a way that implies endorsement without the other's prior written consent, except that Customer may state, as provided in section 4.6, that it is a verified business on Viadere, and Viadere may list Customer's name and logo as a customer in the directory and in customer lists [subject to Customer's opt-out by notice]. No named brand is represented as a Viadere customer unless it has agreed in writing.

## 22. Force majeure

Neither party is liable for a delay or failure to perform (other than payment) caused by events beyond its reasonable control, including natural disaster, epidemic, war, terrorism, labor disputes (other than of its own personnel), government action, utility, power or internet failure, failure or changes of carriers, providers, Apple or other third parties, or denial-of-service attacks. The affected party will promptly notify the other and use reasonable efforts to resume performance. If the event lasts more than [30] days, either party may terminate the affected Service on notice.

## 23. Marks and brand use

Viadere grants Customer a limited, non-exclusive, non-transferable, revocable licence during the Term to display the "Connect with Viadere" button and Viadere's name and marks as set out in the brand guidelines, solely to refer to the Services. Customer will not alter them, combine them with another mark, or use them in a manner likely to cause confusion, to suggest endorsement or to imply that Viadere is the source of Customer's products. Customer grants Viadere a licence to display Customer's name and marks in the directory, in the app and in the Services.

## 24. Governing law and disputes

### 24.1 Governing law

This Agreement and any dispute arising out of or relating to it are governed by the laws of [the State of Delaware / New York], without regard to conflict-of-laws rules, and, for Customer's outside the United States, [the laws chosen in the Order Form]. The UN Convention on Contracts for the International Sale of Goods does not apply.

### 24.2 Escalation

A party will first give written notice of a dispute, and the parties' executives will meet or confer within [15] days to try to resolve it in good faith. Either party may seek urgent injunctive relief at any time.

### 24.3 Forum

If not resolved within [30] days, the dispute will be decided exclusively [by the state and federal courts located in [COUNTY, STATE], and each party submits to their jurisdiction and waives objections to venue] [ALTERNATIVE: by binding arbitration administered by [AAA / JAMS / ICC] under its commercial rules, before [one/three] arbitrators, seated in [CITY], in English]. [COUNSEL: choose courts or arbitration.]

### 24.4 Jury waiver

TO THE EXTENT PERMITTED BY LAW, EACH PARTY WAIVES ITS RIGHT TO A JURY TRIAL IN ANY PROCEEDING ARISING OUT OF THIS AGREEMENT.

### 24.5 Costs

The prevailing party in a proceeding to enforce this Agreement may recover its reasonable costs and legal fees, as the court or arbitrator decides. [COUNSEL: confirm.]

## 25. General

### 25.1 Notices

Notices must be in writing and are effective when delivered by hand, one business day after being sent by a recognized courier, or, for email, when sent to the address in the Order Form with confirmation of transmission (but notices of breach, termination or an indemnity claim must also be sent by courier). Viadere may give operational notices in the Dashboard, by email to the Customer's owners and security contacts and on the [status page](/status/). Legal notices to Viadere: [LEGAL-NOTICES-CONTACT-PLACEHOLDER], with a copy to [COUNSEL: postal address].

### 25.2 Assignment

Neither party may assign this Agreement without the other's written consent, not to be unreasonably withheld, except that either party may assign it in its entirety to an Affiliate or to a successor in a merger, acquisition or sale of all or substantially all of its relevant assets, on notice. A change of control of Customer to a competitor of Viadere allows Viadere to terminate on notice [COUNSEL]. An assignment in breach of this section is void.

### 25.3 Subcontractors

Viadere may use Affiliates and subcontractors to perform the Services and remains responsible for their performance as this Agreement states. Subprocessors of Personal Data are covered by the DPA.

### 25.4 Relationship

The parties are independent contractors. There is no partnership, joint venture, agency or employment relationship, and neither has authority to bind the other.

### 25.5 No third-party beneficiaries

This Agreement does not give rights to anyone who is not a party, except that the Customer Indemnitees and the Viadere Indemnitees may enforce section 16.

### 25.6 Waiver, severability and construction

A failure or delay in exercising a right is not a waiver. If a provision is held invalid or unenforceable, it will be enforced to the extent allowed and the rest will continue. Headings are for convenience, "including" means "including without limitation", and the Agreement will not be construed against its drafter.

### 25.7 Entire agreement and amendments

This Agreement is the entire agreement about its subject and replaces all earlier understandings. It may be amended only in writing signed by both parties, or as sections 2.3 and 6.5 allow for published documents.

### 25.8 Counterparts and electronic acceptance

Acceptance in the Dashboard, an electronic signature and signature in counterparts are as valid as handwritten signatures. Viadere's record of acceptance, which holds the document, version, time, the accepting user and hashed network and agent details, is evidence of acceptance.

### 25.9 Export, government use and anti-assignment of rights

The Services may not be exported, re-exported or used in breach of export and sanctions laws. If Customer is a US government entity, the Services are commercial items with the rights stated in this Agreement.

### 25.10 Equitable relief

Each party may seek injunctive or other equitable relief for a breach of sections 12 or 13 in any court of competent jurisdiction, without posting a bond where the law allows.

## Exhibit A. Order Form

[This Order Form is entered into under the Business Services Agreement between [COUNSEL: LEGAL ENTITY NAME] and the Customer named below.]

| Field | Value |
|---|---|
| Customer legal name | [CUSTOMER LEGAL NAME] |
| Jurisdiction and registration number | [JURISDICTION AND NUMBER] |
| Address and billing contact | [ADDRESS AND EMAIL] |
| Security contact | [NAME AND EMAIL] |
| Business handle and code | [HANDLE] and [CODE] (issued on approval) |
| Order Form effective date | [DATE] |
| Initial term | [12 months] |
| Renewal | [Automatic for successive 12-month terms unless notice 30 days before the end] |
| Services ordered | [Messaging / Approve / Verify (when available) / Authenticator (when available)] |
| Tier | [M / A / V / E] |
| Plan, committed volume and quotas | [PLAN AND VOLUMES] |
| Fees | [See Exhibit C, with any negotiated amounts] |
| Billing frequency and payment method | [Monthly in arrears / invoice / card] |
| Governing law and forum (if other than section 24) | [VALUE] |
| Special terms | [VALUE, noting the section of the Agreement overridden] |
| Signature | [AUTHORIZED SIGNATORY, TITLE, DATE] for Customer and for Viadere |

## Exhibit B. Support and service levels

### B.1 Support

Viadere provides support through [SUPPORT-CONTACT-PLACEHOLDER] during [business hours in the US Eastern time zone, Monday to Friday, excluding holidays]. Security incidents affecting Customer are handled under the Incident Notification Policy at any time. [PRODUCT: on-call and 24x7 coverage for higher tiers.]

### B.2 Severity and response targets

| Severity | Definition | Initial response target |
|---|---|---|
| 1, Critical | The production Services are unavailable or a Security Incident is under way | [1 hour] |
| 2, High | A major function is materially impaired and there is no workaround | [4 business hours] |
| 3, Normal | A minor function is impaired or a question that does not stop operation | [1 business day] |
| 4, Low | A request for information or an enhancement | [3 business days] |

Targets are for the first human response. They are targets, not resolution times, and are not credits-bearing unless the Order Form says so.

### B.3 Availability

[PRODUCT: no availability commitment is published. The following is a placeholder for a commitment to be set by the business and engineering teams once Viadere has operating history.] Viadere will use commercially reasonable efforts to make the generally available production Business API available at least [99.9%] of the time in a calendar month, excluding: scheduled maintenance announced at least [48 hours] ahead; emergency maintenance; beta features and the sandbox; outages or degradation of carriers, providers, Apple or the internet; suspension as this Agreement allows; Customer's systems; and force majeure. Where a security-critical limiter cannot reach its database, Viadere will fail closed for the affected functions, which can reduce availability by design.

### B.4 Service credits

If Viadere does not meet the availability commitment in a month, Customer may claim a credit against the next invoice of [5%] of the monthly platform Fee if availability is below [99.9%] but at least [99.0%], and [10%] if below [99.0%], by notice within [30] days after the month ends. Credits are Customer's sole and exclusive remedy for a failure to meet the availability commitment, and may not be redeemed for cash. [PRODUCT AND COUNSEL: confirm.]

### B.5 Status and maintenance

Viadere publishes service status and incident notices at the [status page](/status/) and announces maintenance in advance where practicable.

### B.6 Exclusions

Support does not cover Customer's own systems, third-party tools, the work of integrating, or advice on legal or regulatory requirements.

## Exhibit C. Fees

### C.1 Fee schedule

| Category | What it covers | Amount |
|---|---|---|
| Platform fee | Metered interactions through the Business API | [PRICE TBD] |
| Per-message fee | Messages sent through Viadere, per message | [PRICE TBD] |
| Verification fee | Each Verify check, when Verify is available | [PRICE TBD] |
| Carrier fee | Carrier charges passed through for SMS and RCS delivery, which vary by carrier, content and direction | Passed through at cost [plus [x]%] |
| Provider fee | Messaging and verification provider charges passed through | Passed through at cost [plus [x]%] |
| Overage fee | Use beyond the daily live-interaction quota or plan limits | [PRICE TBD] |

### C.2 Free tier

The default free tier has a daily limit on live interactions, currently 1,000. Sandbox traffic with a test key is not counted or billed.

### C.3 What money does not buy

Paying never changes the priority of a message and never bypasses a Consumer's consent. A plan raises quotas only. See the [pricing page](/businesses/pricing/).

### C.4 Taxes and currency

Section 7.5 applies. Fees are in [US dollars].
