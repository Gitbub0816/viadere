---
title: Verification Services Addendum
order: 8
description: "Evidence sources, assurance limits, permitted purposes, data handling and responsibilities for Verify. Verify is planned."
version: 0.2.0
effective_date: ""
owner: "General Counsel [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete addendum covering capabilities, evidence sources, customer consent, result handling and retention, assurance labels and limits, permitted and prohibited uses, jurisdiction rules, regulatory reliance, accuracy and appeals, fees, liability and suspension."
disclosures: [identity_verification, age_verification]
---
::: callout
Verify is [planned](/products/verify/) and not available. This draft exists so that the terms are reviewed before launch. Statements about how Verify works describe the design, not a service in operation.
:::

::: draft-notice
**Draft for counsel review.** This addendum is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This Verification Services Addendum (the "**Verification Addendum**") is part of the [Business Services Agreement](/legal/business-services-agreement/) between [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") and the business that accepted it ("**Customer**"). It applies only if Customer has been approved for Tier V and has accepted this addendum. Terms defined in the Agreement have the same meaning here.

## 1. Definitions

- "**Attribute**" means a single fact about a Consumer that Customer asks Viadere to confirm, such as that the Consumer is at least a given age.
- "**Capability**" means a Verify function: `age.minimum` (a minimum-age threshold), `identity.name`, `identity.address` and `identity.verified`.
- "**Consumer**" means the individual who is asked to verify.
- "**Consent Receipt**" means the record of a Consumer's consent to one disclosure.
- "**Evidence**" means the information used to verify an Attribute, such as an issuer-signed credential in Apple Wallet or an identity document, a selfie and a liveness check.
- "**Evidence Provider**" means a third party that captures or checks Evidence for Viadere, currently Didit, or that issues a credential, such as a government agency that issues an ID presented from Apple Wallet.
- "**Verification Result**" means the output of a verification for a Capability, including its outcome and provenance.
- "**Verified Label**" means one of the labels that describe what was verified: verified identity, verified age threshold, registered authenticator, reachable contact, and estimated age, which is never described as verified.

## 2. The service

### 2.1 What Verify does

At Customer's request, and with the Consumer's consent, Viadere confirms one Attribute about the Consumer and returns a Verification Result to Customer. The default is a threshold answer (for example "meets the threshold of 18"), not the Consumer's date of birth. Customer receives only what the Capability's definition allows.

### 2.2 Status

Verify is planned. Viadere may decide not to launch it, may launch it in some places only, and may change it. Viadere will not offer Verify until it has completed its release gate, including a legal assessment for each market and a privacy impact assessment. [COUNSEL AND PRIVACY: assessment status for government-ID processing, biometric verification and age assurance.]

### 2.3 Disclosures

::: disclosure
Viadere may verify selected identity attributes using supported credentials or verification providers. A verification result describes the attribute and assurance evaluated; it is not a universal guarantee of identity or eligibility.
:::

::: disclosure
Where supported, Viadere can confirm that a person meets a specified age threshold without disclosing their date of birth. Availability and legal sufficiency vary by jurisdiction and service.
:::

## 3. Capabilities and requests

### 3.1 Capabilities

| Capability | What it returns | Default tier |
|---|---|---|
| `age.minimum` | Whether the Consumer meets a threshold of 13, 16, 18, 21 or 25 years, with assurance, issue time, expiry and the audience (Customer). Only a true result is ever returned as "meets threshold". It does not return the age or date of birth | Tier V |
| `identity.verified` | Whether the identity was verified, with provenance. No name or address | Tier V, heightened review |
| `identity.name` | The Consumer's verified name, only with the Consumer's consent to that exact request and Customer's entitlement | Tier V, heightened review |
| `identity.address` | The Consumer's verified address, subject to the same conditions | Tier V, heightened review |

### 3.2 How Customer requests a verification

Customer makes a request through the Business API with the Consumer's pairwise reference, the Capability, any parameter (for an age check, the threshold), a purpose code, a callback reference to one of Customer's registered webhook endpoints, and an expiry between 30 and 600 seconds (default 300). A request is idempotent on its idempotency key. Viadere first checks Customer's key scope, entitlement, tier, any kill switch, the typed parameters, the purpose and the jurisdiction rules, and only then identifies the Consumer. An unknown Consumer, or one at another business, is a plain "not found". At most three requests can be open for one Consumer.

### 3.3 Purpose

Customer must state an accurate purpose for each request and may use the result only for that purpose. A request that does not state the real purpose, or a purpose not in the list Viadere has approved for Customer, will be rejected.

### 3.4 Entitlement and heightened review

Access to `identity.name`, `identity.address` and `identity.verified` requires a documented heightened review by Viadere with a justification and a recorded reference. Entitlements are a ceiling: Customer's key scope, the Consumer's consent, the sufficiency of the evidence and law and policy must all allow a disclosure, and revoking a tier or Capability takes effect at once.

## 4. Evidence sources and methods

### 4.1 Apple Wallet

Where the Consumer has an eligible ID in Apple Wallet and their device supports it, the Consumer may present it. Viadere verifies, in memory: the encrypted presentation; the issuer's signature and certificate chain to a configured trust anchor; that the credential is valid at that time; that the presentation is bound to the Consumer's device and to the request; and the requested elements. It reduces the presentation to the requested element and does not store or log the presentation. Customer acknowledges that: (a) availability depends on the Consumer's device, jurisdiction and issuer; (b) Apple's terms and entitlements for identity presentment apply and may change; (c) Wallet credential revocation status is not currently checked, so a credential revoked by its issuer but still within its validity period may verify, and the provenance records that revocation was not checked; and (d) regulated uses must not rely on a Wallet result as proof that a credential has not been revoked.

### 4.2 Identity document and liveness check

Where a Consumer has no eligible Wallet ID, the Consumer may choose a check by Viadere's Evidence Provider. The Consumer's device captures an identity document, a selfie and liveness video and sends them directly to the Evidence Provider. The Evidence Provider checks the document, confirms a live person and compares the face with the document photo. Viadere receives a decision, not the images or biometric data. A selfie-based age estimate alone is recorded only as an estimate and is never a verified age.

### 4.3 Method ceilings

Each method can establish only the labels it is able to establish. A Wallet presentation of an age threshold is age evidence, not identity evidence. A document and liveness check can establish a verified age threshold and a verified identity. A device key establishes only a registered authenticator. A contact code establishes only a reachable contact. Viadere does not promote a weaker result to a stronger label, and Customer must not present one as stronger.

### 4.4 Alternatives

Because not every person has a compatible Wallet ID, biometric capability or standard document, Viadere aims to offer an accessible alternative path where one is feasible. Customer must offer a fallback of its own for a Consumer who cannot or will not use Verify, and must not treat a decline as proof of anything.

### 4.5 Evidence Providers

Evidence Providers are subprocessors of Viadere under the [Data Processing Addendum](/legal/data-processing-addendum/) and are listed on the [Subprocessors](/legal/subprocessors/) page. Viadere may change Evidence Providers or methods with notice. [COUNSEL: Customer's rights if a method is withdrawn.]

## 5. Consumer consent

### 5.1 What the Consumer sees

The Viadere app shows the Consumer the verified identity of Customer, the purpose, exactly what would be disclosed and what would not, the recipient and the expiry. The Consumer must consent before any disclosure. The consent is bound to what was displayed. Viadere computes a digest of the displayed content in the app and the server verifies that the Consumer consented to that same content, so what was shown is what was agreed. The Consumer may withdraw consent until the disclosure happens.

### 5.2 Customer's obligations

Customer must not change, hide or contradict the consent display; must provide accurate business information; must not pressure or deceive a Consumer into verifying; and must not make verification a condition of something unrelated to the stated purpose. Customer must comply with the notice and consent rules that apply to its own collection and use of the result.

### 5.3 Consent Receipt

Viadere keeps a Consent Receipt for each consent: the business, pairwise reference, Capability, purpose, field names, request identifier and times. It contains no Attribute values. A Consent Receipt is single-use and expires with the request, at most 600 seconds.

## 6. Results, retrieval and retention

### 6.1 Retrieval

Customer is notified of completion by webhook (for every end, including an expiry) with a result reference, and retrieves the Verification Result through the Business API with its credential. The result may be retrieved once. After that, or after 15 minutes if it is not retrieved, the payload is erased. A second attempt returns an error.

### 6.2 Neutral outcomes

To avoid revealing why a verification did not succeed, Viadere returns the same neutral outcome for every end of the same polarity: a decline, an expiry or an inability to verify are indistinguishable to Customer. A negative result is returned as "not verified" with an empty result. Customer must not try to infer a reason, and must not treat "not verified" as evidence of a particular fact about the Consumer, such as being under the threshold.

### 6.3 End-to-end sealing of identity fields

For `identity.name` and `identity.address`, if Customer has published a valid encryption key in the authenticated key directory, Viadere seals the personal-data fields to that key so that Viadere stores only ciphertext. Viadere may refuse requests for such Capabilities from a business without a key. [PRODUCT: whether sealing is required for these Capabilities.]

### 6.4 What Viadere retains

Viadere keeps the request record, the method, the verifier, the policy version, the Consent Receipt and an opaque provider session identifier, with no names, birthdates, document numbers, images, face data or scores, for 400 days [COUNSEL: confirm period], after which they are deleted. Viadere deletes the Evidence Provider's session and user record after each document check and retries until it succeeds. The platform audit trail records the result and the method for security purposes, but the business-facing audit trail records only that a request was made, that it completed with an outcome and that the result was retrieved.

### 6.5 What Customer may retain

Customer may keep the Verification Result only as long as its stated purpose and the law require, and not longer than [the period set in the order, or 30 days, if none]. Customer must not keep any Attribute beyond what it asked for, must not create a profile from results, and must delete a result on request of the Consumer where the law gives them that right. Customer must not re-disclose a result except as the law requires or as the Consumer has directed. Names and addresses obtained through Wallet are declared to Apple as data that Customer may store and are therefore Customer's responsibility as Controller. Age thresholds and the "identity verified" result are declared as not stored and only a Boolean should be kept. [COUNSEL: Apple's terms on relaying identity data to third parties.]

### 6.6 Result validity

Each result carries a validity period and is addressed to Customer as its audience. A result is not reusable across businesses and Customer must not present it as valid for another business or after expiry.

## 7. Assurance and limits

### 7.1 What a result means

A Verification Result describes the Attribute and the assurance that Viadere evaluated: the evidence type, the authenticator, the issuer's trust, freshness, presentation binding and transaction risk. Viadere records these dimensions separately and uses the Verified Labels to distinguish them. It does not use a single universal badge. A result is not a guarantee of identity, age, eligibility or intent.

### 7.2 No framework claims

Viadere does not claim that Verify meets any particular assurance level under NIST SP 800-63 or another framework, and does not claim any independent assessment of Verify. [COUNSEL AND SECURITY: update if an assessment is obtained.]

### 7.3 Conservative age date

To avoid reporting a person as being of age before the day they turn the threshold anywhere in the world, Viadere computes an age threshold using the earliest calendar date anywhere. This can delay a positive result by up to 12 hours for a person in an early time zone. Customer must take this into account in regulated uses. [COUNSEL: confirm for each regulated use.]

### 7.4 Accuracy and errors

Verification can fail or be wrong: documents can be damaged, poor lighting and accessibility can affect capture, and checks can produce false rejections or false acceptances. Viadere does not warrant that a result is accurate or complete. Customer must give a Consumer who is wrongly rejected a way to resolve it, and must not rely on Verify as the only control for a high-risk decision.

### 7.5 Jurisdiction rules

Viadere evaluates the legal-entity jurisdiction of Customer, and the country of the document issuer, when a request is created, read, retrieved and disclosed, against rules that Viadere sets. A rule can block a Capability, and rules for high-sensitivity Capabilities fail closed if a jurisdiction is unknown. Customer acknowledges that Verify may be unavailable for a Consumer or a use because of those rules.

## 8. Permitted purposes and prohibited uses

### 8.1 Permitted purposes

Customer may use Verify to confirm, with the Consumer's consent, that: a Consumer meets a minimum age for a product or service that has an age requirement; a Consumer is the person who they claim to be for a lawful purpose Viadere has approved; or the name or address given to Customer matches a verified record, where the Capability is approved. [COUNSEL AND PRODUCT: list approved purpose codes.]

### 8.2 Prohibited

Customer will not use Verify to: discriminate unlawfully; make decisions about employment, credit, insurance, housing or education eligibility unless Viadere has approved it in writing and the law permits it; screen for or infer sensitive characteristics; surveil a person; verify a person who has not consented or is not the person present; build a database of verified identities for resale; resell or sublicense Verify results; try to link people across businesses; bypass the consent display; or conduct a request for a purpose it has not stated. Customer will not use Verify for adult services, gambling or other restricted uses unless approved under the [Acceptable Use Policy](/legal/acceptable-use-policy/).

### 8.3 Children

Customer will not use Verify to collect information about a child, and will not use it for any purpose that targets children, other than to deny access to an age-restricted service. [COUNSEL: COPPA, state child-privacy laws and age-appropriate design requirements.]

## 9. No universal regulatory sufficiency

A Verify result does not automatically satisfy any regulatory duty of Customer, including customer identification, know-your-customer, anti-money-laundering, sanctions screening, age-assurance, strong-customer-authentication or other duties. Customer defines and is responsible for its own reliance. For financial institutions, Viadere's verification does not automatically fulfil KYC or bank-regulatory requirements. Viadere does not promise compliance with any age-verification law for adult content, alcohol, gambling or other restricted services on the strength of a Boolean answer. Customer will make its own legal assessment.

## 10. Data protection

### 10.1 Roles

For a verification, Viadere acts as Controller for the verification attempt, the Consent Receipt and the security record, and Customer is a separate Controller for the Verification Result it receives. The Evidence Provider is Viadere's processor. [COUNSEL: confirm, and consider whether there is joint control.] The [Privacy Notice](/legal/privacy-notice/) describes Viadere's handling, including the biometric notice.

### 10.2 Customer's obligations

Customer will provide any notice and obtain any consent needed for its own processing of the Verification Result, will protect it with appropriate security, and will promptly tell Viadere of any Security Incident involving a Verification Result.

### 10.3 Biometric data

Viadere does not receive or store biometric data. The Evidence Provider processes it on Viadere's behalf for the duration of a check. Customer must not request or store biometric identifiers or templates from Consumers through Verify. [COUNSEL: BIPA and other biometric laws, which apply to Viadere and the Evidence Provider and may apply to Customer.]

## 11. Fees

Verification fees are set out in the Order Form and Exhibit C of the Agreement, and include provider fees that are passed through. Fees apply to each attempted verification, whether or not it succeeds [COUNSEL AND PRODUCT: confirm whether a failed or abandoned attempt is charged]. Pricing is not final.

## 12. Suspension and changes

Viadere may suspend Verify, a Capability or Customer's access at once to protect Consumers or the service, in response to a legal, provider or Apple requirement, an incident, a failed assurance review, a violation of this addendum or a change in law. Verify depends on third parties; if Apple, an issuer or the Evidence Provider changes or withdraws a method, Verify may change or stop. A kill switch can stop new document verifications while the deletion of finished provider sessions continues.

## 13. Warranties and liability

### 13.1 No warranty of outcomes

SUBJECT TO THE AGREEMENT, VERIFY IS PROVIDED "AS IS". VIADERE DOES NOT WARRANT THAT ANY VERIFICATION WILL BE AVAILABLE, ACCURATE, COMPLETE OR SUFFICIENT FOR CUSTOMER'S LEGAL PURPOSES.

### 13.2 Liability allocation

[COUNSEL: allocation of liability for verification errors, including whether Verify results have a separate cap, and the allocation between Viadere and Customer for claims arising from a Consumer's data, a false positive or a false negative. Default position: the limits in section 17 of the Agreement apply, Customer bears the consequences of its own decisions.] Customer is responsible for decisions it takes on the basis of a result.

### 13.3 Indemnity

Customer's indemnity in section 16.2 of the Agreement applies to claims arising from Customer's use of a Verification Result, its failure to give notice or obtain consent, and its breach of this addendum.

## 14. Term

This addendum applies while Customer uses Verify and as long as Customer retains Verification Results.
