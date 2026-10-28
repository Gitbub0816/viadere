---
title: Incident Notification Policy
order: 12
description: "How and when Viadere tells businesses, consumers and regulators about a security incident or personal data breach."
version: 0.2.0
effective_date: ""
owner: "Security lead [NAME PLACEHOLDER]"
counsel_review: pending
change_summary: "Second draft: complete policy with definitions, severity, notification clocks by recipient, content of notices, channels, containment measures, customer obligations, post-incident review and records."
---
::: draft-notice
**Draft for counsel review.** This policy is not in force. Values in square brackets are choices or facts still to be filled in or confirmed.
:::

This policy describes how [COUNSEL: LEGAL ENTITY NAME] ("**Viadere**") detects, handles and tells people about security incidents that affect the Viadere service, businesses that use it and the people who connect to them. It supports the [Data Processing Addendum](/legal/data-processing-addendum/), the [Business Services Agreement](/legal/business-services-agreement/) and the [Privacy Notice](/legal/privacy-notice/). It states commitments Viadere intends to keep. It does not create a right for any person beyond those contracts and the law.

## 1. Definitions

- "**Security Incident**" means a breach of security that leads to the accidental or unlawful destruction, loss, alteration, unauthorized disclosure of, or access to, data or systems that Viadere or its subprocessors control, and any event that compromises the integrity of the approval, verification or messaging trust path. Unsuccessful attempts that do not compromise security, such as blocked log-ins, port scans and denied traffic, are not Security Incidents.
- "**Personal Data Breach**" means a Security Incident that affects personal data.
- "**Trust-path incident**" means an incident that affects the keys, signatures, key directory, audit log or the isolation between businesses, whether or not personal data was exposed.
- "**Affected Business**" means a business whose data, keys or Consumers are affected. "**Affected Consumer**" means a person whose personal data is affected.

## 2. Severity

Viadere classifies each incident when it is detected and reviews the class as facts come in.

| Class | Meaning | Examples |
|---|---|---|
| SEV1 | Active compromise of keys, identity evidence or tenant isolation, or a full outage of sign-in approval | A forged approval, compromise of the application servers or a signing key, cross-tenant data exposure |
| SEV2 | A contained compromise of one business or one capability, or a capability is down | A leaked business API key used for fraud, a business impersonation, a webhook takeover |
| SEV3 | A degraded service or a suspected incident | An unusual pattern still under investigation |

SEV1 and SEV2 incidents page the incident commander and the security lead immediately.

## 3. What we do first

1. Open a time-stamped incident record, and move to a contact path that does not depend on Viadere's own systems, including a separate channel and a status page hosted away from Viadere's application stack.
2. Preserve evidence before changing state: redacted server logs, edge logs, key-management audit logs and the audit-log head.
3. Check the integrity of the audit chain against the last exported head.
4. Contain with the narrowest control that works, then eradicate, recover, notify and review.
5. Record the time at which personal data exposure first became plausible, which starts the notification clocks in section 4.

## 4. Who is told, and when

[COUNSEL: confirm each period against the laws that apply in each launch region and the commitments in the contracts.]

### 4.1 Affected Businesses

Viadere will notify an Affected Business without undue delay and, where feasible, within **[72] hours** after becoming aware of a Security Incident that affects its data, keys, Consumers or integration. The notice goes to the business's security contact and owners, through the Dashboard and by email. For a trust-path incident that requires action by the business, such as a key rotation, Viadere will notify the business as soon as the need is confirmed, and will not wait for the end of the investigation. Viadere will provide updates at least [every 24 hours] during a SEV1 incident and [every 72 hours] during a SEV2 incident until it is contained.

### 4.2 Affected Consumers

Where a Personal Data Breach is likely to create a risk to Consumers, or the law requires it, Viadere will notify the Affected Consumers without undue delay. Because Consumer accounts have no email address, Viadere will use an in-app security notice, a push notification and, if appropriate, a text from the Viadere number, as well as the [status page](/status/). Where a Business has the direct relationship, Viadere and the Business will agree who notifies. [COUNSEL: statutory content and timing for state breach laws.] A notice never asks for a password, a code or an approval.

### 4.3 Regulators

Where Viadere is a controller and the GDPR or UK GDPR applies, Viadere will notify the competent supervisory authority without undue delay and, where feasible, within **72 hours** after becoming aware of a Personal Data Breach that is likely to result in a risk to people, unless it is unlikely to result in a risk. Where US state laws apply, Viadere will notify the attorneys general, regulators and consumer-reporting agencies, and the affected people, as those laws require. [COUNSEL: Canadian federal and provincial breach rules, and sector rules.] Where Viadere is a processor, it will tell the controller, who decides about notifying regulators and Consumers, and Viadere will help.

### 4.4 Carriers, providers and Apple

Where an incident affects a carrier, messaging provider, Apple or another partner, or the partner's rules require it, Viadere will notify them under the relevant contract.

### 4.5 Law enforcement

Viadere may tell law enforcement of an incident that appears criminal, and will do so under the [Law-Enforcement Request Policy](/legal/law-enforcement-request-policy/) and its other legal duties. Viadere will tell affected parties unless law enforcement lawfully asks it to delay.

### 4.6 Public notice

For an incident that affects many people, a material part of the service or public safety, Viadere will post a notice on the [status page](/status/). Viadere will not publicize a business's identity without need.

### 4.7 Insurers and advisers

Viadere may tell its insurers, lawyers and forensic advisers, under confidentiality.

## 5. What a notice contains

Where known, and in phases where it is not yet known, each notice will state:

1. What happened and when it was detected, and when it began.
2. The type of incident and the systems involved.
3. The categories and approximate number of people and records affected, and which data.
4. The likely consequences.
5. What Viadere has done and is doing to contain and fix it.
6. What the recipient should do, including any key rotation, secret change, device review, or credential change.
7. A contact for questions, and, for Consumers, how to exercise their rights.
8. What Viadere will tell them next, and when.

A notice does not admit fault or liability.

## 6. Channels

| Recipient | Channel |
|---|---|
| Businesses | Email to the security contacts and owners, a Dashboard notice, the status page. For urgent trust-path issues, an operator notice delivered through the Dashboard and a webhook event where the integration subscribes |
| Consumers | In-app security notice, push notification (generic, with no sensitive content), text from the Viadere number where appropriate, the status page |
| Regulators | The channel that each regulator prescribes |
| Public | The status page, hosted separately from Viadere's application stack, and, if needed, a statement on the website |

[OPERATIONS: define and test the contact paths, including a way to reach businesses if Viadere's own email and Dashboard are unavailable.]

## 7. Containment measures

Viadere has controls that can be used during an incident, which include:

- Revoking a business's API key or all of its keys, without suspending the business.
- Suspending a business, which removes it from discovery and routing and cancels its pending requests.
- Pausing webhook delivery for a business.
- Disabling a capability globally or for a business, including approvals, verification, vault sync and new document verifications.
- Throttling a business or lowering its priority ceiling.
- Revoking Consumer devices, sessions or approval keys, and freezing a Consumer's approvals.
- Blocking traffic at the edge, or stopping the application, in preference to allowing an attacker to relay approvals. An outage is preferable to a forged approval.
- Rotating keys, which has a documented procedure and which may require businesses to take action.
- Sending a notice to affected Consumers or businesses.

Viadere will tell Affected Businesses when a measure affects them, and will lift the measure when the cause is resolved.

## 8. What we ask of businesses

A business that uses Viadere will: keep its security contacts current in the Dashboard; tell Viadere promptly, and no later than [24 hours], after it becomes aware of a suspected compromise of a key, secret, endpoint or Dashboard account, or of a forged or disputed approval; revoke the affected credentials; cooperate with the investigation; keep its own records; and notify its own regulators and customers where it is required to. Where a business is responsible for an incident, it must meet the cost that the Business Services Agreement allocates to it.

## 9. After an incident

Within [10] business days after an incident is closed, Viadere will hold a blameless review of the cause, the timeline, the effectiveness of detection and response and the communications. It will add a test that reproduces the exploit path, update the runbooks and the risk register, and share a summary with Affected Businesses on request. For a SEV1 incident Viadere will publish a post-incident summary on the status page [COUNSEL: confirm publication practice].

## 10. Records

Viadere keeps an incident record, including the time of detection, the decision about each notice, the notices sent and the evidence preserved, for [at least five years or as the law requires]. Viadere keeps a register of Personal Data Breaches, including those that were not notified.

## 11. Preparedness

Viadere keeps runbooks for key compromise, business impersonation, webhook takeover, compromise of the relay, vendor outage and credential-issuer revocation, and runs exercises to test them. The runbooks name the controls to use and the contacts to notify.

## 12. Contact

To report an incident that affects Viadere: [SECURITY-CONTACT-PLACEHOLDER]. To report a vulnerability: [Vulnerability Disclosure Policy](/legal/vulnerability-disclosure-policy/). For privacy questions: [PRIVACY-CONTACT-PLACEHOLDER].
