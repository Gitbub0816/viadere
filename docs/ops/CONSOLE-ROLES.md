# Business console roles and permissions (spec section 9.2)

**Status:** v1, 2026-10-28. The matrix below is **generated from the code** (`OrgRoleMatrix` in `Server/Sources/ViadereServerKit/Dashboard/DashboardRoles.swift`);
`WP6RolesTests.testPermissionMatrixDocumentMatchesTheCode` fails when this file and the server disagree. To refresh it after changing a permission run
`WRITE_ROLES_DOC=1 swift test --filter WP6RolesTests/testPermissionMatrixDocumentMatchesTheCode` in `Server/` and commit the result.

## The nine roles

| Role | Stored as | What it is for |
|---|---|---|
| Owner | `owner` | Everything, including billing, contracts, going live and adding owners. At least one owner always exists. |
| Organization Admin | `org_admin` | Team, organization profile, API keys, webhooks, contracts and audit. Cannot add Owners, Organization Admins or Security Admins. |
| Developer | `developer` | API keys and webhooks within the standard messaging scopes, templates and campaign links. Cannot widen a key's scope or manage people. |
| Messaging Operator | `messaging_operator` | Templates, campaigns, consent status and delivery reports. No credentials. |
| Verification Compliance Admin | `verification_admin` | Verification settings, consent templates, compliance records and attestations. No credentials. |
| Security Admin | `security_admin` | Sessions, IP and certificate restrictions, alerts, scope elevation and second-person approvals. Cannot manage people. |
| Analyst | `analyst` | Aggregate analytics and usage. Read-only. |
| Billing Admin | `billing_admin` | Usage, invoices, payment methods and spend alerts. |
| Read-only Auditor | `auditor` | Read-only access to settings, audit log and compliance records. No secrets, no changes. |

## Migration of the five earlier roles

Before WP6 a member held one of `owner`, `admin`, `developer`, `support`, `analyst`. The migration `CreatePlatformWP6Schema.migrateRoles` renames stored
memberships and open invitations: `admin` becomes `org_admin`, `support` becomes `messaging_operator`; `owner`, `developer` and `analyst` keep their names.
It is idempotent. Stale forms and old invitation links that still say `admin` or `support` are accepted by `OrgRole.parse` and mapped the same way.
No member gains a permission through the migration that the old role did not have, except the new read-only views that every role may open (overview,
templates, support).

## Separation of duties

* Nobody grants a role to themselves; only an Owner creates Owners, Organization Admins or Security Admins. An Organization Admin's reach stops below those three.
* Only an Owner or a Security Admin can create a key with a scope or capability beyond the messaging baseline (`elevateKeyScope`). The roles that can
  manage people (Owner, Organization Admin) and the roles that can widen a credential (Owner, Security Admin) overlap only in the Owner, so no
  low-privilege role can issue a credential, widen its scope and grant itself the right to do so.
* **Two-person approval** (optional, Security > Approvals): when on, creating or rotating a key and granting a role wait as a pending change until a
  different member with `approveChanges` decides it (a request that widens scope needs an Owner or Security Admin). The requester alone completes an
  approved key request and sees the secret once; the stored request, not anything posted later, is what gets issued; approval is single use and
  expires after 24 hours.
* **Step-up re-authentication:** creating or rotating a key, granting or changing roles, mTLS, IP allow-lists, retention, deletion and go-live need a
  passkey assertion from the last few minutes, and the privileged-inactivity timeout (default 5 minutes, 60 s to 15 min per organization) means a console
  left open cannot be used for them. Revoking a key is protective and needs no step-up.
* Permissions are checked on every request against the **current** membership: a demotion or removal takes effect on the next request, and the
  server (not the hidden button) is what refuses.
* **Loops (WP-3.2, WP-3.7):** `submitLoops` (Owner, Organization Admin, Developer) edits Loop Studio drafts and submits them for Viadere review;
  `viewLoops` (the same plus Messaging Operator and Read-only Auditor) reads drafts, the automated report, the sandboxed preview and the review status,
  with every editing control removed. No business permission publishes or reviews a Loop: every revision is decided by Viadere operators holding the
  operator permission `loop_reviewer` (two of them for high risk), and only then signed.

## Matrix

<!-- matrix:begin -->
| Permission | Owner | Organization Admin | Security Admin | Developer | Verification Compliance Admin | Messaging Operator | Billing Admin | Analyst | Read-only Auditor |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `viewOverview` | x | x | x | x | x | x | x | x | x |
| `viewTemplates` | x | x | x | x | x | x | x | x | x |
| `viewOrganization` | x | x | x |  | x |  |  |  | x |
| `manageOrganization` | x | x |  |  |  |  |  |  |  |
| `viewTeam` | x | x | x |  |  |  |  |  | x |
| `manageTeam` | x | x |  |  |  |  |  |  |  |
| `viewAPIKeys` | x | x | x | x |  |  |  |  | x |
| `manageAPIKeys` | x | x | x | x |  |  |  |  |  |
| `revokeAPIKeys` | x | x | x | x |  |  |  |  |  |
| `elevateKeyScope` | x |  | x |  |  |  |  |  |  |
| `viewWebhooks` | x | x |  | x |  | x |  |  | x |
| `manageWebhooks` | x | x |  | x |  |  |  |  |  |
| `viewMessaging` | x | x |  | x |  | x |  | x | x |
| `manageCampaigns` | x | x |  | x |  | x |  |  |  |
| `viewConsent` | x | x |  |  | x | x |  | x | x |
| `viewVerify` | x | x | x |  | x |  |  | x | x |
| `manageVerify` | x |  |  |  | x |  |  |  |  |
| `viewApprove` | x | x | x | x |  |  |  |  | x |
| `manageApprove` | x |  | x |  |  |  |  |  |  |
| `viewSecurity` | x | x | x |  |  |  |  |  | x |
| `manageSecurity` | x |  | x |  |  |  |  |  |  |
| `viewAudit` | x | x | x |  |  |  |  |  | x |
| `viewCompliance` | x | x | x |  | x |  |  |  | x |
| `manageCompliance` | x | x |  |  | x |  |  |  |  |
| `acceptContracts` | x | x |  |  |  |  |  |  |  |
| `requestGoLive` | x | x |  |  |  |  |  |  |  |
| `viewBilling` | x | x |  |  |  |  | x | x | x |
| `manageBilling` | x |  |  |  |  |  | x |  |  |
| `viewSupport` | x | x | x | x | x | x | x | x | x |
| `manageSupport` | x | x | x | x | x | x | x |  |  |
| `approveChanges` | x | x | x |  |  |  |  |  |  |
| `manageDataRequests` | x | x |  |  |  |  |  |  |  |
| `viewInbox` | x | x |  |  |  | x |  |  | x |
| `manageInbox` | x | x |  |  |  | x |  |  |  |
| `submitLoops` | x | x |  | x |  |  |  |  |  |
| `viewLoops` | x | x |  | x |  | x |  |  | x |
| `manageBrandKits` | x | x |  |  |  |  |  |  |  |
<!-- matrix:end -->
