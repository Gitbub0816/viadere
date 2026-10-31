import Foundation
import ViadereCore

/// Organization roles (spec §9.2). Least privilege: each role gets exactly the permissions its job needs, and the matrix below is the single
/// source of truth (docs/ops/CONSOLE-ROLES.md is generated from it and a test fails when they differ).
///
/// Migration of the five legacy roles: `admin` -> `orgAdmin`, `support` -> `messagingOperator`; `owner`, `developer` and `analyst` are unchanged.
public enum OrgRole: String, CaseIterable, Sendable, Comparable {
    case owner
    case orgAdmin = "org_admin"
    case developer
    case messagingOperator = "messaging_operator"
    case verificationAdmin = "verification_admin"
    case securityAdmin = "security_admin"
    case analyst
    case billingAdmin = "billing_admin"
    case auditor

    /// Legacy names kept for readability in older call sites and tests.
    static var admin: OrgRole { .orgAdmin }
    static var support: OrgRole { .messagingOperator }

    /// Accepts the current names and the five legacy ones (a stale form or an old invitation link).
    static func parse(_ raw: String) -> OrgRole? {
        if let role = OrgRole(rawValue: raw) { return role }
        switch raw {
        case "admin": return .orgAdmin
        case "support": return .messagingOperator
        default: return nil
        }
    }

    /// Display order and, for `<`, a coarse privilege rank (used only to order lists; permissions come from the matrix, never from rank).
    var rank: Int {
        switch self {
        case .auditor: 0
        case .analyst: 1
        case .billingAdmin: 2
        case .messagingOperator: 3
        case .verificationAdmin: 4
        case .developer: 5
        case .securityAdmin: 6
        case .orgAdmin: 7
        case .owner: 8
        }
    }

    public static func < (lhs: OrgRole, rhs: OrgRole) -> Bool { lhs.rank < rhs.rank }

    var title: String {
        switch self {
        case .owner: "Owner"
        case .orgAdmin: "Organization Admin"
        case .developer: "Developer"
        case .messagingOperator: "Messaging Operator"
        case .verificationAdmin: "Verification Compliance Admin"
        case .securityAdmin: "Security Admin"
        case .analyst: "Analyst"
        case .billingAdmin: "Billing Admin"
        case .auditor: "Read-only Auditor"
        }
    }

    var summary: String {
        switch self {
        case .owner: "Everything, including billing, contracts, going live and adding owners."
        case .orgAdmin: "Team, organization profile, API keys, webhooks, contracts and audit. Cannot add owners, Organization Admins or Security Admins."
        case .developer: "API keys and webhooks within the standard messaging scopes, templates and campaign links. Cannot widen a key's scope or manage people."
        case .messagingOperator: "Templates, campaigns, consent status and delivery reports. No credentials."
        case .verificationAdmin: "Verification settings, consent templates, compliance records and attestations. No credentials."
        case .securityAdmin: "Sessions, IP and certificate restrictions, alerts, scope elevation and second-person approvals."
        case .analyst: "Aggregate analytics and usage. Read-only."
        case .billingAdmin: "Usage, invoices, payment methods and spend alerts."
        case .auditor: "Read-only access to settings, audit log and compliance records. No secrets, no changes."
        }
    }

    func permits(_ permission: DashboardPermission) -> Bool { permission.roles.contains(self) }

    /// Roles an actor of this role may grant, change from or remove (`RoleGrantPolicy`).
    var grantableRoles: Set<OrgRole> {
        switch self {
        case .owner: Set(OrgRole.allCases)
        case .orgAdmin: [.developer, .messagingOperator, .verificationAdmin, .analyst, .billingAdmin, .auditor]
        default: []
        }
    }
}

/// Everything a dashboard action can require. Checked on every request against the *current* membership, so a role change or removal takes
/// effect immediately.
public enum DashboardPermission: String, CaseIterable, Sendable {
    case viewOverview, viewTemplates
    case viewOrganization, manageOrganization
    case viewTeam, manageTeam
    /// See keys (never their secrets) and their last-used metadata.
    case viewAPIKeys
    /// Create or rotate a key within the baseline scopes. Never widens scope (see `elevateKeyScope`).
    case manageAPIKeys
    /// Revoke a key. Protective, so it needs no re-authentication.
    case revokeAPIKeys
    /// Create a key with a scope beyond the messaging baseline (approvals, key directory, any non-messaging capability). The only
    /// permission that widens what a credential can do.
    case elevateKeyScope
    case viewWebhooks, manageWebhooks
    case viewMessaging, manageCampaigns, viewConsent
    case viewVerify, manageVerify
    case viewApprove, manageApprove
    case viewSecurity, manageSecurity
    case viewAudit
    case viewCompliance, manageCompliance
    /// Accept the business agreement, DPA, AUP and addenda on behalf of the organization.
    case acceptContracts
    /// Submit onboarding facts (domain, legal entity) and request production access.
    case requestGoLive
    case viewBilling, manageBilling
    case viewSupport, manageSupport
    /// Decide a second-person approval (never one's own request).
    case approveChanges
    /// Request the tenant's data export or deletion.
    case manageDataRequests
    /// Hosted Loops inbox (WP-3.4): read items, which contain what customers entered.
    case viewInbox
    /// Act on inbox items: accept, reject, ask for information, assign, notes, operating hours.
    case manageInbox
    /// Submit Loop revisions for Viadere review. There is no business permission that publishes (FX-3).
    case submitLoops
    /// Brand Kit Studio (WP-2.5): upload images, edit kits and the schedule, submit for Viadere review. Never publishes unreviewed content.
    case manageBrandKits

    var roles: Set<OrgRole> {
        switch self {
        case .viewOverview, .viewTemplates, .viewSupport: Set(OrgRole.allCases)
        case .viewOrganization: [.owner, .orgAdmin, .verificationAdmin, .securityAdmin, .auditor]
        case .manageOrganization, .requestGoLive: [.owner, .orgAdmin]
        case .viewTeam: [.owner, .orgAdmin, .securityAdmin, .auditor]
        case .manageTeam: [.owner, .orgAdmin]
        case .viewAPIKeys: [.owner, .orgAdmin, .developer, .securityAdmin, .auditor]
        case .manageAPIKeys: [.owner, .orgAdmin, .developer, .securityAdmin]
        case .revokeAPIKeys: [.owner, .orgAdmin, .developer, .securityAdmin]
        case .elevateKeyScope: [.owner, .securityAdmin]
        case .viewWebhooks: [.owner, .orgAdmin, .developer, .messagingOperator, .auditor]
        case .manageWebhooks: [.owner, .orgAdmin, .developer]
        case .viewMessaging: [.owner, .orgAdmin, .developer, .messagingOperator, .analyst, .auditor]
        case .manageCampaigns: [.owner, .orgAdmin, .developer, .messagingOperator]
        case .viewConsent: [.owner, .orgAdmin, .messagingOperator, .verificationAdmin, .analyst, .auditor]
        case .viewVerify: [.owner, .orgAdmin, .verificationAdmin, .securityAdmin, .analyst, .auditor]
        case .manageVerify: [.owner, .verificationAdmin]
        case .viewApprove: [.owner, .orgAdmin, .developer, .securityAdmin, .auditor]
        case .manageApprove: [.owner, .securityAdmin]
        case .viewSecurity: [.owner, .orgAdmin, .securityAdmin, .auditor]
        case .manageSecurity: [.owner, .securityAdmin]
        case .viewAudit: [.owner, .orgAdmin, .securityAdmin, .auditor]
        case .viewCompliance: [.owner, .orgAdmin, .verificationAdmin, .securityAdmin, .auditor]
        case .manageCompliance: [.owner, .orgAdmin, .verificationAdmin]
        case .acceptContracts: [.owner, .orgAdmin]
        case .viewBilling: [.owner, .orgAdmin, .billingAdmin, .analyst, .auditor]
        case .manageBilling: [.owner, .billingAdmin]
        case .manageSupport: [.owner, .orgAdmin, .developer, .messagingOperator, .verificationAdmin, .securityAdmin, .billingAdmin]
        case .approveChanges: [.owner, .securityAdmin, .orgAdmin]
        case .manageDataRequests: [.owner, .orgAdmin]
        case .viewInbox: [.owner, .orgAdmin, .messagingOperator, .auditor]
        case .manageInbox: [.owner, .orgAdmin, .messagingOperator]
        case .submitLoops: [.owner, .orgAdmin, .developer]
        case .manageBrandKits: [.owner, .orgAdmin]
        }
    }
}

/// Who may grant which role (separation of duties): nobody grants themselves anything, only an Owner creates Owners, Organization Admins or
/// Security Admins, and the Organization Admin's reach stops below those three.
enum RoleGrantPolicy {
    /// Whether `actor` may assign `target`, or change or remove a member currently holding it.
    static func mayManage(actor: OrgRole, role target: OrgRole) -> Bool { actor.grantableRoles.contains(target) }
}

/// Key scopes that widen what a credential can do beyond messaging (needs `elevateKeyScope`).
enum KeyScopePolicy {
    static let baselineScopes: Set<String> = [BusinessAPIKeys.Scope.interactionsWrite, BusinessAPIKeys.Scope.interactionsRead, BusinessAPIKeys.Scope.messagesWrite,
                                              BusinessAPIKeys.Scope.statusesWrite, BusinessAPIKeys.Scope.webhooksManage, BusinessAPIKeys.Scope.rewardsWrite,
                                              BusinessAPIKeys.Scope.walletWrite]

    /// True if any requested operational scope or capability goes beyond the messaging baseline.
    static func elevates(scopes: [String], capabilities: [String]) -> Bool {
        !Set(scopes).isSubset(of: baselineScopes) || !Set(capabilities).isSubset(of: Set(Capability.messaging.map(\.rawValue)))
    }
}

/// The permission matrix as Markdown, rendered from `DashboardPermission.roles`. `docs/ops/CONSOLE-ROLES.md` embeds this text between the
/// markers and `WP6RolesTests` fails when the file and the code differ, so the document cannot drift from what the server enforces.
enum OrgRoleMatrix {
    static let beginMarker = "<!-- matrix:begin -->"
    static let endMarker = "<!-- matrix:end -->"

    static func markdown() -> String {
        let roles = OrgRole.allCases.sorted(by: >)
        var lines = ["| Permission | " + roles.map(\.title).joined(separator: " | ") + " |",
                     "|---|" + roles.map { _ in ":-:" }.joined(separator: "|") + "|"]
        for permission in DashboardPermission.allCases {
            lines.append("| `\(permission.rawValue)` | " + roles.map { permission.roles.contains($0) ? "x" : "" }.joined(separator: " | ") + " |")
        }
        return lines.joined(separator: "\n")
    }
}
