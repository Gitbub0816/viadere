import Foundation

/// Organization roles. Least privilege: each role gets exactly the permissions its job needs.
public enum OrgRole: String, CaseIterable, Sendable, Comparable {
    case analyst, support, developer, admin, owner

    var rank: Int {
        switch self {
        case .analyst: 0
        case .support: 1
        case .developer: 2
        case .admin: 3
        case .owner: 4
        }
    }

    public static func < (lhs: OrgRole, rhs: OrgRole) -> Bool { lhs.rank < rhs.rank }

    var title: String { rawValue.capitalized }

    var summary: String {
        switch self {
        case .owner: "Everything, including billing and adding owners."
        case .admin: "Team, API keys, webhooks, audit and settings. Cannot add owners."
        case .developer: "API keys, webhooks, templates and campaign links."
        case .support: "Consent status and templates. No credentials."
        case .analyst: "Aggregate analytics and usage. Read-only."
        }
    }

    func permits(_ permission: DashboardPermission) -> Bool { permission.roles.contains(self) }
}

/// Everything a dashboard action can require. Checked on every request against the *current* membership,
/// so a role change or removal takes effect immediately.
public enum DashboardPermission: Sendable {
    case viewOverview, viewTemplates
    case viewAPIKeys, manageAPIKeys
    case viewWebhooks, manageWebhooks
    case manageCampaigns
    case viewConsent
    case viewAudit
    case viewTeam, manageTeam
    case viewBilling
    case manageOrganization

    var roles: Set<OrgRole> {
        switch self {
        case .viewOverview: Set(OrgRole.allCases)
        case .viewTemplates: Set(OrgRole.allCases)
        case .viewAPIKeys, .manageAPIKeys: [.owner, .admin, .developer]
        case .viewWebhooks, .manageWebhooks: [.owner, .admin, .developer]
        case .manageCampaigns: [.owner, .admin, .developer]
        case .viewConsent: [.owner, .admin, .support, .analyst]
        case .viewAudit: [.owner, .admin]
        case .viewTeam, .manageTeam: [.owner, .admin]
        case .viewBilling: [.owner, .admin, .analyst]
        case .manageOrganization: [.owner, .admin]
        }
    }
}
