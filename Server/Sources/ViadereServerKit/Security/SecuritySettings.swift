import Fluent
import Foundation
import ViadereCore

/// What a business subscribes to by email (console > Security > Alerts). With no explicit choice every topic is on.
enum SecurityAlertTopic: String, CaseIterable, Sendable {
    case suspiciousLogin = "suspicious_login"
    case keyEvents = "key_events"
    case roleChanges = "role_changes"
    case webhookEvents = "webhook_events"
    case assurance
    case incidents

    var title: String {
        switch self {
        case .suspiciousLogin: "Sign-ins from a new device, location or address"
        case .keyEvents: "API keys created, rotated, revoked or expiring"
        case .roleChanges: "Team and role changes"
        case .webhookEvents: "Webhook endpoints verified, paused or failing"
        case .assurance: "Verification, contract and domain re-checks"
        case .incidents: "Viadere incident and policy notices"
        }
    }
}

/// Per-business console security settings (spec §9.1 Security): IP allow-list for the console, the privileged-operation inactivity timeout,
/// two-person approval, required mTLS, alert subscriptions and security contacts.
struct SecuritySettings {
    let db: any Database
    let ctx: ServerContext

    static let inactivityBounds = 60...900
    static let maxContacts = 5

    func settings(businessId: UUID) async throws -> BusinessSecuritySettingsRecord {
        if let found = try await BusinessSecuritySettingsRecord.query(on: db).filter(\.$businessId == businessId).first() { return found }
        let created = BusinessSecuritySettingsRecord(businessId: businessId, now: ctx.now)
        do { try await created.create(on: db) } catch {
            if error.isConstraintViolation, let found = try await BusinessSecuritySettingsRecord.query(on: db).filter(\.$businessId == businessId).first() { return found }
            throw error
        }
        return created
    }

    /// Read without creating a row (the request path).
    func existing(businessId: UUID) async throws -> BusinessSecuritySettingsRecord? {
        try await BusinessSecuritySettingsRecord.query(on: db).filter(\.$businessId == businessId).first()
    }

    // MARK: Contacts

    func contacts(businessId: UUID) async throws -> [String] {
        guard let row = try await existing(businessId: businessId), let sealed = row.contactsCiphertext, let id = row.id,
              let data = try? ctx.cipher.open(sealed, context: "business_security_settings.contacts", rowId: id),
              let list = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return list
    }

    func setContacts(businessId: UUID, emails raw: [String], by userId: UUID) async throws {
        let emails = raw.compactMap { DashboardAuthService.normalizeEmail($0) }
        guard emails.count == raw.filter({ !$0.trimmingCharacters(in: .whitespaces).isEmpty }).count, emails.count <= Self.maxContacts else {
            throw APIError.validation("Enter up to \(Self.maxContacts) valid email addresses.", details: ["contacts": "invalid"])
        }
        let unique = Array(Set(emails)).sorted()
        let row = try await settings(businessId: businessId)
        row.contactsCiphertext = unique.isEmpty ? nil : try ctx.cipher.seal(JSONEncoder().encode(unique), context: "business_security_settings.contacts", rowId: row.id!)
        try await touch(row, by: userId, action: "security.contacts_set", businessId: businessId, metadata: ["count": String(unique.count)])
    }

    // MARK: Alerts

    func subscriptions(businessId: UUID) async throws -> Set<SecurityAlertTopic> {
        guard let row = try await existing(businessId: businessId), !row.alertSubscriptions.isEmpty else { return Set(SecurityAlertTopic.allCases) }
        if row.alertSubscriptions == "none" { return [] }
        return Set(row.alertSubscriptions.split(separator: ",").compactMap { SecurityAlertTopic(rawValue: String($0)) })
    }

    func setSubscriptions(businessId: UUID, topics: Set<SecurityAlertTopic>, by userId: UUID) async throws {
        let row = try await settings(businessId: businessId)
        row.alertSubscriptions = topics.isEmpty ? "none" : topics.map(\.rawValue).sorted().joined(separator: ",")
        try await touch(row, by: userId, action: "security.alerts_set", businessId: businessId, metadata: ["topics": row.alertSubscriptions])
    }

    // MARK: Restrictions

    /// The console IP allow-list. The caller's own address must be inside it (no self-lockout) unless the list is being cleared.
    func setConsoleAllowlist(businessId: UUID, text: String, callerIP: String, by userId: UUID) async throws {
        guard let networks = IPNetwork.parseList(text, limit: 20) else {
            throw APIError.validation("Enter addresses or CIDR blocks such as 203.0.113.0/24, separated by commas.", details: ["allowlist": "invalid"])
        }
        guard networks.isEmpty || IPNetwork.allows(callerIP, in: networks) else {
            throw APIError.validation("Your current address is not in the list. Add it first so you are not locked out.", details: ["allowlist": "excludes_you"])
        }
        let row = try await settings(businessId: businessId)
        row.consoleIPAllowlist = networks.map(\.description).joined(separator: ",")
        try await touch(row, by: userId, action: "security.console_allowlist_set", businessId: businessId, metadata: ["entries": String(networks.count)])
    }

    func setPrivilegedInactivity(businessId: UUID, seconds: Int, by userId: UUID) async throws {
        guard Self.inactivityBounds.contains(seconds) else {
            throw APIError.validation("Choose between \(Self.inactivityBounds.lowerBound) and \(Self.inactivityBounds.upperBound) seconds.", details: ["seconds": "out_of_range"])
        }
        let row = try await settings(businessId: businessId)
        row.privilegedInactivitySeconds = seconds
        try await touch(row, by: userId, action: "security.inactivity_set", businessId: businessId, metadata: ["seconds": String(seconds)])
    }

    /// Two-person approval needs at least two people who can approve, or the tenant could lock itself out of creating keys.
    func setTwoPerson(businessId: UUID, required: Bool, by userId: UUID) async throws {
        if required {
            let approvers = try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$removedAt == nil).all()
                .filter { OrgRole(rawValue: $0.role)?.permits(.approveChanges) == true }
            guard approvers.count >= 2 else {
                throw APIError.conflict("Two-person approval needs at least two members who can approve (Owner, Security Admin or Organization Admin).")
            }
        }
        let row = try await settings(businessId: businessId)
        row.twoPersonRequired = required
        try await touch(row, by: userId, action: "security.two_person_set", businessId: businessId, metadata: ["required": required ? "true" : "false"])
    }

    func setMTLSRequired(businessId: UUID, required: Bool, by userId: UUID) async throws {
        if required {
            let certs = try await MTLSCertificates(db: db, ctx: ctx).list(businessId: businessId).filter { $0.isActive(at: ctx.now) }
            guard !certs.isEmpty else { throw APIError.conflict("Add a client certificate before requiring mutual TLS for every key.") }
        }
        let row = try await settings(businessId: businessId)
        row.mtlsRequired = required
        try await touch(row, by: userId, action: "security.mtls_required_set", businessId: businessId, metadata: ["required": required ? "true" : "false"])
    }

    private func touch(_ row: BusinessSecuritySettingsRecord, by userId: UUID, action: String, businessId: UUID, metadata: [String: String]) async throws {
        row.updatedAt = ctx.now
        row.updatedBy = userId
        try await row.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record(action, actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
                                                          businessId: BusinessID(businessId), subjectType: "security_settings", metadata: metadata)
    }
}
