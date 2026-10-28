import Fluent
import Foundation
import ViadereCore

/// Console actions added by WP6: onboarding, contracts, security settings, certificates, sessions, compliance and support. Each one checks the
/// caller's *current* permission, scopes every query to the caller's organization, asks for a fresh passkey assertion where the action is
/// sensitive, and writes an audit event.
extension DashboardActions {
    private var onboarding: OnboardingService { OnboardingService(db: db, ctx: ctx) }
    var userId: UUID { principal.user.id! }

    // MARK: Onboarding

    func addDomain(_ domain: String) async throws -> BusinessDomainRecord {
        try require(.manageOrganization)
        return try await DomainControl(db: db, ctx: ctx).add(businessId: businessId, domain: domain, by: userId)
    }

    func checkDomain(id: UUID) async throws -> DomainControl.Outcome {
        try require(.manageOrganization)
        return try await DomainControl(db: db, ctx: ctx).check(businessId: businessId, id: id, by: userId)
    }

    func removeDomain(id: UUID) async throws {
        try require(.manageOrganization)
        try await requireReauth(next: "/dashboard/organization/domains")
        try await DomainControl(db: db, ctx: ctx).remove(businessId: businessId, id: id, by: userId)
    }

    func submitLegalEntity(registryNumber: String, jurisdiction: String, registryName: String, evidence: [String]) async throws {
        try require(.manageOrganization)
        try await onboarding.submitLegalEntity(businessId: businessId, registryNumber: registryNumber, jurisdiction: jurisdiction, registryName: registryName,
                                               evidence: evidence, by: userId)
    }

    func requestGoLive(useCase: String, volume: String) async throws {
        try require(.requestGoLive)
        try await requireReauth(next: "/dashboard/organization")
        try await onboarding.requestGoLive(businessId: businessId, useCase: useCase, volume: volume, by: userId)
        await alert(.assurance, subject: "Production access requested", text: "Your organization asked for production access. A Viadere reviewer will respond by email.")
    }

    // MARK: Contracts

    func acceptContract(slug: String, version: String, ip: String, userAgent: String) async throws {
        try require(.acceptContracts)
        try await requireReauth(next: "/dashboard/compliance")
        try await ContractService(db: db, ctx: ctx).accept(businessId: businessId, slug: slug, version: version, by: userId, ip: ip, userAgent: userAgent)
        try await onboarding.contractsChanged(businessId: businessId, actor: actor)
    }

    // MARK: Security

    func setConsoleAllowlist(_ text: String, callerIP: String) async throws {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/network")
        try await settingsService.setConsoleAllowlist(businessId: businessId, text: text, callerIP: callerIP, by: userId)
    }

    func setPrivilegedInactivity(seconds: Int) async throws {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/network")
        try await settingsService.setPrivilegedInactivity(businessId: businessId, seconds: seconds, by: userId)
    }

    /// Turning two-person approval **on** takes effect at once (it only adds a control). Turning it **off** is a pending change that a second
    /// person who may manage security has to approve, so one Security Admin (or one stolen session) cannot remove the control alone.
    @discardableResult
    func setTwoPerson(_ required: Bool) async throws -> TeamChange {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/approvals")
        if !required, try await twoPersonRequired() {
            let change = try await PendingChanges(db: db, ctx: ctx).request(businessId: businessId, kind: .securitySetting, by: userId,
                payload: PendingChanges.Payload(operation: "disable_two_person"))
            return .awaitingApproval(change.id!)
        }
        try await settingsService.setTwoPerson(businessId: businessId, required: required, by: userId)
        await alert(.roleChanges, subject: "Two-person approval changed", text: "Two-person approval for keys and team changes was turned \(required ? "on" : "off").")
        return .done
    }

    func setMTLSRequired(_ required: Bool) async throws {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/certificates")
        try await settingsService.setMTLSRequired(businessId: businessId, required: required, by: userId)
    }

    /// Needs a fresh passkey assertion (a stolen cookie must not silence alerts or add a contact) and always tells the owners, security admins and
    /// organization admins when the subscriptions or contacts changed, whatever the new subscriptions are (platform gate M2). The notice carries
    /// no contact address.
    func setAlerts(topics: Set<SecurityAlertTopic>, contacts: [String]) async throws {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/alerts")
        let topicsBefore = try await settingsService.subscriptions(businessId: businessId)
        let contactsBefore = try await settingsService.contacts(businessId: businessId)
        try await settingsService.setSubscriptions(businessId: businessId, topics: topics, by: userId)
        try await settingsService.setContacts(businessId: businessId, emails: contacts, by: userId)
        let topicsAfter = try await settingsService.subscriptions(businessId: businessId)
        let contactsAfter = try await settingsService.contacts(businessId: businessId)
        if topicsBefore != topicsAfter || Set(contactsBefore) != Set(contactsAfter) {
            await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .securityAdmin, .orgAdmin], includeSecurityContacts: false, topic: nil,
                subject: "Your organization's security alert settings changed",
                text: "A team member changed which security alerts are emailed (\(topicsAfter.count) of \(SecurityAlertTopic.allCases.count) topics are on) or the security contacts (\(contactsAfter.count) now). If this was not expected, review Security > Alerts and contacts and your team's sessions.",
                kind: "security-alert")
        }
        // A security contact completes an onboarding fact; nothing else changes.
        if !contacts.filter({ !$0.trimmingCharacters(in: .whitespaces).isEmpty }).isEmpty {
            _ = try await onboarding.apply(.securityContactSet, businessId: businessId, actor: actor) { _, _ in }
        }
    }

    func addCertificate(label: String, pem: String?, fingerprint: String?, asCA: Bool) async throws {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/certificates")
        let identity: MTLSCertificates.Identity
        if let pem, !pem.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { identity = try MTLSCertificates.identity(pem: pem, asCA: asCA) }
        else if let fingerprint, !asCA { identity = try MTLSCertificates.identity(fingerprint: fingerprint) }
        else { throw APIError.validation("Paste a PEM certificate or a SHA-256 fingerprint.", details: ["certificate": "required"]) }
        _ = try await MTLSCertificates(db: db, ctx: ctx).add(businessId: businessId, label: label, identity: identity, by: userId)
    }

    func removeCertificate(id: UUID) async throws {
        try require(.manageSecurity)
        try await requireReauth(next: "/dashboard/security/certificates")
        try await MTLSCertificates(db: db, ctx: ctx).revoke(businessId: businessId, id: id, by: userId)
    }

    /// Signs out one session. Everybody may end their own; ending someone else's is a Security Admin or Owner action and asks for the passkey.
    func revokeSession(id: UUID) async throws {
        guard let session = try await DashboardSessionRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        if session.userId != userId {
            try require(.manageSecurity)
            try await requireReauth(next: "/dashboard/security/sessions?scope=all")
        }
        try await SessionSecurity(db: db, ctx: ctx).revoke(sessionId: id, businessId: businessId, by: actor)
        // Ending the session this very request runs in is allowed; the cookie simply stops working.
    }

    func revokeOtherSessions() async throws {
        try await SessionSecurity(db: db, ctx: ctx).revokeOthers(userId: userId, keeping: principal.session.id!, businessId: businessId, by: actor)
    }

    // MARK: Two-person approvals

    func decideChange(id: UUID, approve: Bool, note: String?) async throws {
        try require(.approveChanges)
        try await requireReauth(next: "/dashboard/security/approvals")
        let pending = PendingChanges(db: db, ctx: ctx)
        if approve {
            try await pending.approve(id: id, approver: principal, note: note) { payload, requester in try await self.executeRoleGrant(payload, requester: requester) }
        } else {
            try await pending.reject(id: id, approver: principal, note: note)
        }
    }

    func cancelChange(id: UUID) async throws {
        try await PendingChanges(db: db, ctx: ctx).cancel(id: id, requester: principal)
    }

    // MARK: Compliance

    func setRetention(_ cls: RetentionClass, days: Int) async throws {
        try require(.manageCompliance)
        try await requireReauth(next: "/dashboard/compliance/retention")
        try await RetentionPolicy(db: db, ctx: ctx).setTenant(cls, businessId: businessId, days: days, by: userId)
    }

    func clearRetention(_ cls: RetentionClass) async throws {
        try require(.manageCompliance)
        try await requireReauth(next: "/dashboard/compliance/retention")
        try await RetentionPolicy(db: db, ctx: ctx).clearTenant(cls, businessId: businessId, by: userId)
    }

    func requestExport() async throws -> UUID {
        try require(.manageDataRequests)
        try await requireReauth(next: "/dashboard/compliance/requests")
        return try await TenantDataRequests(db: db, ctx: ctx).requestExport(businessId: businessId, by: userId)
    }

    func requestDeletion(confirmation: String) async throws {
        guard principal.role == .owner else { throw APIError.forbidden }
        try await requireReauth(next: "/dashboard/compliance/requests")
        try await TenantDataRequests(db: db, ctx: ctx).requestDeletion(businessId: businessId, confirmation: confirmation, by: userId)
        await alert(.assurance, subject: "Deletion of your organization's data was requested", text: "An Owner requested deletion of this organization's data. A Viadere operator will review it. If this was not you, contact Viadere support at once.")
    }

    func downloadExport(id: UUID) async throws -> Data {
        try require(.manageDataRequests)
        try await requireReauth(next: "/dashboard/compliance/requests")
        return try await TenantDataRequests(db: db, ctx: ctx).download(id: id, businessId: businessId, by: actor)
    }

    // MARK: Support

    func openTicket(kind: String, subject: String, body: String) async throws {
        try require(.manageSupport)
        let ticket = try await SupportDesk(db: db, ctx: ctx).open(businessId: businessId, kind: kind, subject: subject, body: body, by: userId)
        try await audit("support.\(kind)_opened", subjectType: "ticket", subjectId: ticket.id?.uuidString.lowercased())
    }
}
