import Fluent
import Foundation
import ViadereCore

/// State-changing dashboard operations. Every method re-checks permission against the principal's *current* role,
/// scopes every query to the principal's organization, and writes an audit event.
struct DashboardActions {
    let db: any Database
    let ctx: ServerContext
    let principal: DashboardPrincipal

    var businessId: UUID { principal.business?.id ?? UUID() }
    var actor: AuditActor { AuditActor(kind: .business, id: principal.user.id?.uuidString.lowercased()) }

    func require(_ permission: DashboardPermission) throws {
        guard principal.can(permission) else { throw APIError.forbidden }
    }

    func requireVerified() throws {
        guard principal.business?.isVerified == true else {
            throw APIError(.forbidden, .forbidden, "This is available once Viadere has verified your organization.")
        }
    }

    /// Sensitive actions need a passkey assertion from the last few minutes.
    func requireReauth(next: String) throws {
        guard principal.hasFreshReauth(ctx: ctx) else { throw ReauthRequired(next: next) }
    }

    private func audit(_ action: String, outcome: AuditEvent.Outcome = .success, subjectType: String? = nil, subjectId: String? = nil,
                       metadata: [String: String] = [:]) async throws {
        _ = try await AuditService(db: db, ctx: ctx).record(action, outcome: outcome, actor: actor, businessId: BusinessID(businessId),
                                                          subjectType: subjectType, subjectId: subjectId, metadata: metadata)
    }

    // MARK: API keys

    static let maxActiveKeys = 25

    func createAPIKey(name rawName: String, live: Bool, scopes: [String], expiresInDays: Int?) async throws -> BusinessAPIKeys.Issued {
        try require(.manageAPIKeys)
        try requireVerified()
        try requireReauth(next: "/dashboard/api-keys")
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...64).contains(name.count), !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Give the key a name of up to 64 characters.", details: ["name": "invalid"])
        }
        let chosen = Array(Set(scopes)).filter { BusinessAPIKeys.Scope.all.contains($0) }
        guard !chosen.isEmpty, chosen.count == Set(scopes).count else {
            throw APIError.validation("Choose at least one valid scope.", details: ["scopes": "invalid"])
        }
        let active = try await BusinessAPIKeyRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).count()
        guard active < Self.maxActiveKeys else { throw APIError.conflict("Revoke an unused key before creating another.") }
        let now = ctx.now
        let expiry = expiresInDays.flatMap { [30, 90, 365].contains($0) ? now.addingTimeInterval(TimeInterval($0) * 86_400) : nil }
        let issued = try await BusinessAPIKeys.issue(businessId: businessId, name: name, live: live, scopes: chosen.sorted(), now: now,
                                                     expiresAt: expiry, on: db)
        try await audit("apikey.created", subjectType: "api_key", subjectId: issued.record.id?.uuidString.lowercased(),
                        metadata: ["mode": live ? "live" : "test", "scopes": chosen.sorted().joined(separator: " ")])
        return issued
    }

    func revokeAPIKey(id: UUID) async throws {
        try require(.manageAPIKeys)
        guard let key = try await BusinessAPIKeyRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else {
            throw APIError.notFound
        }
        guard key.revokedAt == nil else { return }
        // Revoking is protective, so it never needs re-authentication.
        _ = try await DB.swapFromNull(db, table: BusinessAPIKeyRecord.schema, id: id, column: "revoked_at", newValue: ctx.now)
        try await audit("apikey.revoked", subjectType: "api_key", subjectId: id.uuidString.lowercased())
    }

    // MARK: Webhooks

    func createWebhook(url: String, events: [String]) async throws -> WebhookSecretResponse {
        try require(.manageWebhooks)
        try requireVerified()
        try requireReauth(next: "/dashboard/webhooks")
        guard let parsed = URL(string: url.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw APIError.validation("Enter a valid https URL.", details: ["url": "invalid"])
        }
        let created = try await WebhookService(db: db, ctx: ctx).create(
            businessId: BusinessID(businessId), request: CreateWebhookRequest(url: parsed, events: events.map { WebhookEventType(rawValue: $0) }))
        try await audit("dashboard.webhook_created", subjectType: "webhook", subjectId: created.subscription.id.description)
        return created
    }

    func rotateWebhook(id: UUID) async throws -> WebhookSecretResponse {
        try require(.manageWebhooks)
        try requireVerified()
        try requireReauth(next: "/dashboard/webhooks")
        let rotated = try await WebhookService(db: db, ctx: ctx).rotate(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id))
        try await audit("dashboard.webhook_rotated", subjectType: "webhook", subjectId: id.uuidString.lowercased())
        return rotated
    }

    func deleteWebhook(id: UUID) async throws {
        try require(.manageWebhooks)
        try await WebhookService(db: db, ctx: ctx).delete(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id))
        try await audit("dashboard.webhook_deleted", subjectType: "webhook", subjectId: id.uuidString.lowercased())
    }

    /// Re-queues a dead-lettered delivery of *this* organization. Compare-and-swap `dead → pending`, so a
    /// double click replays once.
    func replayDelivery(id: UUID) async throws {
        try require(.manageWebhooks)
        try requireVerified()
        guard let delivery = try await WebhookDeliveryRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else {
            throw APIError.notFound
        }
        guard delivery.status == "dead", let subscription = try await WebhookSubscriptionRecord.find(delivery.subscriptionId, on: db),
              subscription.active, subscription.businessId == businessId else {
            throw APIError.conflict("Only dead-lettered deliveries to an active endpoint can be replayed.")
        }
        guard try await DB.swap(db, table: WebhookDeliveryRecord.schema, id: id, column: "status", expected: "dead", newValue: "pending",
                                extra: [("attempts", 0), ("next_attempt_at", ctx.now)]) else {
            throw APIError.conflict("This delivery was already replayed.")
        }
        try await audit("dashboard.webhook_replayed", subjectType: "webhook_delivery", subjectId: id.uuidString.lowercased(),
                        metadata: ["event_type": delivery.eventType])
    }

    // MARK: Campaign links

    static let identifierCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")

    struct Campaign {
        var link: ConnectLink
        var plainLink: ConnectLink
        var qr: QRCode
        var expiresAt: Date?
    }

    func campaign(name: String, action: String?, validDays: Int) async throws -> Campaign {
        try require(.manageCampaigns)
        try requireVerified()
        func clean(_ value: String?, _ field: String) throws -> String? {
            guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
            guard value.count <= 64, value.unicodeScalars.allSatisfy({ Self.identifierCharacters.contains($0) }) else {
                throw APIError.validation("Use up to 64 letters, digits, dots, dashes or underscores.", details: [field: "invalid"])
            }
            return value
        }
        guard let campaignId = try clean(name, "campaign") else {
            throw APIError.validation("Give the campaign a short identifier.", details: ["campaign": "required"])
        }
        let actionId = try clean(action, "action")
        guard let codeRecord = try await BusinessCodeRecord.query(on: db).filter(\.$businessId == businessId).first(),
              let code = BusinessCode(parsing: codeRecord.canonical) else { throw APIError.notFound }
        let now = ctx.now
        let days = min(max(validDays, 0), 365)
        let expires = days == 0 ? nil : now.addingTimeInterval(TimeInterval(days) * 86_400)
        let context = ConnectContext(campaign: campaignId, action: actionId, issuedAt: now, expiresAt: expires)
        let link = try ConnectLink(code: code, context: context, key: ctx.config.connectLinkKey)
        let qr = try QRCode.encode(link.urlString, errorCorrection: .medium)
        try await audit("campaign.link_created", subjectType: "campaign", subjectId: campaignId)
        return Campaign(link: link, plainLink: ConnectLink(code: code), qr: qr, expiresAt: expires)
    }

    // MARK: Team

    static let maxPendingInvites = 20

    private func membership(_ id: UUID) async throws -> OrgMembershipRecord {
        guard let found = try await OrgMembershipRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId)
            .filter(\.$removedAt == nil).first() else { throw APIError.notFound }
        return found
    }

    private func ownerCount(excluding id: UUID? = nil) async throws -> Int {
        var query = OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$role == OrgRole.owner.rawValue).filter(\.$removedAt == nil)
        if let id { query = query.filter(\.$id != id) }
        return try await query.count()
    }

    /// Admins may manage everything below `owner`; only owners create, change or remove owners — and adding an owner
    /// needs a fresh passkey assertion.
    private func authorize(roleChangeTo target: OrgRole, current: OrgRole?) throws {
        guard let actorRole = principal.role else { throw APIError.forbidden }
        if target == .owner || current == .owner {
            guard actorRole == .owner else { throw APIError.forbidden }
        }
    }

    func invite(email rawEmail: String, role: OrgRole) async throws -> String {
        try require(.manageTeam)
        try authorize(roleChangeTo: role, current: nil)
        if role == .owner { try requireReauth(next: "/dashboard/team") }
        guard let email = DashboardAuthService.normalizeEmail(rawEmail) else {
            throw APIError.validation("Enter a valid email address.", details: ["email": "invalid"])
        }
        let emailHash = ctx.hasher.hmacHex("dashboard-email", email)
        if let user = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == emailHash).first(),
           try await OrgMembershipRecord.query(on: db).filter(\.$userId == user.id!).filter(\.$businessId == businessId).filter(\.$removedAt == nil).count() > 0 {
            throw APIError.conflict("That person is already on the team.")
        }
        let pending = try await OrgInviteRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$state == "open").count()
        guard pending < Self.maxPendingInvites else { throw APIError.conflict("Too many pending invitations. Revoke some first.") }
        let token = SecureToken.generate()
        let now = ctx.now
        try await db.transaction { tx in
            // Only the newest invitation to an address works.
            try await OrgInviteRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$emailHash == emailHash).filter(\.$state == "open")
                .set(\.$state, to: "revoked").update()
            let invite = OrgInviteRecord()
            invite.id = UUID()
            invite.businessId = businessId
            invite.emailHash = emailHash
            invite.emailCiphertext = try ctx.cipher.seal(email, context: "org_invites.email", rowId: invite.id!)
            invite.role = role.rawValue
            invite.tokenHash = SecureToken.hash(token)
            invite.invitedBy = principal.user.id!
            invite.state = "open"
            invite.createdAt = now
            invite.expiresAt = now.addingTimeInterval(ctx.config.dashboard.inviteTTL)
            try await invite.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("team.invited", actor: actor, businessId: BusinessID(businessId), subjectType: "invite",
                                                              subjectId: invite.id?.uuidString.lowercased(), metadata: ["role": role.rawValue])
        }
        return ctx.config.publicBaseURL + "/dashboard/invite/" + token
    }

    func revokeInvite(id: UUID) async throws {
        try require(.manageTeam)
        guard let invite = try await OrgInviteRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        if invite.role == OrgRole.owner.rawValue { try authorize(roleChangeTo: .owner, current: nil) }
        _ = try await DB.swap(db, table: OrgInviteRecord.schema, id: id, column: "state", expected: "open", newValue: "revoked")
        try await audit("team.invite_revoked", subjectType: "invite", subjectId: id.uuidString.lowercased())
    }

    func changeRole(membershipId: UUID, to newRole: OrgRole) async throws {
        try require(.manageTeam)
        let member = try await membership(membershipId)
        let current = OrgRole(rawValue: member.role)
        guard member.userId != principal.user.id else { throw APIError.conflict("Ask another owner or admin to change your own role.") }
        try authorize(roleChangeTo: newRole, current: current)
        if newRole == .owner { try requireReauth(next: "/dashboard/team") }
        if current == .owner, newRole != .owner, try await ownerCount(excluding: membershipId) == 0 {
            throw APIError.conflict("An organization needs at least one owner.")
        }
        member.role = newRole.rawValue
        try await member.update(on: db)
        try await audit("team.role_changed", subjectType: "user", subjectId: member.userId.uuidString.lowercased(),
                        metadata: ["from": current?.rawValue ?? "", "to": newRole.rawValue])
        // The member's sessions keep working but their role is read fresh on every request.
    }

    func removeMember(membershipId: UUID) async throws {
        try require(.manageTeam)
        let member = try await membership(membershipId)
        let current = OrgRole(rawValue: member.role)
        guard member.userId != principal.user.id else { throw APIError.conflict("Ask another owner or admin to remove you.") }
        try authorize(roleChangeTo: current ?? .analyst, current: current)
        if current == .owner, try await ownerCount(excluding: membershipId) == 0 { throw APIError.conflict("An organization needs at least one owner.") }
        member.removedAt = ctx.now
        try await member.update(on: db)
        // Sessions acting for this organization end now.
        try await DashboardSessionRecord.query(on: db).filter(\.$userId == member.userId).filter(\.$businessId == businessId)
            .filter(\.$revokedAt == nil).set(\.$revokedAt, to: ctx.now).update()
        try await audit("team.member_removed", subjectType: "user", subjectId: member.userId.uuidString.lowercased(), metadata: ["role": member.role])
    }

    /// A signed-in user accepts an invitation addressed to their own email.
    static func acceptInvite(token: String, principal: DashboardPrincipal, db: any Database, ctx: ServerContext) async throws -> UUID {
        guard let invite = try await DashboardAuthService(db: db, ctx: ctx).openInvite(token: token),
              ConstantTime.equals(invite.emailHash, principal.user.emailHash) else {
            throw APIError(.forbidden, .forbidden, "This invitation is not valid for your account.")
        }
        let userId = principal.user.id!
        try await db.transaction { tx in
            guard try await DB.swap(tx, table: OrgInviteRecord.schema, id: invite.id!, column: "state", expected: "open", newValue: "accepted",
                                    extra: [("accepted_at", ctx.now)]) else { throw APIError.gone("This invitation was already used.") }
            if let existing = try await OrgMembershipRecord.query(on: tx).filter(\.$businessId == invite.businessId).filter(\.$userId == userId).first() {
                existing.removedAt = nil
                existing.role = invite.role
                try await existing.update(on: tx)
            } else {
                let membership = OrgMembershipRecord()
                membership.id = UUID()
                membership.businessId = invite.businessId
                membership.userId = userId
                membership.role = invite.role
                membership.createdAt = ctx.now
                try await membership.create(on: tx)
            }
            _ = try await AuditService(db: tx, ctx: ctx).record("team.invite_accepted", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
                businessId: BusinessID(invite.businessId), subjectType: "user", subjectId: userId.uuidString.lowercased(), metadata: ["role": invite.role])
        }
        return invite.businessId
    }

    /// Moves the session to another organization the user belongs to (membership re-verified).
    static func switchOrganization(to businessId: UUID, principal: DashboardPrincipal, db: any Database) async throws {
        guard try await OrgMembershipRecord.query(on: db).filter(\.$userId == principal.user.id!).filter(\.$businessId == businessId)
            .filter(\.$removedAt == nil).count() > 0 else { throw APIError.forbidden }
        principal.session.businessId = businessId
        try await principal.session.update(on: db)
    }

    // MARK: Organization

    func resubmit(legalName: String?, website: String?, requestedHandle: String?, description: String?) async throws {
        try require(.manageOrganization)
        var handle: String?
        if let raw = requestedHandle?.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "@", with: ""), !raw.isEmpty {
            guard let valid = try? BusinessHandle.validateForRegistration(raw) else {
                throw APIError.validation("That handle can't be used.", details: ["requestedHandle": "invalid"])
            }
            handle = valid.value
        }
        do {
            try await BusinessOnboarding(db: db, ctx: ctx).resubmit(businessId: businessId, by: principal.user.id!, legalName: legalName,
                                                                    website: website, requestedHandle: handle, description: description)
        } catch BusinessOnboarding.Failure.notPending {
            throw APIError.conflict("Your application can only be edited after it has been declined.")
        }
    }
}
