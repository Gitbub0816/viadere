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

    /// Features tied to the public identity (campaign links, QR codes) need the approved application: the handle and code exist only then.
    func requireVerified() throws {
        guard principal.business?.isVerified == true else {
            throw APIError(.forbidden, .forbidden, "This is available once Viadere has verified your organization.")
        }
    }

    /// Sandbox work (test keys, webhooks, the test customer) is open as soon as the organization's domain control is verified; production work
    /// needs the approved application **and** the approved go-live review.
    func requireAccess(live: Bool) async throws {
        guard let business = principal.business else { throw APIError.forbidden }
        guard try await OnboardingGate.allows(business: business, livemode: live, on: db) else {
            throw APIError(.forbidden, .forbidden, live
                ? "Production access is approved after your go-live review. Complete onboarding under Organization."
                : "Verify a domain you control (Organization > Onboarding) to unlock the sandbox.")
        }
    }

    var settingsService: SecuritySettings { SecuritySettings(db: db, ctx: ctx) }

    func twoPersonRequired() async throws -> Bool { try await settingsService.existing(businessId: businessId)?.twoPersonRequired == true }

    /// Sensitive actions need a passkey assertion from the last few minutes, and the session must not have sat idle longer than the
    /// organization's privileged-operation timeout (default five minutes, 60 s to 15 min configurable): a left-open console cannot be used for them.
    func requireReauth(next: String) async throws {
        guard principal.hasFreshReauth(ctx: ctx) else { throw ReauthRequired(next: next) }
        let allowed = try await settingsService.existing(businessId: businessId)?.privilegedInactivitySeconds ?? 300
        if principal.idleBeforeRequest(ctx: ctx) > TimeInterval(allowed) {
            ctx.metrics.count(.privilegedDenied)
            throw ReauthRequired(next: next)
        }
    }

    func audit(_ action: String, outcome: AuditEvent.Outcome = .success, subjectType: String? = nil, subjectId: String? = nil,
               metadata: [String: String] = [:]) async throws {
        _ = try await AuditService(db: db, ctx: ctx).record(action, outcome: outcome, actor: actor, businessId: BusinessID(businessId),
                                                          subjectType: subjectType, subjectId: subjectId, metadata: metadata)
    }

    /// Emails the subscribed people of the organization about a security-relevant event (never includes a secret).
    func alert(_ topic: SecurityAlertTopic, subject: String, text: String) async {
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .securityAdmin, .orgAdmin], topic: topic, subject: subject, text: text, kind: "security-alert")
    }

    // MARK: API keys

    static let maxActiveKeys = 25
    static let expiryChoices = [30, 90, 365]

    /// A key request as the form (or an approved two-person payload) states it.
    struct KeyRequest {
        var name: String
        var live: Bool
        var scopes: [String]
        var capabilities: [String]?
        var expiresInDays: Int?
        var ipAllowlist: String
        var requiresMTLS: Bool
        /// A completed two-person approval to consume.
        var approvedChange: UUID?
    }

    enum KeyCreation {
        case issued(BusinessAPIKeys.Issued)
        /// Waiting for a second person (two-person approval is on).
        case awaitingApproval(UUID)
    }

    private struct ValidatedKey {
        var name: String
        var scopes: [String]
        var capabilities: [Capability]
        var expiry: Date?
        var networks: [IPNetwork]
        var elevates: Bool
    }

    private func validated(_ request: KeyRequest) async throws -> ValidatedKey {
        let name = request.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...64).contains(name.count), !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Give the key a name of up to 64 characters.", details: ["name": "invalid"])
        }
        let chosen = Array(Set(request.scopes)).filter { BusinessAPIKeys.Scope.all.contains($0) }
        guard !chosen.isEmpty, chosen.count == Set(request.scopes).count else {
            throw APIError.validation("Choose at least one valid scope.", details: ["scopes": "invalid"])
        }
        // Capability scopes (SEC-API-003) can only be chosen within the organization's current entitlements. Left out, a key that can
        // send gets the messaging capabilities it is entitled to and nothing more; a key with only webhook or reward scopes gets none.
        let entitled = try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId)
        func allowed(_ capability: Capability) -> Bool {
            guard let definition = capability.definition else { return false }
            return entitled.capabilities.contains(capability) && entitled.tiers.contains(definition.minimumTier)
        }
        let capabilities: [Capability]
        if let requested = request.capabilities {
            let parsed = requested.map { Capability(rawValue: $0) }
            guard Set(requested).count == requested.count, parsed.allSatisfy(allowed) else {
                throw APIError.validation("Choose only capabilities your organization is enabled for.", details: ["capabilities": "not_entitled"])
            }
            capabilities = parsed
        } else {
            let sends = !Set(chosen).isDisjoint(with: [BusinessAPIKeys.Scope.interactionsWrite, BusinessAPIKeys.Scope.interactionsRead,
                                                      BusinessAPIKeys.Scope.messagesWrite, BusinessAPIKeys.Scope.statusesWrite])
            capabilities = sends ? Capability.messaging.filter(allowed) : []
        }
        guard let networks = IPNetwork.parseList(request.ipAllowlist, limit: 20) else {
            throw APIError.validation("Enter addresses or CIDR blocks such as 203.0.113.0/24, separated by commas.", details: ["ipAllowlist": "invalid"])
        }
        // An unknown choice is refused rather than quietly becoming "never expires".
        if let days = request.expiresInDays, days != 0, !Self.expiryChoices.contains(days) {
            throw APIError.validation("Choose when the key expires from the list.", details: ["expires": "invalid"])
        }
        let expiry = request.expiresInDays.flatMap { Self.expiryChoices.contains($0) ? ctx.now.addingTimeInterval(TimeInterval($0) * 86_400) : nil }
        let elevates = KeyScopePolicy.elevates(scopes: chosen, capabilities: capabilities.map(\.rawValue))
        return ValidatedKey(name: name, scopes: chosen.sorted(), capabilities: capabilities, expiry: expiry, networks: networks, elevates: elevates)
    }

    /// Creates a key, or files a request for a second person's approval when the organization requires one.
    ///
    /// Separation of duties: credential creation needs `manageAPIKeys`; a key that goes beyond the messaging baseline (approvals, key directory,
    /// any other capability) additionally needs `elevateKeyScope` (Security Admin or Owner). A Developer can therefore issue credentials but can
    /// never widen what credentials can do.
    func createAPIKey(_ request: KeyRequest) async throws -> KeyCreation {
        try require(.manageAPIKeys)
        try await requireAccess(live: request.live)
        try await requireReauth(next: "/dashboard/api-keys")
        var request = request
        let userId = principal.user.id!
        var wasApproved = false
        if let changeId = request.approvedChange {
            // The stored request is the only one that counts: nothing the requester posts now can change what was approved.
            let stored = try await PendingChanges(db: db, ctx: ctx).consumeApproved(id: changeId, businessId: businessId, requester: userId, kind: .apiKey)
            request = KeyRequest(name: stored.name ?? "", live: stored.live ?? false, scopes: stored.scopes ?? [], capabilities: stored.capabilities,
                                 expiresInDays: stored.expiresInDays, ipAllowlist: stored.ipAllowlist ?? "", requiresMTLS: stored.requiresMTLS ?? false)
            try await requireAccess(live: request.live)
            wasApproved = true
        }
        let key = try await validated(request)
        if key.elevates && !wasApproved {
            guard principal.can(.elevateKeyScope) else {
                throw APIError(.forbidden, .forbidden, "This key goes beyond the messaging scopes. A Security Admin or an Owner has to create it.")
            }
        }
        if request.requiresMTLS {
            guard try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId).tiers.contains(.e) else {
                throw APIError(.forbidden, .forbidden, "Client certificates are part of the Enterprise tier.")
            }
            guard try await MTLSCertificates(db: db, ctx: ctx).list(businessId: businessId).contains(where: { $0.isActive(at: ctx.now) }) else {
                throw APIError.conflict("Add a client certificate under Security before requiring one for a key.")
            }
        }
        if !wasApproved, try await twoPersonRequired() {
            let change = try await PendingChanges(db: db, ctx: ctx).request(businessId: businessId, kind: .apiKey, by: userId, payload: PendingChanges.Payload(
                name: key.name, live: request.live, scopes: key.scopes, capabilities: key.capabilities.map(\.rawValue), expiresInDays: request.expiresInDays,
                ipAllowlist: key.networks.map(\.description).joined(separator: ","), requiresMTLS: request.requiresMTLS, elevates: key.elevates))
            return .awaitingApproval(change.id!)
        }
        let active = try await BusinessAPIKeyRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).count()
        guard active < Self.maxActiveKeys else { throw APIError.conflict("Revoke an unused key before creating another.") }
        var options = BusinessAPIKeys.Options(expiresAt: key.expiry)
        options.ipAllowlist = key.networks
        options.requiresMTLS = request.requiresMTLS
        options.createdBy = userId
        let issued = try await BusinessAPIKeys.issue(businessId: businessId, name: key.name, live: request.live, scopes: key.scopes, capabilities: key.capabilities,
                                                     now: ctx.now, options: options, on: db)
        ctx.metrics.count(.apiKeyCreated)
        try await audit("apikey.created", subjectType: "api_key", subjectId: issued.record.id?.uuidString.lowercased(),
                        metadata: ["mode": request.live ? "live" : "test", "scopes": key.scopes.joined(separator: " "),
                                   "capabilities": key.capabilities.map(\.rawValue).sorted().joined(separator: " "), "kid": issued.record.kid ?? "",
                                   "ip_restricted": key.networks.isEmpty ? "false" : "true", "approved_by_second_person": wasApproved ? "true" : "false"])
        if !request.live { try await OnboardingService(db: db, ctx: ctx).sandboxKeyIssued(businessId: businessId) }
        await alert(.keyEvents, subject: "An API key was created", text: "A new \(request.live ? "live" : "test") API key (\(issued.record.prefix)\(issued.record.kid ?? "")) was created for your organization. If this was not expected, revoke it in the console under Developers.")
        return .issued(issued)
    }

    /// Rotates a key with overlap. A key with elevated scope can only be rotated by someone who may issue one.
    func rotateAPIKey(id: UUID, overlap: TimeInterval, approvedChange: UUID? = nil) async throws -> KeyCreation {
        try require(.manageAPIKeys)
        try await requireReauth(next: "/dashboard/api-keys")
        let userId = principal.user.id!
        var overlap = overlap
        var id = id
        var wasApproved = false
        if let changeId = approvedChange {
            let stored = try await PendingChanges(db: db, ctx: ctx).consumeApproved(id: changeId, businessId: businessId, requester: userId, kind: .apiKeyRotation)
            guard let raw = stored.keyId, let storedId = UUID(uuidString: raw) else { throw APIError.internalError }
            id = storedId
            overlap = TimeInterval(stored.overlapSeconds ?? 0)
            wasApproved = true
        }
        let lifecycle = APIKeyLifecycle(db: db, ctx: ctx)
        let old = try await lifecycle.key(id, businessId: businessId)
        try await requireAccess(live: old.livemode)
        let elevates = KeyScopePolicy.elevates(scopes: Array(old.scopeSet), capabilities: old.capabilitySet.map(\.rawValue))
        if elevates && !wasApproved && !principal.can(.elevateKeyScope) {
            throw APIError(.forbidden, .forbidden, "This key goes beyond the messaging scopes. A Security Admin or an Owner has to rotate it.")
        }
        if !wasApproved, try await twoPersonRequired() {
            guard APIKeyLifecycle.overlapChoices.contains(overlap) else { throw APIError.validation("Choose a valid overlap.", details: ["overlap": "invalid"]) }
            let change = try await PendingChanges(db: db, ctx: ctx).request(businessId: businessId, kind: .apiKeyRotation, by: userId, payload: PendingChanges.Payload(
                keyId: id.uuidString.lowercased(), overlapSeconds: Int(overlap), elevates: elevates))
            return .awaitingApproval(change.id!)
        }
        let issued = try await lifecycle.rotate(id: id, businessId: businessId, overlap: overlap, actor: .user(userId))
        await alert(.keyEvents, subject: "An API key was rotated", text: "The API key \(old.prefix)\(old.kid ?? "…\(old.last4)") was rotated. " + (overlap == 0 ? "The old key stopped working immediately." : "The old key keeps working until the overlap ends."))
        return .issued(issued)
    }

    func revokeAPIKey(id: UUID) async throws {
        try require(.revokeAPIKeys)
        // Revoking is protective, so it never needs re-authentication.
        try await APIKeyLifecycle(db: db, ctx: ctx).revoke(id: id, businessId: businessId, reason: "revoked in the console", actor: .user(principal.user.id!))
        await alert(.keyEvents, subject: "An API key was revoked", text: "An API key of your organization was revoked in the console.")
    }

    // MARK: Webhooks

    func createWebhook(url: String, events: [String], opaque: Bool = false) async throws -> WebhookSecretResponse {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
        try await requireReauth(next: "/dashboard/webhooks")
        guard let parsed = URL(string: url.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw APIError.validation("Enter a valid https URL.", details: ["url": "invalid"])
        }
        let created = try await WebhookService(db: db, ctx: ctx).create(
            businessId: BusinessID(businessId), request: CreateWebhookRequest(url: parsed, events: events.map { WebhookEventType(rawValue: $0) },
                                                                              envelopeVersion: opaque ? WebhookEnvelopeV2.version : nil))
        try await audit("dashboard.webhook_created", subjectType: "webhook", subjectId: created.subscription.id.description)
        return created
    }

    func rotateWebhook(id: UUID) async throws -> WebhookSecretResponse {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
        try await requireReauth(next: "/dashboard/webhooks")
        let rotated = try await WebhookService(db: db, ctx: ctx).rotate(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id))
        try await audit("dashboard.webhook_rotated", subjectType: "webhook", subjectId: id.uuidString.lowercased())
        return rotated
    }

    func deleteWebhook(id: UUID) async throws {
        try require(.manageWebhooks)
        try await WebhookService(db: db, ctx: ctx).delete(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id))
        try await audit("dashboard.webhook_deleted", subjectType: "webhook", subjectId: id.uuidString.lowercased())
    }

    func verifyWebhook(id: UUID) async throws -> WebhookService.VerificationResult {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
        return try await WebhookService(db: db, ctx: ctx).verifyOwnership(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id))
    }

    func setWebhookPaused(id: UUID, paused: Bool, reason: String) async throws {
        try require(.manageWebhooks)
        try await WebhookService(db: db, ctx: ctx).setPaused(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id), paused: paused,
                                                             reason: reason.isEmpty ? "paused in the console" : reason, actor: actor)
        await alert(.webhookEvents, subject: paused ? "A webhook endpoint was paused" : "A webhook endpoint was resumed",
                    text: "A webhook endpoint of your organization was \(paused ? "paused" : "resumed") in the console.")
    }

    func sendTestEvent(id: UUID) async throws {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
        try await WebhookService(db: db, ctx: ctx).sendTestEvent(businessId: BusinessID(businessId), id: WebhookSubscriptionID(id))
    }

    /// Creates the sandbox customer (what the API's `POST /v1/business/sandbox/relationships` does) from the console.
    func createSandboxCustomer() async throws -> UUID {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
        let principal = BusinessPrincipal(businessId: BusinessID(businessId), keyId: UUID(), livemode: false, scopes: [], businessName: "", capabilities: [])
        let result = try await Sandbox(db: db).create(principal: principal, now: ctx.now, ctx: ctx)
        try await OnboardingService(db: db, ctx: ctx).sandboxRelationshipCreated(businessId: businessId)
        try await audit("dashboard.sandbox_customer_created", subjectType: "relationship", subjectId: result.relationshipId.description)
        return result.relationshipId.uuid
    }

    func simulateSandboxReply(relationshipId: UUID, text: String) async throws {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
        try await WebhookService(db: db, ctx: ctx).simulateReply(businessId: BusinessID(businessId), relationshipId: relationshipId, text: text)
    }

    /// Re-queues a dead-lettered delivery of *this* organization. Compare-and-swap `dead → pending`, so a
    /// double click replays once.
    func replayDelivery(id: UUID) async throws {
        try require(.manageWebhooks)
        try await requireAccess(live: false)
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
        let link = try ctx.connectKeys.link(code: code, context: context)
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

    /// Separation of duties: nobody grants themselves anything, only an Owner creates, changes or removes Owners, Organization Admins and Security
    /// Admins, and the Organization Admin's reach stops below those (`RoleGrantPolicy`). The three highest roles need a fresh passkey assertion.
    private func authorize(roleChangeTo target: OrgRole?, current: OrgRole?) async throws {
        guard let actorRole = principal.role else { throw APIError.forbidden }
        for role in [target, current].compactMap({ $0 }) {
            guard RoleGrantPolicy.mayManage(actor: actorRole, role: role) else { throw APIError.forbidden }
        }
        if [target, current].compactMap({ $0 }).contains(where: { [.owner, .orgAdmin, .securityAdmin].contains($0) }) { try await requireReauth(next: "/dashboard/team") }
    }

    /// What a role change or invitation turned into.
    enum TeamChange {
        case done
        case awaitingApproval(UUID)
    }

    /// Creates the invitation and **emails** the single-use link to the invited address; the inviter never sees the token. Accepting needs
    /// the invitee to prove the mailbox again with an emailed code (`DashboardAuthService.sendInviteCode`).
    @discardableResult
    func invite(email rawEmail: String, role: OrgRole) async throws -> TeamChange {
        try require(.manageTeam)
        try await authorize(roleChangeTo: role, current: nil)
        guard let email = DashboardAuthService.normalizeEmail(rawEmail) else {
            throw APIError.validation("Enter a valid email address.", details: ["email": "invalid"])
        }
        if try await twoPersonRequired() {
            let change = try await PendingChanges(db: db, ctx: ctx).request(businessId: businessId, kind: .roleGrant, by: principal.user.id!,
                payload: PendingChanges.Payload(operation: "invite", email: email, role: role.rawValue))
            return .awaitingApproval(change.id!)
        }
        try await createInvite(email: email, role: role, invitedBy: principal.user.id!)
        return .done
    }

    func createInvite(email: String, role: OrgRole, invitedBy: UUID) async throws {
        let emailHash = ctx.hasher.hmacHex("dashboard-email", email)
        if let user = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == emailHash).first(),
           try await OrgMembershipRecord.query(on: db).filter(\.$userId == user.id!).filter(\.$businessId == businessId).filter(\.$removedAt == nil).count() > 0 {
            throw APIError.conflict("That person is already on the team.")
        }
        let pending = try await OrgInviteRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$state == "open").count()
        guard pending < Self.maxPendingInvites else { throw APIError.conflict("Too many pending invitations. Revoke some first.") }
        let token = SecureToken.generate()
        let now = ctx.now
        let inviteId = UUID()
        let inviter = AuditActor(kind: .business, id: invitedBy.uuidString.lowercased())
        try await db.transaction { tx in
            // Only the newest invitation to an address works.
            try await OrgInviteRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$emailHash == emailHash).filter(\.$state == "open")
                .set(\.$state, to: "revoked").update()
            let invite = OrgInviteRecord()
            invite.id = inviteId
            invite.businessId = businessId
            invite.emailHash = emailHash
            invite.emailCiphertext = try ctx.cipher.seal(email, context: "org_invites.email", rowId: invite.id!)
            invite.role = role.rawValue
            invite.tokenHash = SecureToken.hash(token)
            invite.invitedBy = invitedBy
            invite.state = "open"
            invite.createdAt = now
            invite.expiresAt = now.addingTimeInterval(ctx.config.dashboard.inviteTTL)
            try await invite.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("team.invited", actor: inviter, businessId: BusinessID(businessId), subjectType: "invite",
                                                              subjectId: invite.id?.uuidString.lowercased(), metadata: ["role": role.rawValue])
        }
        let organization = principal.business?.displayName ?? "an organization"
        let message = EmailMessage(to: email, subject: "You've been invited to Viadere", text: """
            You've been invited to join \(organization) on Viadere as \(role.title).

            Open this link to accept (it works once and expires in \(Int(ctx.config.dashboard.inviteTTL / 86_400)) days):
            \(ctx.config.publicBaseURL)/dashboard/invite/\(token)

            You will be asked for a verification code that we email to this address when you open the link. If you did not expect this invitation, ignore this email.
            """, kind: "invite")
        do { try await ctx.email.send(message) } catch {
            // The invitation is useless if the mail did not go out: withdraw it instead of leaving a link nobody has.
            _ = try? await DB.swap(db, table: OrgInviteRecord.schema, id: inviteId, column: "state", expected: "open", newValue: "revoked")
            throw APIError.unavailable("The invitation email could not be sent. Try again in a few minutes.")
        }
    }

    func revokeInvite(id: UUID) async throws {
        try require(.manageTeam)
        guard let invite = try await OrgInviteRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        if let role = OrgRole(rawValue: invite.role) { try await authorize(roleChangeTo: nil, current: role) }
        _ = try await DB.swap(db, table: OrgInviteRecord.schema, id: id, column: "state", expected: "open", newValue: "revoked")
        try await audit("team.invite_revoked", subjectType: "invite", subjectId: id.uuidString.lowercased())
    }

    @discardableResult
    func changeRole(membershipId: UUID, to newRole: OrgRole) async throws -> TeamChange {
        try require(.manageTeam)
        let member = try await membership(membershipId)
        let current = OrgRole(rawValue: member.role)
        guard member.userId != principal.user.id else { throw APIError.conflict("Ask another owner or admin to change your own role.") }
        try await authorize(roleChangeTo: newRole, current: current)
        if current == .owner, newRole != .owner, try await ownerCount(excluding: membershipId) == 0 {
            throw APIError.conflict("An organization needs at least one owner.")
        }
        if try await twoPersonRequired() {
            let change = try await PendingChanges(db: db, ctx: ctx).request(businessId: businessId, kind: .roleGrant, by: principal.user.id!,
                payload: PendingChanges.Payload(operation: "change", role: newRole.rawValue, membershipId: membershipId.uuidString.lowercased()))
            return .awaitingApproval(change.id!)
        }
        try await applyRoleChange(member, to: newRole, by: principal.user.id!)
        return .done
    }

    func applyRoleChange(_ member: OrgMembershipRecord, to newRole: OrgRole, by userId: UUID) async throws {
        let current = OrgRole(rawValue: member.role)
        member.role = newRole.rawValue
        try await member.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("team.role_changed", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "user", subjectId: member.userId.uuidString.lowercased(),
            metadata: ["from": current?.rawValue ?? "", "to": newRole.rawValue])
        // The member's sessions keep working but their role is read fresh on every request.
        await alert(.roleChanges, subject: "A team role changed", text: "A team member's role in your organization changed to \(newRole.title).")
    }

    func removeMember(membershipId: UUID) async throws {
        try require(.manageTeam)
        let member = try await membership(membershipId)
        let current = OrgRole(rawValue: member.role)
        guard member.userId != principal.user.id else { throw APIError.conflict("Ask another owner or admin to remove you.") }
        try await authorize(roleChangeTo: nil, current: current ?? .analyst)
        if current == .owner, try await ownerCount(excluding: membershipId) == 0 { throw APIError.conflict("An organization needs at least one owner.") }
        member.removedAt = ctx.now
        try await member.update(on: db)
        // Sessions acting for this organization end now.
        try await DashboardSessionRecord.query(on: db).filter(\.$userId == member.userId).filter(\.$businessId == businessId)
            .filter(\.$revokedAt == nil).set(\.$revokedAt, to: ctx.now).update()
        try await audit("team.member_removed", subjectType: "user", subjectId: member.userId.uuidString.lowercased(), metadata: ["role": member.role])
        await alert(.roleChanges, subject: "A team member was removed", text: "A member (role: \(current?.title ?? "unknown")) was removed from your organization.")
    }

    /// Executes an approved role grant (called by the approver's request, on behalf of the requester).
    func executeRoleGrant(_ payload: PendingChanges.Payload, requester: UUID) async throws {
        guard let raw = payload.role, let role = OrgRole(rawValue: raw) else { throw APIError.internalError }
        if payload.operation == "invite", let email = payload.email {
            try await createInvite(email: email, role: role, invitedBy: requester)
        } else if payload.operation == "change", let raw = payload.membershipId, let id = UUID(uuidString: raw) {
            let member = try await membership(id)
            if let current = OrgRole(rawValue: member.role), current == .owner, role != .owner, try await ownerCount(excluding: id) == 0 {
                throw APIError.conflict("An organization needs at least one owner.")
            }
            try await applyRoleChange(member, to: role, by: requester)
        }
    }

    /// A signed-in user accepts an invitation addressed to their own email.
    static func acceptInvite(token: String, principal: DashboardPrincipal, db: any Database, ctx: ServerContext) async throws -> UUID {
        // Defence in depth: an account whose address is not verified never accepts an invitation (it cannot hold a session either).
        guard principal.user.status == "active", let invite = try await DashboardAuthService(db: db, ctx: ctx).openInvite(token: token),
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
