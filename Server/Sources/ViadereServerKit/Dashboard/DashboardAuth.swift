import Fluent
import Foundation
import Vapor
import ViadereCore

enum DashboardResponses {
    /// 303 See Other to a fixed, server-chosen path (never to user input, so there is no open redirect).
    static func redirect(_ path: String) -> Response {
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: .location, value: path)
        return response
    }

    static func json(status: HTTPStatus = .ok, _ object: [String: Any]) -> Response {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data("{}".utf8)
        let response = Response(status: status, body: .init(data: data))
        response.headers.contentType = .json
        return response
    }
}

struct SignupBeginBody: Codable {
    var email: String
    var displayName: String
    var organizationName: String
    var category: String?
    var legalName: String?
    var website: String?
    var requestedHandle: String?
    var description: String?
}

struct InviteBeginBody: Codable {
    var token: String
    var displayName: String
}

struct EnrollBeginBody: Codable {
    var token: String
}

/// WebAuthn ceremonies for the dashboard and operator console. Credentials, users and sessions are separate from
/// consumers'. The relying party ID is shared with the consumer app (`viadere.com`); the verifier used here may
/// be bound to a different *origin* (`DASHBOARD_ORIGIN`, e.g. `https://business.viadere.com`) so a dashboard on a
/// sub-domain still verifies, and a business passkey can never mint a consumer session or vice versa (different
/// credential tables, different session realms).
struct DashboardAuthService {
    let db: any Database
    let ctx: ServerContext

    static let ceremonyTTL: TimeInterval = 5 * 60
    static let categories = ["retail", "banking", "airline", "hospitality", "food_and_drink", "healthcare", "utilities", "telecom",
                             "government", "other"]

    private var store: DashboardSessionStore { DashboardSessionStore(db: db, ctx: ctx) }
    private var verifier: any PasskeyVerifier { ctx.dashboardPasskeys }

    // MARK: Helpers

    static func normalizeEmail(_ raw: String) -> String? {
        let email = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard email.count >= 6, email.count <= 254, email.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 0x20 && $0.value < 0x7F }),
              email.filter({ $0 == "@" }).count == 1 else { return nil }
        let parts = email.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, parts[0].count <= 64, parts[1].contains("."), !parts[1].hasPrefix("."),
              !parts[1].hasSuffix("."), !parts[1].contains("..") else { return nil }
        return email
    }

    func emailHash(_ email: String) -> String { ctx.hasher.hmacHex("dashboard-email", email) }

    func cleanName(_ raw: String, max: Int, min: Int = 1) -> String? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.count >= min, value.count <= max, !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return value
    }

    private func newCeremony(kind: String, userId: UUID?, payload: String?) async throws -> (DashboardCeremonyRecord, Data) {
        let challenge = verifier.makeChallenge()
        let record = DashboardCeremonyRecord()
        record.id = UUID()
        record.kind = kind
        record.challenge = Base64URL.encode(challenge)
        record.userId = userId
        record.payloadJSON = payload
        record.state = "open"
        record.createdAt = ctx.now
        record.expiresAt = ctx.now.addingTimeInterval(Self.ceremonyTTL)
        try await record.create(on: db)
        return (record, challenge)
    }

    /// Consumes a ceremony exactly once; unknown, expired, used and wrong-kind ceremonies are indistinguishable.
    private func consume(_ id: CeremonyID, kind: String) async throws -> DashboardCeremonyRecord {
        guard let ceremony = try await DashboardCeremonyRecord.find(id.uuid, on: db), ceremony.kind == kind, ceremony.state == "open",
              ceremony.expiresAt > ctx.now,
              try await DB.swap(db, table: DashboardCeremonyRecord.schema, id: id.uuid, column: "state", expected: "open", newValue: "used")
        else { throw APIError.unauthorized }
        return ceremony
    }

    private func registrationOptions(_ ceremony: DashboardCeremonyRecord, challenge: Data, handle: String, email: String,
                                     displayName: String) -> PasskeyRegistrationOptions {
        PasskeyRegistrationOptions(ceremonyId: CeremonyID(ceremony.id!), challenge: Base64URL.encode(challenge),
                                   relyingPartyId: ctx.config.relyingPartyID, relyingPartyName: ctx.config.relyingPartyName, userId: handle,
                                   userName: email, userDisplayName: displayName, timeoutMilliseconds: Int(Self.ceremonyTTL * 1000))
    }

    private func verifyRegistration(_ finish: PasskeyRegistrationFinishRequest, ceremony: DashboardCeremonyRecord) async throws -> VerifiedPasskeyRegistration {
        guard let challenge = Base64URL.decode(ceremony.challenge) else { throw APIError.unauthorized }
        let database = db
        do {
            return try await verifier.verifyRegistration(finish.credential, challenge: challenge) { credentialId in
                try await DashboardPasskeyRecord.query(on: database).filter(\.$credentialId == credentialId).count() > 0
            }
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("dashboard.register_failed", outcome: .failure, actor: AuditActor(kind: .system))
            throw APIError(.unauthorized, .unauthorized, "Passkey registration could not be verified.")
        }
    }

    private func savePasskey(_ verified: VerifiedPasskeyRegistration, userId: UUID, on tx: any Database) async throws {
        let passkey = DashboardPasskeyRecord()
        passkey.id = UUID()
        passkey.userId = userId
        passkey.credentialId = verified.credentialId
        passkey.publicKey = Base64URL.encode(verified.publicKey)
        passkey.signCount = Int(verified.signCount)
        passkey.backupEligible = verified.backupEligible
        passkey.createdAt = ctx.now
        try await passkey.create(on: tx)
    }

    private func makeUser(kind: String, email: String, displayName: String, handle: String, status: String, id: UUID = UUID()) throws -> DashboardUserRecord {
        let user = DashboardUserRecord()
        user.id = id
        user.kind = kind
        user.emailHash = emailHash(email)
        user.emailCiphertext = try ctx.cipher.seal(email, context: "dashboard_users.email")
        user.displayName = displayName
        user.userHandle = handle
        user.status = status
        user.createdAt = ctx.now
        return user
    }

    // MARK: Sign-up (creates a user, a *pending* organization and an application)

    func signupBegin(_ body: SignupBeginBody, ip: String) async throws -> PasskeyRegistrationOptions {
        guard let email = Self.normalizeEmail(body.email), let name = cleanName(body.displayName, max: 64),
              let org = cleanName(body.organizationName, max: 80, min: 2) else {
            throw APIError.validation("Enter a valid email, your name and your organization's name.", details: ["form": "invalid"])
        }
        let category = body.category.flatMap { Self.categories.contains($0) ? $0 : nil } ?? "other"
        var website: String?
        if let raw = body.website?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            guard raw.count <= 200, let url = URL(string: raw), url.scheme == "https", url.host?.contains(".") == true, url.user == nil else {
                throw APIError.validation("The website must be an https URL.", details: ["website": "invalid"])
            }
            website = raw
        }
        var handle: String?
        if let raw = body.requestedHandle?.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "@", with: ""), !raw.isEmpty {
            guard let valid = try? BusinessHandle.validateForRegistration(raw) else {
                throw APIError.validation("That handle can't be used. Use 3–30 letters, digits or underscores, starting with a letter.",
                                          details: ["requestedHandle": "invalid"])
            }
            handle = valid.value
        }
        let legal = body.legalName.flatMap { cleanName($0, max: 120) }
        let detail = body.description.flatMap { cleanName($0, max: 500) }
        try await ctx.limiter.enforce("dashboard-signup-email", key: emailHash(email), rule: .perHour(5, burst: 5))
        if try await DashboardUserRecord.query(on: db).filter(\.$emailHash == emailHash(email)).count() > 0 {
            throw APIError.conflict("An account with this email already exists. Sign in instead.")
        }
        let userHandle = SecureToken.generate(byteCount: 32)
        let payload = SignupPayload(email: email, displayName: name, organizationName: org, category: category, legalName: legal,
                                    website: website, requestedHandle: handle, description: detail, userHandle: userHandle)
        let json = String(decoding: try JSONEncoder().encode(payload), as: UTF8.self)
        let (ceremony, challenge) = try await newCeremony(kind: "signup", userId: nil, payload: try ctx.cipher.seal(json, context: "dashboard_ceremonies.payload"))
        return registrationOptions(ceremony, challenge: challenge, handle: userHandle, email: email, displayName: name)
    }

    struct SignupPayload: Codable {
        var email: String
        var displayName: String
        var organizationName: String
        var category: String
        var legalName: String?
        var website: String?
        var requestedHandle: String?
        var description: String?
        var userHandle: String
    }

    func signupFinish(_ finish: PasskeyRegistrationFinishRequest, previousCookie: String?) async throws -> DashboardSessionStore.Created {
        let ceremony = try await consume(finish.ceremonyId, kind: "signup")
        guard let sealed = ceremony.payloadJSON, let data = try? ctx.cipher.open(sealed, context: "dashboard_ceremonies.payload"),
              let payload = try? JSONDecoder().decode(SignupPayload.self, from: data) else { throw APIError.unauthorized }
        let verified = try await verifyRegistration(finish, ceremony: ceremony)
        let userId = UUID()
        let businessId = UUID()
        do {
            try await db.transaction { tx in
                try await makeUser(kind: "business", email: payload.email, displayName: payload.displayName, handle: payload.userHandle,
                                   status: "active", id: userId).create(on: tx)
                try await savePasskey(verified, userId: userId, on: tx)
                _ = try await BusinessOnboarding(db: tx, ctx: ctx).createPending(
                    businessId: businessId, ownerId: userId, displayName: payload.organizationName, legalName: payload.legalName,
                    category: BusinessCategory(rawValue: payload.category), website: payload.website, requestedHandle: payload.requestedHandle,
                    description: payload.description)
                _ = try await AuditService(db: tx, ctx: ctx).record("dashboard.registered", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
                    businessId: BusinessID(businessId), subjectType: "organization", subjectId: businessId.uuidString.lowercased())
            }
        } catch {
            if error.isConstraintViolation { throw APIError.conflict("An account with this email already exists. Sign in instead.") }
            throw error
        }
        return try await store.create(userId: userId, realm: .business, businessId: businessId, replacing: previousCookie)
    }

    // MARK: Sign-in

    func loginBegin(realm: DashboardRealm) async throws -> PasskeyAssertionOptions {
        let (ceremony, challenge) = try await newCeremony(kind: "login:\(realm.rawValue)", userId: nil, payload: nil)
        return PasskeyAssertionOptions(ceremonyId: CeremonyID(ceremony.id!), challenge: Base64URL.encode(challenge),
                                       relyingPartyId: ctx.config.relyingPartyID, allowCredentialIds: [], timeoutMilliseconds: Int(Self.ceremonyTTL * 1000))
    }

    /// The user handle returned by authenticators is the bytes we registered (the UTF-8 of the handle string).
    private func handleMatches(_ supplied: String, stored: String) -> Bool {
        if ConstantTime.equals(supplied, stored) { return true }
        if let bytes = Base64URL.decode(supplied), let text = String(data: bytes, encoding: .utf8) { return ConstantTime.equals(text, stored) }
        return false
    }

    func loginFinish(realm: DashboardRealm, _ finish: PasskeyLoginFinishRequest, previousCookie: String?) async throws -> DashboardSessionStore.Created {
        let ceremony = try await consume(finish.ceremonyId, kind: "login:\(realm.rawValue)")
        let failure = APIError(.unauthorized, .unauthorized, "Sign-in could not be verified.")
        let audit = AuditService(db: db, ctx: ctx)
        guard let challenge = Base64URL.decode(ceremony.challenge), finish.credential.id.count <= 1024,
              let credential = try await DashboardPasskeyRecord.query(on: db).filter(\.$credentialId == finish.credential.id).first(),
              let user = try await DashboardUserRecord.find(credential.userId, on: db), user.status == "active",
              user.isOperator == (realm == .operator), let publicKey = Base64URL.decode(credential.publicKey) else {
            _ = try? await audit.record("dashboard.login_failed", outcome: .failure, actor: AuditActor(kind: .system),
                                        metadata: ["reason": "unknown_credential", "realm": realm.rawValue])
            throw failure
        }
        if let handle = finish.credential.userHandle, !handleMatches(handle, stored: user.userHandle) { throw failure }
        let actorKind: AuditActor.Kind = realm == .operator ? .operator_ : .business
        do {
            let result = try verifier.verifyAssertion(finish.credential, challenge: challenge, publicKey: publicKey, signCount: UInt32(clamping: credential.signCount))
            credential.signCount = Int(result.newSignCount)
            credential.lastUsedAt = ctx.now
            try await credential.update(on: db)
        } catch {
            _ = try? await audit.record("dashboard.login_failed", outcome: .failure, actor: AuditActor(kind: actorKind, id: user.id?.uuidString.lowercased()),
                                        metadata: ["reason": "assertion_invalid", "realm": realm.rawValue])
            throw failure
        }
        var businessId: UUID?
        if realm == .business {
            // Land in the organization the user joined first; without a live membership there is nothing to sign in to.
            guard let membership = try await OrgMembershipRecord.query(on: db).filter(\.$userId == user.id!).filter(\.$removedAt == nil)
                .sort(\.$createdAt, .ascending).first() else { throw failure }
            businessId = membership.businessId
        }
        user.lastLoginAt = ctx.now
        try await user.update(on: db)
        let created = try await store.create(userId: user.id!, realm: realm, businessId: businessId, replacing: previousCookie)
        _ = try await audit.record("dashboard.login", actor: AuditActor(kind: actorKind, id: user.id?.uuidString.lowercased()),
                                   businessId: businessId.map(BusinessID.init), metadata: ["realm": realm.rawValue])
        return created
    }

    // MARK: Re-authentication (sensitive actions)

    func reauthBegin(_ principal: DashboardPrincipal) async throws -> PasskeyAssertionOptions {
        let credentials = try await DashboardPasskeyRecord.query(on: db).filter(\.$userId == principal.user.id!).all().map(\.credentialId)
        let (ceremony, challenge) = try await newCeremony(kind: "reauth:\(principal.realm.rawValue)", userId: principal.user.id, payload: nil)
        return PasskeyAssertionOptions(ceremonyId: CeremonyID(ceremony.id!), challenge: Base64URL.encode(challenge),
                                       relyingPartyId: ctx.config.relyingPartyID, allowCredentialIds: credentials, timeoutMilliseconds: Int(Self.ceremonyTTL * 1000))
    }

    func reauthFinish(_ principal: DashboardPrincipal, _ finish: PasskeyLoginFinishRequest) async throws {
        let ceremony = try await consume(finish.ceremonyId, kind: "reauth:\(principal.realm.rawValue)")
        let failure = APIError(.unauthorized, .unauthorized, "Confirmation could not be verified.")
        // The assertion must come from a passkey owned by *this* user, on a ceremony minted for *this* user.
        guard ceremony.userId == principal.user.id, let challenge = Base64URL.decode(ceremony.challenge), finish.credential.id.count <= 1024,
              let credential = try await DashboardPasskeyRecord.query(on: db).filter(\.$credentialId == finish.credential.id)
                  .filter(\.$userId == principal.user.id!).first(), let publicKey = Base64URL.decode(credential.publicKey) else { throw failure }
        let actorKind: AuditActor.Kind = principal.realm == .operator ? .operator_ : .business
        do {
            let result = try verifier.verifyAssertion(finish.credential, challenge: challenge, publicKey: publicKey, signCount: UInt32(clamping: credential.signCount))
            credential.signCount = Int(result.newSignCount)
            credential.lastUsedAt = ctx.now
            try await credential.update(on: db)
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("dashboard.reauth_failed", outcome: .failure,
                actor: AuditActor(kind: actorKind, id: principal.user.id?.uuidString.lowercased()), businessId: principal.business?.id.map(BusinessID.init))
            throw failure
        }
        principal.session.reauthAt = ctx.now
        try await principal.session.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("dashboard.reauth", actor: AuditActor(kind: actorKind, id: principal.user.id?.uuidString.lowercased()),
                                                          businessId: principal.business?.id.map(BusinessID.init))
    }

    // MARK: Invitations

    func inviteBegin(_ body: InviteBeginBody) async throws -> PasskeyRegistrationOptions {
        guard let name = cleanName(body.displayName, max: 64), let invite = try await openInvite(token: body.token) else {
            throw APIError.validation("This invitation is not valid.", details: ["token": "invalid"])
        }
        let email = try ctx.cipher.openString(invite.emailCiphertext, context: "org_invites.email")
        guard try await DashboardUserRecord.query(on: db).filter(\.$emailHash == invite.emailHash).count() == 0 else {
            throw APIError.conflict("An account with this email already exists. Sign in, then accept the invitation.")
        }
        let handle = SecureToken.generate(byteCount: 32)
        let payload = String(decoding: try JSONEncoder().encode(["inviteId": invite.id!.uuidString, "displayName": name, "userHandle": handle]), as: UTF8.self)
        let (ceremony, challenge) = try await newCeremony(kind: "invite", userId: nil, payload: try ctx.cipher.seal(payload, context: "dashboard_ceremonies.payload"))
        return registrationOptions(ceremony, challenge: challenge, handle: handle, email: email, displayName: name)
    }

    func openInvite(token: String) async throws -> OrgInviteRecord? {
        guard Base64URL.isValid(token, minLength: 20, maxLength: 64),
              let invite = try await OrgInviteRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(token)).first(),
              invite.state == "open", invite.expiresAt > ctx.now,
              try await BusinessRecord.find(invite.businessId, on: db) != nil else { return nil }
        return invite
    }

    func inviteFinish(_ finish: PasskeyRegistrationFinishRequest, previousCookie: String?) async throws -> DashboardSessionStore.Created {
        let ceremony = try await consume(finish.ceremonyId, kind: "invite")
        guard let sealed = ceremony.payloadJSON, let data = try? ctx.cipher.open(sealed, context: "dashboard_ceremonies.payload"),
              let payload = try? JSONDecoder().decode([String: String].self, from: data), let inviteIdText = payload["inviteId"],
              let inviteId = UUID(uuidString: inviteIdText), let name = payload["displayName"], let handle = payload["userHandle"],
              let invite = try await OrgInviteRecord.find(inviteId, on: db), invite.state == "open", invite.expiresAt > ctx.now,
              let email = try? ctx.cipher.openString(invite.emailCiphertext, context: "org_invites.email") else { throw APIError.unauthorized }
        let verified = try await verifyRegistration(finish, ceremony: ceremony)
        let userId = UUID()
        try await db.transaction { tx in
            // Single use: exactly one acceptance can flip open → accepted.
            guard try await DB.swap(tx, table: OrgInviteRecord.schema, id: inviteId, column: "state", expected: "open", newValue: "accepted",
                                    extra: [("accepted_at", ctx.now)]) else { throw APIError.unauthorized }
            try await makeUser(kind: "business", email: email, displayName: name, handle: handle, status: "active", id: userId).create(on: tx)
            try await savePasskey(verified, userId: userId, on: tx)
            let membership = OrgMembershipRecord()
            membership.id = UUID()
            membership.businessId = invite.businessId
            membership.userId = userId
            membership.role = invite.role
            membership.createdAt = ctx.now
            try await membership.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("team.invite_accepted", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
                businessId: BusinessID(invite.businessId), subjectType: "user", subjectId: userId.uuidString.lowercased(), metadata: ["role": invite.role])
        }
        return try await store.create(userId: userId, realm: .business, businessId: invite.businessId, replacing: previousCookie)
    }

    // MARK: Operator enrollment

    func enrollBegin(_ body: EnrollBeginBody) async throws -> PasskeyRegistrationOptions {
        guard let enrollment = try await openEnrollment(token: body.token), let user = try await DashboardUserRecord.find(enrollment.userId, on: db) else {
            throw APIError.validation("This enrollment link is not valid.", details: ["token": "invalid"])
        }
        let email = try ctx.cipher.openString(user.emailCiphertext, context: "dashboard_users.email")
        let payload = String(decoding: try JSONEncoder().encode(["enrollmentId": enrollment.id!.uuidString]), as: UTF8.self)
        let (ceremony, challenge) = try await newCeremony(kind: "enroll", userId: user.id, payload: payload)
        return registrationOptions(ceremony, challenge: challenge, handle: user.userHandle, email: email, displayName: user.displayName)
    }

    func openEnrollment(token: String) async throws -> OperatorEnrollmentRecord? {
        guard Base64URL.isValid(token, minLength: 20, maxLength: 64),
              let enrollment = try await OperatorEnrollmentRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(token)).first(),
              enrollment.state == "open", enrollment.expiresAt > ctx.now else { return nil }
        return enrollment
    }

    func enrollFinish(_ finish: PasskeyRegistrationFinishRequest, previousCookie: String?) async throws -> DashboardSessionStore.Created {
        let ceremony = try await consume(finish.ceremonyId, kind: "enroll")
        guard let json = ceremony.payloadJSON, let payload = try? JSONDecoder().decode([String: String].self, from: Data(json.utf8)),
              let idText = payload["enrollmentId"], let enrollmentId = UUID(uuidString: idText),
              let enrollment = try await OperatorEnrollmentRecord.find(enrollmentId, on: db), enrollment.state == "open",
              enrollment.expiresAt > ctx.now, ceremony.userId == enrollment.userId,
              let user = try await DashboardUserRecord.find(enrollment.userId, on: db), user.isOperator else { throw APIError.unauthorized }
        let verified = try await verifyRegistration(finish, ceremony: ceremony)
        try await db.transaction { tx in
            guard try await DB.swap(tx, table: OperatorEnrollmentRecord.schema, id: enrollmentId, column: "state", expected: "open", newValue: "used")
            else { throw APIError.unauthorized }
            try await savePasskey(verified, userId: user.id!, on: tx)
            user.status = "active"
            try await user.update(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("operator.enrolled", actor: AuditActor(kind: .operator_, id: user.id?.uuidString.lowercased()))
        }
        return try await store.create(userId: user.id!, realm: .operator, businessId: nil, replacing: previousCookie)
    }

    /// Creates a pending operator and a one-time enrollment token (shown once by the `create-operator` command).
    func createOperator(email rawEmail: String, displayName: String) async throws -> String {
        guard let email = Self.normalizeEmail(rawEmail), let name = cleanName(displayName, max: 64) else { throw APIError.validation("Invalid operator details.") }
        let userId = UUID()
        let token = SecureToken.generate()
        try await db.transaction { tx in
            try await makeUser(kind: "operator", email: email, displayName: name, handle: SecureToken.generate(byteCount: 32), status: "pending", id: userId).create(on: tx)
            let enrollment = OperatorEnrollmentRecord()
            enrollment.id = UUID()
            enrollment.userId = userId
            enrollment.tokenHash = SecureToken.hash(token)
            enrollment.state = "open"
            enrollment.createdAt = ctx.now
            enrollment.expiresAt = ctx.now.addingTimeInterval(ctx.config.dashboard.operatorEnrollmentTTL)
            try await enrollment.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("operator.created", actor: AuditActor(kind: .system), subjectType: "operator", subjectId: userId.uuidString.lowercased())
        }
        return ctx.config.publicBaseURL + "/operator/enroll/" + token
    }
}
