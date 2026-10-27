import Fluent
import Foundation
import ViadereCore

/// Passkey registration/login, session rotation and device enrollment.
struct AuthService {
    let db: any Database
    let ctx: ServerContext

    static let ceremonyTTL: TimeInterval = 5 * 60
    static let enrollChallengeTTL: TimeInterval = 5 * 60
    static let maxDevicesPerConsumer = 10

    private var tokens: ConsumerTokenService { ConsumerTokenService(db: db, ctx: ctx) }

    private func session(consumerId: UUID, issued: ConsumerTokenService.IssuedSession) -> AuthSession {
        AuthSession(consumerId: ConsumerID(consumerId), accessToken: issued.accessToken, expiresAt: issued.accessExpiresAt,
                    refreshToken: issued.refreshToken, refreshExpiresAt: issued.refreshExpiresAt)
    }

    // MARK: Passkey registration

    func registerBegin(_ request: PasskeyRegistrationBeginRequest) async throws -> PasskeyRegistrationOptions {
        let name = request.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 64, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("A display name of up to 64 characters is required.", details: ["displayName": "invalid"])
        }
        let challenge = ctx.passkeys.makeChallenge()
        let consumerId = UUID()
        let handle = SecureToken.generate(byteCount: 32)
        let ceremony = PasskeyCeremonyRecord(kind: "register", challenge: Base64URL.encode(challenge), consumerId: consumerId,
                                             displayName: name, userHandle: handle, now: ctx.now, ttl: Self.ceremonyTTL)
        try await ceremony.create(on: db)
        return PasskeyRegistrationOptions(
            ceremonyId: CeremonyID(ceremony.id!), challenge: Base64URL.encode(challenge), relyingPartyId: ctx.config.relyingPartyID,
            relyingPartyName: ctx.config.relyingPartyName, userId: handle, userName: name, userDisplayName: name,
            timeoutMilliseconds: Int(Self.ceremonyTTL * 1000))
    }

    /// Consumes a ceremony exactly once. Unknown, expired, already-used or wrong-kind ceremonies are indistinguishable.
    private func consumeCeremony(_ id: CeremonyID, kind: String) async throws -> PasskeyCeremonyRecord {
        guard let ceremony = try await PasskeyCeremonyRecord.find(id.uuid, on: db), ceremony.kind == kind, ceremony.state == "open",
              ceremony.expiresAt > ctx.now else { throw APIError.unauthorized }
        guard try await DB.swap(db, table: PasskeyCeremonyRecord.schema, id: id.uuid, column: "state", expected: "open", newValue: "used")
        else { throw APIError.unauthorized }
        return ceremony
    }

    func registerFinish(_ request: PasskeyRegistrationFinishRequest) async throws -> AuthSession {
        let ceremony = try await consumeCeremony(request.ceremonyId, kind: "register")
        guard let challenge = Base64URL.decode(ceremony.challenge), let consumerId = ceremony.consumerId,
              let name = ceremony.displayName, let handle = ceremony.userHandle else { throw APIError.unauthorized }
        let verified: VerifiedPasskeyRegistration
        let database = db
        do {
            verified = try await ctx.passkeys.verifyRegistration(request.credential, challenge: challenge) { credentialId in
                try await PasskeyCredentialRecord.query(on: database).filter(\.$credentialId == credentialId).count() > 0
            }
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth.register_failed", outcome: .failure, actor: AuditActor(kind: .system))
            throw APIError(.unauthorized, .unauthorized, "Passkey registration could not be verified.")
        }
        let now = ctx.now
        let issued: ConsumerTokenService.IssuedSession = try await db.transaction { tx in
            try await ConsumerRecord(id: consumerId, displayName: name, userHandle: handle, now: now).create(on: tx)
            try await PasskeyCredentialRecord(consumerId: consumerId, credentialId: verified.credentialId,
                                              publicKey: Base64URL.encode(verified.publicKey), signCount: Int(verified.signCount),
                                              backupEligible: verified.backupEligible, now: now).create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("auth.registered", actor: AuditActor(kind: .consumer, id: ConsumerID(consumerId).description),
                                                               consumerId: ConsumerID(consumerId))
            return try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: consumerId)
        }
        return session(consumerId: consumerId, issued: issued)
    }

    // MARK: Passkey login

    func loginBegin() async throws -> PasskeyAssertionOptions {
        let challenge = ctx.passkeys.makeChallenge()
        let ceremony = PasskeyCeremonyRecord(kind: "login", challenge: Base64URL.encode(challenge), consumerId: nil, displayName: nil,
                                             userHandle: nil, now: ctx.now, ttl: Self.ceremonyTTL)
        try await ceremony.create(on: db)
        return PasskeyAssertionOptions(ceremonyId: CeremonyID(ceremony.id!), challenge: Base64URL.encode(challenge),
                                       relyingPartyId: ctx.config.relyingPartyID, allowCredentialIds: [],
                                       timeoutMilliseconds: Int(Self.ceremonyTTL * 1000))
    }

    func loginFinish(_ request: PasskeyLoginFinishRequest) async throws -> AuthSession {
        let ceremony = try await consumeCeremony(request.ceremonyId, kind: "login")
        let failure = APIError(.unauthorized, .unauthorized, "Sign-in could not be verified.")
        guard let challenge = Base64URL.decode(ceremony.challenge), request.credential.id.count <= 1024,
              let credential = try await PasskeyCredentialRecord.query(on: db).filter(\.$credentialId == request.credential.id).first(),
              let consumer = try await ConsumerRecord.find(credential.consumerId, on: db), consumer.status == "active",
              let publicKey = Base64URL.decode(credential.publicKey) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth.login_failed", outcome: .failure, actor: AuditActor(kind: .system),
                                                                metadata: ["reason": "unknown_credential"])
            throw failure
        }
        // For discoverable credentials the authenticator returns the user handle; it must match the credential's owner.
        if let handle = request.credential.userHandle, !ConstantTime.equals(handle, consumer.userHandle) { throw failure }
        do {
            let result = try ctx.passkeys.verifyAssertion(request.credential, challenge: challenge, publicKey: publicKey,
                                                         signCount: UInt32(clamping: credential.signCount))
            credential.signCount = Int(result.newSignCount)
            credential.lastUsedAt = ctx.now
            try await credential.update(on: db)
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth.login_failed", outcome: .failure,
                actor: AuditActor(kind: .consumer, id: ConsumerID(consumer.id!).description), consumerId: ConsumerID(consumer.id!),
                metadata: ["reason": "assertion_invalid"])
            throw failure
        }
        let issued: ConsumerTokenService.IssuedSession = try await db.transaction { tx in
            _ = try await AuditService(db: tx, ctx: ctx).record("auth.login", actor: AuditActor(kind: .consumer, id: ConsumerID(consumer.id!).description),
                                                               consumerId: ConsumerID(consumer.id!))
            return try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: consumer.id!)
        }
        return session(consumerId: consumer.id!, issued: issued)
    }

    // MARK: Refresh / logout

    func refresh(_ request: AuthRefreshRequest) async throws -> AuthSession {
        do {
            let result = try await tokens.rotate(refreshToken: request.refreshToken)
            return session(consumerId: result.consumerId, issued: result.session)
        } catch ConsumerTokenService.RefreshFailure.reuseDetected(let consumerId, let familyId) {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth.refresh_reuse_detected", outcome: .denied,
                actor: AuditActor(kind: .system), consumerId: ConsumerID(consumerId), subjectType: "token_family",
                subjectId: familyId.uuidString.lowercased(), metadata: ["reason": "family_revoked"])
            throw APIError(.unauthorized, .unauthorized, "This session is no longer valid. Please sign in again.")
        } catch is ConsumerTokenService.RefreshFailure {
            throw APIError(.unauthorized, .unauthorized, "This session is no longer valid. Please sign in again.")
        }
    }

    func logout(_ principal: ConsumerPrincipal) async throws {
        try await tokens.revokeFamily(principal.familyId, now: ctx.now)
        _ = try await AuditService(db: db, ctx: ctx).record("auth.logout", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                                                           consumerId: principal.consumerId)
    }

    // MARK: Devices

    func enrollBegin(_ principal: ConsumerPrincipal) async throws -> DeviceEnrollmentChallenge {
        let challenge = SecureToken.generate()
        let expires = ctx.now.addingTimeInterval(Self.enrollChallengeTTL)
        try await DeviceEnrollChallengeRecord(consumerId: principal.consumerId.uuid, challengeHash: SecureToken.hash(challenge),
                                              expiresAt: expires).create(on: db)
        return DeviceEnrollmentChallenge(challenge: challenge, expiresAt: expires)
    }

    func deviceDTO(_ device: DeviceRecord, keys: [DeviceKeyRecord]) -> Device {
        let keyDTOs: [DeviceKey] = keys.compactMap { key in
            guard let purpose = DeviceKeyPurpose(rawValue: key.purpose), let publicKey = try? DevicePublicKey(base64URL: key.publicKey),
                  let id = key.id else { return nil }
            return DeviceKey(id: DeviceKeyID(id), purpose: purpose, publicKey: publicKey, hardwareBacked: key.hardwareBacked,
                             createdAt: key.createdAt)
        }
        return Device(id: DeviceID(device.id!), consumerId: ConsumerID(device.consumerId), name: device.name,
                      platform: DevicePlatform(rawValue: device.platform) ?? .iOS, keys: keyDTOs, createdAt: device.createdAt,
                      lastSeenAt: device.lastSeenAt, revokedAt: device.revokedAt)
    }

    func enroll(_ principal: ConsumerPrincipal, request: DeviceEnrollRequest) async throws -> Device {
        let name = request.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 64 else { throw APIError.validation("A device name of up to 64 characters is required.", details: ["name": "invalid"]) }
        let purposes = request.keys.map(\.purpose)
        guard purposes.contains(.request), Set(purposes).count == purposes.count, request.keys.count <= DeviceKeyPurpose.allCases.count else {
            throw APIError.validation("Provide exactly one key per purpose, including a request key.", details: ["keys": "invalid"])
        }
        let existing = try await DeviceRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$revokedAt == nil).count()
        guard existing < Self.maxDevicesPerConsumer else { throw APIError.conflict("Too many devices are enrolled. Revoke one first.") }
        // Proof of possession for every key, over the server's single-use challenge.
        guard request.challenge.count <= 128, let challengeRecord = try await DeviceEnrollChallengeRecord.query(on: db)
            .filter(\.$challengeHash == SecureToken.hash(request.challenge)).filter(\.$consumerId == principal.consumerId.uuid).first(),
              challengeRecord.state == "open", challengeRecord.expiresAt > ctx.now else {
            throw APIError(.unauthorized, .unauthorized, "The enrollment challenge is invalid or expired.")
        }
        for key in request.keys where !DeviceEnrollment.verify(key, consumerId: principal.consumerId, challenge: request.challenge) {
            _ = try? await AuditService(db: db, ctx: ctx).record("device.enroll_failed", outcome: .failure, actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                                                                consumerId: principal.consumerId, metadata: ["reason": "bad_proof", "purpose": key.purpose.rawValue])
            throw APIError(.unauthorized, .signatureInvalid, "Key proof of possession failed.")
        }
        guard try await DB.swap(db, table: DeviceEnrollChallengeRecord.schema, id: challengeRecord.id!, column: "state", expected: "open", newValue: "used")
        else { throw APIError(.unauthorized, .unauthorized, "The enrollment challenge is invalid or expired.") }
        let now = ctx.now
        let device = DeviceRecord(consumerId: principal.consumerId.uuid, name: name, platform: request.platform, now: now)
        let keyRecords = request.keys.map { DeviceKeyRecord(deviceId: device.id!, purpose: $0.purpose, publicKey: $0.publicKey,
                                                           hardwareBacked: $0.hardwareBacked, now: now) }
        try await db.transaction { tx in
            try await device.create(on: tx)
            for key in keyRecords { try await key.create(on: tx) }
            _ = try await AuditService(db: tx, ctx: ctx).record("device.enrolled", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                consumerId: principal.consumerId, subjectType: "device", subjectId: DeviceID(device.id!).description,
                metadata: ["platform": request.platform.rawValue, "max_assurance": Device.maxAssurance(keys: request.keys).rawValue])
        }
        return deviceDTO(device, keys: keyRecords)
    }

    func devices(for consumer: ConsumerID) async throws -> [Device] {
        let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumer.uuid).sort(\.$createdAt, .ascending).all()
        let keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).all()
        return devices.map { device in deviceDTO(device, keys: keys.filter { $0.deviceId == device.id }) }
    }

    func revoke(_ principal: ConsumerPrincipal, deviceId: DeviceID) async throws {
        guard let device = try await DeviceRecord.query(on: db).filter(\.$id == deviceId.uuid)
            .filter(\.$consumerId == principal.consumerId.uuid).first() else { throw APIError.notFound }
        guard device.revokedAt == nil else { return }
        let now = ctx.now
        try await db.transaction { tx in
            device.revokedAt = now
            try await device.update(on: tx)
            try await APNsTokenRecord.query(on: tx).filter(\.$deviceId == deviceId.uuid).delete()
            _ = try await AuditService(db: tx, ctx: ctx).record("device.revoked", principal: principal, subjectType: "device", subjectId: deviceId.description)
        }
    }
}

extension Device {
    /// Highest assurance for a set of enrollment keys (mirrors `Device.maxAssurance(for:)`).
    static func maxAssurance(keys: [DeviceKeyRegistration]) -> DecisionAssurance {
        let purposes = Set(keys.map(\.purpose))
        if purposes.contains(.approvalBiometric) { return .biometric }
        if purposes.contains(.approvalUserPresence) { return .devicePasscode }
        return .none
    }
}
