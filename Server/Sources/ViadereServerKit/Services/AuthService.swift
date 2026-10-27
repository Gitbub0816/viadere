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
    /// A device enrolled by an account that had any device in the last `coolDownLookback` cannot approve high or critical requests for
    /// this long, unless an existing trusted device confirms it (`confirm`).
    static let newDeviceCoolDown: TimeInterval = 24 * 3600
    /// An account that had a device (revoked ones included) this recently is not "new": revoking the owner's devices does not reset it.
    static let coolDownLookback: TimeInterval = 30 * 86_400
    /// A revoked device can still be named by `replacesDeviceId` for this long.
    static let replaceWindow: TimeInterval = 30 * 86_400
    /// App Clip devices stop working on their own after this long.
    static let appClipLifetime: TimeInterval = 7 * 24 * 3600

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
            return try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: consumerId, origin: "register")
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
            return try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: consumer.id!, origin: "login")
        }
        return session(consumerId: consumer.id!, issued: issued)
    }

    // MARK: Refresh / logout

    func refresh(_ request: AuthRefreshRequest) async throws -> AuthSession {
        do {
            let result = try await tokens.rotate(refreshToken: request.refreshToken)
            if result.replayed {
                _ = try? await AuditService(db: db, ctx: ctx).record("auth.refresh_replayed", actor: AuditActor(kind: .system),
                    consumerId: ConsumerID(result.consumerId), metadata: ["reason": "grace_window"])
            }
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
        // Logout ends this session and nothing else: the device it belongs to stays enrolled (an extension or a replayed request must
        // never be able to take the owner's device away by logging out).
        try await tokens.revokeFamily(principal.familyId, now: ctx.now, devices: .none)
        _ = try await AuditService(db: db, ctx: ctx).record("auth.logout", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                                                           consumerId: principal.consumerId)
    }

    // MARK: Devices

    /// Starts an enrollment: a single-use challenge **and** WebAuthn assertion options over that same challenge. The app performs a
    /// user-verified passkey assertion over it and sends the result with the keys (`enroll`), so a bearer token alone can never
    /// create a device. The exception (`assertionOptional`) is a session that a passkey ceremony created minutes ago and that has
    /// not enrolled yet.
    func enrollBegin(_ principal: ConsumerPrincipal) async throws -> DeviceEnrollmentChallenge {
        try await ctx.limiter.enforce("enroll-begin", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let challenge = SecureToken.generate()
        let expires = ctx.now.addingTimeInterval(Self.enrollChallengeTTL)
        let record = DeviceEnrollChallengeRecord(consumerId: principal.consumerId.uuid, challengeHash: SecureToken.hash(challenge),
                                                 expiresAt: expires, familyId: principal.familyId)
        try await record.create(on: db)
        let credentialIds = try await PasskeyCredentialRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).all().map(\.credentialId)
        let options = PasskeyAssertionOptions(ceremonyId: CeremonyID(record.id!), challenge: challenge, relyingPartyId: ctx.config.relyingPartyID,
                                              allowCredentialIds: credentialIds, timeoutMilliseconds: Int(Self.enrollChallengeTTL * 1000))
        return DeviceEnrollmentChallenge(challenge: challenge, expiresAt: expires, assertion: options,
                                         assertionOptional: try await freshSessionMayEnroll(principal.familyId))
    }

    /// The session was created by a passkey ceremony less than five minutes ago, has not enrolled a device, and is not revoked.
    private func freshSessionMayEnroll(_ familyId: UUID) async throws -> Bool {
        guard let family = try await TokenFamilyRecord.find(familyId, on: db), family.revokedAt == nil, family.deviceId == nil,
              let until = family.enrollUntil else { return false }
        return until > ctx.now
    }

    func deviceDTO(_ device: DeviceRecord, keys: [DeviceKeyRecord]) -> Device {
        let keyDTOs: [DeviceKey] = keys.compactMap { key in
            guard let purpose = DeviceKeyPurpose(rawValue: key.purpose), let publicKey = try? DevicePublicKey(base64URL: key.publicKey),
                  let id = key.id else { return nil }
            return DeviceKey(id: DeviceKeyID(id), purpose: purpose, publicKey: publicKey, hardwareBacked: key.hardwareBacked,
                             createdAt: key.createdAt, attested: key.attested)
        }
        return Device(id: DeviceID(device.id!), consumerId: ConsumerID(device.consumerId), name: device.name,
                      platform: DevicePlatform(rawValue: device.platform) ?? .iOS, keys: keyDTOs, createdAt: device.createdAt,
                      lastSeenAt: device.lastSeenAt, revokedAt: device.revokedAt, clientKind: device.kind,
                      approvalsLockedUntil: device.approvalsLockedUntil, expiresAt: device.expiresAt)
    }

    private func enrollmentFailure(_ principal: ConsumerPrincipal, _ reason: String, purpose: String? = nil) async -> Never? {
        var metadata = ["reason": reason]
        if let purpose { metadata["purpose"] = purpose }
        _ = try? await AuditService(db: db, ctx: ctx).record("device.enroll_failed", outcome: .failure,
            actor: AuditActor(kind: .consumer, id: principal.consumerId.description), consumerId: principal.consumerId, metadata: metadata)
        return nil
    }

    func enroll(_ principal: ConsumerPrincipal, request: DeviceEnrollRequest) async throws -> Device {
        try await ctx.limiter.enforce("enroll", key: principal.consumerId.description, rule: .perHour(20, burst: 10))
        let name = request.name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 64, !DisplayTextSanitizer.containsDisallowedScalars(name) else {
            throw APIError.validation("A device name of up to 64 characters is required.", details: ["name": "invalid"])
        }
        let purposes = request.keys.map(\.purpose)
        guard purposes.contains(.request), Set(purposes).count == purposes.count, request.keys.count <= DeviceKeyPurpose.allCases.count else {
            throw APIError.validation("Provide exactly one key per purpose, including a request key.", details: ["keys": "invalid"])
        }
        // App Clip devices can request but never approve: the server refuses to register approval keys for them.
        if request.effectiveClientKind == .appClip, purposes != [.request] {
            throw APIError.validation("An App Clip device can only register a request key.", details: ["keys": "appClipRequestKeyOnly"])
        }
        let existing = try await DeviceRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$revokedAt == nil).count()
        // "Set up again": the device being replaced must be this session's own device, or one revoked recently (the app lost its keys).
        let replaced: DeviceRecord?
        if let replacesId = request.replacesDeviceId {
            guard request.effectiveClientKind == .app,
                  let old = try await DeviceRecord.query(on: db).filter(\.$id == replacesId.uuid).filter(\.$consumerId == principal.consumerId.uuid).first(),
                  try await Self.mayReplace(old, principal: principal, now: ctx.now, db: db) else {
                _ = await enrollmentFailure(principal, "replace_not_allowed")
                throw APIError.forbidden
            }
            replaced = old
        } else {
            replaced = nil
        }
        guard existing - (replaced?.revokedAt == nil && replaced != nil ? 1 : 0) < Self.maxDevicesPerConsumer else {
            throw APIError.conflict("Too many devices are enrolled. Revoke one first.")
        }
        // The challenge is single-use, short-lived, and good only for the session that asked for it.
        guard request.challenge.count <= 128, let challengeRecord = try await DeviceEnrollChallengeRecord.query(on: db)
            .filter(\.$challengeHash == SecureToken.hash(request.challenge)).filter(\.$consumerId == principal.consumerId.uuid).first(),
              challengeRecord.state == "open", challengeRecord.expiresAt > ctx.now,
              challengeRecord.familyId == nil || challengeRecord.familyId == principal.familyId else {
            throw APIError(.unauthorized, .unauthorized, "The enrollment challenge is invalid or expired.")
        }
        // Proof of possession for every key, over the server's challenge.
        for key in request.keys where !DeviceEnrollment.verify(key, consumerId: principal.consumerId, challenge: request.challenge) {
            _ = await enrollmentFailure(principal, "bad_proof", purpose: key.purpose.rawValue)
            throw APIError(.unauthorized, .signatureInvalid, "Key proof of possession failed.")
        }
        // Possession of the account's passkey, fresh, user-verified and bound to this very challenge.
        let method = try await verifyPasskeyPossession(principal, request: request)
        // Replacing (and so revoking) a device is never covered by the "fresh sign-in" shortcut: it needs the assertion.
        if replaced != nil, method != "assertion" {
            _ = await enrollmentFailure(principal, "replace_needs_assertion")
            throw APIError(.unauthorized, .passkeyAssertionRequired, "Confirm with your passkey to set this device up again.")
        }
        guard try await DB.swap(db, table: DeviceEnrollChallengeRecord.schema, id: challengeRecord.id!, column: "state", expected: "open", newValue: "used")
        else { throw APIError(.unauthorized, .unauthorized, "The enrollment challenge is invalid or expired.") }

        let now = ctx.now
        let attestation = await ctx.integrity.verifyEnrollment(request.appAttest, challenge: request.challenge, keys: request.keys)
        // Cool-down: an account that had any app device in the last 30 days (revoked ones included, so deleting the owner's devices does
        // not make a thief's device the "first") cannot approve high-risk requests from this new device for 24 h, unless confirmed.
        let hasApprovalKey = request.keys.contains { $0.purpose != .request }
        let lookback = now.addingTimeInterval(-Self.coolDownLookback)
        let priorDevices = try await DeviceRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$clientKind == DeviceClientKind.app.rawValue).all()
            .filter { $0.revokedAt.map { $0 > lookback } ?? !$0.isExpired(at: now) }
        let coolDown = request.effectiveClientKind == .app && hasApprovalKey && !priorDevices.isEmpty
        let device = DeviceRecord(consumerId: principal.consumerId.uuid, name: name, platform: request.platform, now: now, clientKind: request.effectiveClientKind)
        device.familyId = principal.familyId
        device.enrollmentMethod = method
        device.approvalsLockedUntil = coolDown ? now.addingTimeInterval(Self.newDeviceCoolDown) : nil
        device.expiresAt = request.effectiveClientKind == .appClip ? now.addingTimeInterval(Self.appClipLifetime) : nil
        // `hardwareBacked` is recorded as claimed; `attested` is true only if App Attest verified it.
        let keyRecords = request.keys.map { DeviceKeyRecord(deviceId: device.id!, purpose: $0.purpose, publicKey: $0.publicKey,
                                                           hardwareBacked: $0.hardwareBacked, now: now, attested: attestation.attested) }
        let family = principal.familyId
        try await db.transaction { tx in
            try await device.create(on: tx)
            for key in keyRecords { try await key.create(on: tx) }
            try await Self.bindFamily(family, consumerId: principal.consumerId.uuid, to: device.id!, method: method,
                                      clipExpiry: device.expiresAt, now: now, on: tx)
            if let replaced, replaced.revokedAt == nil, let oldId = replaced.id {
                // The old device goes, with every *other* session bound to it; the caller's own session moved to the new device above.
                try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: [oldId], now: now, cascadeToFamilies: true, keepFamily: family)
                _ = try await AuditService(db: tx, ctx: ctx).record("device.replaced", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                    consumerId: principal.consumerId, subjectType: "device", subjectId: DeviceID(oldId).description,
                    metadata: ["new_device": DeviceID(device.id!).description])
            }
            _ = try await AuditService(db: tx, ctx: ctx).record("device.enrolled", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                consumerId: principal.consumerId, subjectType: "device", subjectId: DeviceID(device.id!).description,
                metadata: ["platform": request.platform.rawValue, "max_assurance": Device.maxAssurance(keys: request.keys).rawValue,
                           "method": method, "client_kind": request.effectiveClientKind.rawValue, "cool_down": coolDown ? "true" : "false",
                           "attested": attestation.attested ? "true" : "false", "attestation": attestation.reason])
        }
        // Every enrollment into an account that already had a device is announced (an App Clip too): in-app notice plus push to the other
        // devices. The first device of a new account has nobody to tell.
        if !priorDevices.isEmpty || request.effectiveClientKind == .appClip { await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(
            of: principal.consumerId.uuid, except: device.id!, notice: request.effectiveClientKind == .appClip ? .appClip
                : (replaced != nil ? .deviceReplaced : .newDevice), subjectId: DeviceID(device.id!).description) }
        return deviceDTO(device, keys: keyRecords)
    }

    /// This session's own device (the one it is bound to, or enrolled through it), or any device of the account revoked in the last 30 days.
    private static func mayReplace(_ old: DeviceRecord, principal: ConsumerPrincipal, now: Date, db: any Database) async throws -> Bool {
        if let revoked = old.revokedAt { return now.timeIntervalSince(revoked) <= replaceWindow }
        if old.familyId == principal.familyId { return true }
        return try await TokenFamilyRecord.find(principal.familyId, on: db)?.deviceId == old.id
    }

    /// Either a fresh passkey assertion over the enrollment challenge, or (once) the unused passkey session. Returns the method.
    private func verifyPasskeyPossession(_ principal: ConsumerPrincipal, request: DeviceEnrollRequest) async throws -> String {
        let required = APIError(.unauthorized, .passkeyAssertionRequired, "Confirm with your passkey to add this device.")
        if let assertion = request.assertion {
            guard assertion.id.count <= 1024, let challenge = Base64URL.decode(request.challenge),
                  let credential = try await PasskeyCredentialRecord.query(on: db).filter(\.$credentialId == assertion.id)
                      .filter(\.$consumerId == principal.consumerId.uuid).first(), let publicKey = Base64URL.decode(credential.publicKey),
                  let consumer = try await ConsumerRecord.find(principal.consumerId.uuid, on: db), consumer.status == "active" else {
                _ = await enrollmentFailure(principal, "unknown_credential")
                throw required
            }
            if let handle = assertion.userHandle, !ConstantTime.equals(handle, consumer.userHandle) {
                _ = await enrollmentFailure(principal, "user_handle_mismatch")
                throw required
            }
            do {
                // `requireUserVerification` is enforced by the verifier; the challenge is this enrollment's challenge.
                let result = try ctx.passkeys.verifyAssertion(assertion, challenge: challenge, publicKey: publicKey,
                                                              signCount: UInt32(clamping: credential.signCount))
                credential.signCount = Int(result.newSignCount)
                credential.lastUsedAt = ctx.now
                try await credential.update(on: db)
            } catch {
                _ = await enrollmentFailure(principal, "assertion_invalid")
                throw required
            }
            return "assertion"
        }
        guard try await freshSessionMayEnroll(principal.familyId) else {
            _ = await enrollmentFailure(principal, "assertion_missing")
            throw required
        }
        return "fresh_session"
    }

    /// Binds the session to the device it enrolled. A fresh-session enrollment is single use: it wins a compare-and-swap on
    /// `device_id IS NULL`, so two concurrent enrollments cannot both ride the same sign-in.
    private static func bindFamily(_ familyId: UUID, consumerId: UUID, to deviceId: UUID, method: String, clipExpiry: Date?, now: Date,
                                   on tx: any Database) async throws {
        guard let family = try await TokenFamilyRecord.find(familyId, on: tx) else {
            // A session from before token families existed: create its record so it is bound from now on.
            let legacy = TokenFamilyRecord(id: familyId, consumerId: consumerId, origin: "legacy", now: now, enrollUntil: nil)
            legacy.deviceId = deviceId
            legacy.expiresAt = clipExpiry
            try await legacy.create(on: tx)
            return
        }
        if method == "fresh_session" {
            guard try await DB.swapFromNull(tx, table: TokenFamilyRecord.schema, id: familyId, column: "device_id", newValue: deviceId) else {
                throw APIError(.unauthorized, .passkeyAssertionRequired, "Confirm with your passkey to add this device.")
            }
            try await TokenFamilyRecord.query(on: tx).filter(\.$id == familyId).set(\.$enrollUntil, to: nil).update()
        } else {
            family.deviceId = deviceId
            family.enrollUntil = nil
            try await family.update(on: tx)
        }
        if let clipExpiry {
            try await TokenFamilyRecord.query(on: tx).filter(\.$id == familyId).set(\.$expiresAt, to: clipExpiry).update()
            try await AccessTokenRecord.query(on: tx).filter(\.$familyId == familyId).filter(\.$expiresAt > clipExpiry).set(\.$expiresAt, to: clipExpiry).update()
            try await RefreshTokenRecord.query(on: tx).filter(\.$familyId == familyId).filter(\.$expiresAt > clipExpiry).set(\.$expiresAt, to: clipExpiry).update()
        }
    }

    func devices(for consumer: ConsumerID) async throws -> [Device] {
        let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumer.uuid).sort(\.$createdAt, .ascending).all()
        let keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).all()
        return devices.map { device in deviceDTO(device, keys: keys.filter { $0.deviceId == device.id }) }
    }

    /// Revokes a device, the sessions bound to it, and its push tokens.
    func revoke(_ principal: ConsumerPrincipal, deviceId: DeviceID) async throws {
        guard let device = try await DeviceRecord.query(on: db).filter(\.$id == deviceId.uuid)
            .filter(\.$consumerId == principal.consumerId.uuid).first() else { throw APIError.notFound }
        guard device.revokedAt == nil else { return }
        let now = ctx.now
        // Signing out of this very device is always allowed; removing another device needs a trusted one, so a device an attacker just
        // enrolled cannot lock the owner out.
        if principal.deviceId != deviceId { try await DeviceTrust.require(principal, db: db, now: now) }
        try await db.transaction { tx in
            try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: [deviceId.uuid], now: now)
            _ = try await AuditService(db: tx, ctx: ctx).record("device.revoked", principal: principal, subjectType: "device", subjectId: deviceId.description)
        }
    }

    /// Lifts the new-device cool-down of `target`. Signed by **another**, trusted device of the same account with a user-verified
    /// approval key (`ConfirmationProof`), so a stolen bearer token plus the new (attacker) device cannot confirm itself.
    func confirm(_ principal: ConsumerPrincipal, target: DeviceID, proof: ConfirmationProof) async throws -> Device {
        try await ctx.limiter.enforce("device-confirm", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let now = ctx.now
        guard let confirmerId = principal.deviceId, proof.deviceId == confirmerId, confirmerId != target,
              let confirmer = try await DeviceRecord.find(confirmerId.uuid, on: db), confirmer.consumerId == principal.consumerId.uuid,
              confirmer.isTrusted(at: now),
              let device = try await DeviceRecord.query(on: db).filter(\.$id == target.uuid)
                  .filter(\.$consumerId == principal.consumerId.uuid).first(), device.revokedAt == nil else { throw APIError.forbidden }
        if device.approvalsLockedUntil != nil {
            guard let purpose = proof.requiredKeyPurpose,
                  let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == confirmerId.uuid)
                      .filter(\.$purpose == purpose.rawValue).first(), let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
                throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID on a device you already trust.")
            }
            do {
                try await proof.verify(subject: .device, subjectId: target.description, publicKey: publicKey, now: now,
                                       replayGuard: DatabaseReplayGuard(db: db))
            } catch ConfirmationProof.Failure.replayed {
                throw APIError(.unauthorized, .replayDetected, "This confirmation was already used.")
            } catch ConfirmationProof.Failure.assuranceTooLow {
                throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID on a device you already trust.")
            } catch {
                _ = try? await AuditService(db: db, ctx: ctx).record("device.confirm_failed", outcome: .failure, principal: principal,
                                                                    subjectType: "device", subjectId: target.description)
                throw APIError.signatureInvalid
            }
            device.approvalsLockedUntil = nil
            device.confirmedAt = now
            try await db.transaction { tx in
                try await device.update(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("device.confirmed", principal: principal, subjectType: "device",
                    subjectId: target.description, metadata: ["assurance": proof.assurance.rawValue])
            }
        }
        let keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == target.uuid).all()
        return deviceDTO(device, keys: keys)
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
