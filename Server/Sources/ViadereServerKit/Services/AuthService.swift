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
    /// Cool-down for a device that could not be attested while `APP_ATTEST_MODE=report` (it is flagged as well).
    static let unattestedCoolDown: TimeInterval = 72 * 3600
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

    /// Legacy passkey-first sign-up (kept for older apps; new accounts are device-first, `AccountEnrollmentService`). The name is optional.
    func registerBegin(_ request: PasskeyRegistrationBeginRequest) async throws -> PasskeyRegistrationOptions {
        let trimmed = (request.displayName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count <= 64, !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("A display name can have up to 64 characters.", details: ["displayName": "invalid"])
        }
        let name: String? = trimmed.isEmpty ? nil : trimmed
        let challenge = ctx.passkeys.makeChallenge()
        let consumerId = UUID()
        let handle = SecureToken.generate(byteCount: 32)
        let ceremony = PasskeyCeremonyRecord(kind: "register", challenge: Base64URL.encode(challenge), consumerId: consumerId,
                                             displayName: name, userHandle: handle, now: ctx.now, ttl: Self.ceremonyTTL)
        try await ceremony.create(on: db)
        let label = name ?? ConsumerRecord.neutralLabel
        return PasskeyRegistrationOptions(
            ceremonyId: CeremonyID(ceremony.id!), challenge: Base64URL.encode(challenge), relyingPartyId: ctx.config.relyingPartyID,
            relyingPartyName: ctx.config.relyingPartyName, userId: handle, userName: label, userDisplayName: label,
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
              let handle = ceremony.userHandle else { throw APIError.unauthorized }
        let name = ceremony.displayName
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
        // The account's 10 recovery codes are issued with the account and shown once, in this response.
        let (issued, codes): (ConsumerTokenService.IssuedSession, RecoveryCodeSet) = try await db.transaction { tx in
            try await ConsumerRecord(id: consumerId, displayName: name, userHandle: handle, now: now).create(on: tx)
            try await PasskeyCredentialRecord(consumerId: consumerId, credentialId: verified.credentialId,
                                              publicKey: Base64URL.encode(verified.publicKey), signCount: Int(verified.signCount),
                                              backupEligible: verified.backupEligible, now: now).create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("auth.registered", actor: AuditActor(kind: .consumer, id: ConsumerID(consumerId).description),
                                                               consumerId: ConsumerID(consumerId))
            let codes = try await RecoveryService(db: tx, ctx: ctx).issueCodes(consumerId: consumerId)
            let issued = try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: consumerId, origin: "register")
            return (issued, codes)
        }
        var result = session(consumerId: consumerId, issued: issued)
        result.recoveryCodes = codes
        return result
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
        if let handle = request.credential.userHandle, !ConstantTime.equals(handle, consumer.userHandle ?? "") { throw failure }
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

    func refresh(_ request: AuthRefreshRequest, http: SignedRequestContext) async throws -> AuthSession {
        // A session bound to a device refreshes only with that device's signature (the grace replay too); otherwise a copied refresh
        // token would be as good as the device.
        try await requireBoundDeviceSignature(refreshToken: request.refreshToken, http: http)
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

    func deviceDTO(_ device: DeviceRecord, keys: [DeviceKeyRecord], pendingReplacementAt: Date? = nil) -> Device {
        Self.deviceDTO(device, keys: keys, pendingReplacementAt: pendingReplacementAt, now: ctx.now)
    }

    static func deviceDTO(_ device: DeviceRecord, keys: [DeviceKeyRecord], pendingReplacementAt: Date? = nil, now: Date) -> Device {
        let keyDTOs: [DeviceKey] = keys.compactMap { key in
            guard let purpose = DeviceKeyPurpose(rawValue: key.purpose), let publicKey = try? DevicePublicKey(base64URL: key.publicKey),
                  let id = key.id else { return nil }
            return DeviceKey(id: DeviceKeyID(id), purpose: purpose, publicKey: publicKey, hardwareBacked: key.hardwareBacked,
                             createdAt: key.createdAt, attested: key.attested)
        }
        return Device(id: DeviceID(device.id!), consumerId: ConsumerID(device.consumerId), name: device.name,
                      platform: DevicePlatform(rawValue: device.platform) ?? .iOS, keys: keyDTOs, createdAt: device.createdAt,
                      lastSeenAt: device.lastSeenAt, revokedAt: device.revokedAt, clientKind: device.kind,
                      approvalsLockedUntil: device.approvalsLockedUntil, expiresAt: device.expiresAt,
                      pendingReplacementBy: device.revokedAt == nil ? device.pendingReplacementBy.map { DeviceID($0) } : nil,
                      pendingReplacementAt: device.revokedAt == nil ? pendingReplacementAt : nil, trustTier: DeviceTrust.tier(device, at: now))
    }

    /// `400` unless every key is `ES256` and the integrity fields do not contradict each other (§2.5a).
    static func validateKeysAndEvidence(_ keys: [DeviceKeyRegistration], conflictingIntegrity: Bool) throws {
        guard keys.allSatisfy({ $0.algorithm.isSupported }) else {
            throw APIError(.badRequest, .badRequest, "Only ES256 (P-256) keys are supported.", details: ["algorithm": "unsupported"])
        }
        guard !conflictingIntegrity else {
            throw APIError(.badRequest, .badRequest, "Send integrity evidence once (integrity or appAttest, not two different ones).", details: ["integrity": "conflict"])
        }
    }

    /// The tier a device starts with (`TrustTierPolicy.initialElevation`), from the server's own records.
    static func initialElevation(consumerId: UUID, kind: DeviceClientKind, purposes: [DeviceKeyPurpose], attested: Bool, mode: AppAttestMode,
                                 db: any Database) async throws -> TrustElevation? {
        let hadAppDevice = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId)
            .filter(\.$clientKind == DeviceClientKind.app.rawValue).count() > 0
        let recovered = try await AccountRecoveryRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state == "activated").count() > 0
        let facts = DeviceTrustFacts(isFullApp: kind == .app, revoked: false, expired: false,
                                     hasUserVerifiedApprovalKey: purposes.contains(.approvalBiometric) || purposes.contains(.approvalUserPresence),
                                     integrityVerified: attested, integrityRequired: mode != .off, firstAppDeviceOfAccount: !hadAppDevice,
                                     accountRecovered: recovered)
        return TrustTierPolicy.initialElevation(facts)
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
        try Self.validateKeysAndEvidence(request.keys, conflictingIntegrity: request.hasConflictingIntegrity)
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
        // A live device being replaced stays live until the replacement is confirmed, so it still counts.
        guard existing < Self.maxDevicesPerConsumer else {
            throw APIError.conflict("Too many devices are enrolled. Revoke one first.")
        }
        if let replaced, replaced.revokedAt == nil, replaced.pendingReplacementBy != nil {
            throw APIError.conflict("A replacement for this device is already pending.")
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

        let now = ctx.now
        let kind = request.effectiveClientKind
        // App Attest: the attestation must vouch for this exact challenge, account and key list (AppAttestBinding).
        let evidence = request.effectiveIntegrity
        let verifiedAttestation = await ctx.integrity.verifyEnrollment(integrity: evidence, consumerId: principal.consumerId, challenge: request.challenge,
                                                                        keys: request.keys, clientKind: kind)
        // An App Attest key can vouch for one device only.
        let keyReused: Bool
        if verifiedAttestation.attested, let keyId = verifiedAttestation.keyId {
            keyReused = try await AppAttestKeyRecord.query(on: db).filter(\.$keyId == keyId).count() > 0
        } else {
            keyReused = false
        }
        let attestation = keyReused ? AttestationResult(attested: false, reason: "key_reused") : verifiedAttestation
        let mode = ctx.config.appAttestMode
        if mode == .require, !attestation.attested {
            _ = await enrollmentFailure(principal, "attestation_required:\(attestation.reason)")
            throw APIError(.forbidden, .attestationRequired, "This device could not be verified. Update Viadere and try again on a genuine device.")
        }
        // The challenge is consumed only now that the request is otherwise acceptable.
        guard try await DB.swap(db, table: DeviceEnrollChallengeRecord.schema, id: challengeRecord.id!, column: "state", expected: "open", newValue: "used")
        else { throw APIError(.unauthorized, .unauthorized, "The enrollment challenge is invalid or expired.") }

        // Trust tier (§2.5a): only a brand-new, never-recovered account's first app device with a user-verified key and verified integrity
        // starts at D1. Every other device is D0 until a D1 device approves it (`confirm`); time never elevates it. The notice window
        // (24 h, 72 h unattested in report mode) for an account that has EVER had an app device (revoked or expired ones included, however
        // long ago) is when the other devices can cancel a replacement; its end does not make the device trusted.
        let hadAppDevice = try await DeviceRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$clientKind == DeviceClientKind.app.rawValue).count() > 0
        let elevation = try await Self.initialElevation(consumerId: principal.consumerId.uuid, kind: kind, purposes: purposes,
                                                        attested: attestation.attested, mode: mode, db: db)
        let unattestedInReport = mode == .report && !attestation.attested
        let coolDown = kind == .app && hadAppDevice
        let coolDownLength = unattestedInReport ? Self.unattestedCoolDown : Self.newDeviceCoolDown
        let replacingLive = replaced.map { $0.revokedAt == nil } ?? false
        let device = DeviceRecord(consumerId: principal.consumerId.uuid, name: name, platform: request.platform, now: now, clientKind: kind)
        // A device that replaces a LIVE one is not tied to the caller's session: revoking it (cancel) must not end the old device's session.
        device.familyId = replacingLive ? nil : principal.familyId // set to the replacement session's family below
        device.enrollmentMethod = method
        device.approvalsLockedUntil = coolDown ? now.addingTimeInterval(coolDownLength) : nil
        device.expiresAt = kind == .appClip ? now.addingTimeInterval(Self.appClipLifetime) : nil
        device.attestationStatus = attestation.attested ? "attested" : (evidence == nil ? "unattested" : "rejected")
        device.integrityFormat = evidence?.format.rawValue
        device.keyAlgorithm = DeviceKeyAlgorithm.es256.rawValue
        if let elevation {
            device.trustTier = DeviceTrustTier.d1.rawValue
            device.elevatedAt = now
            device.elevatedBy = elevation.rawValue
        }
        // `hardwareBacked` is recorded as claimed; `attested` is true only if App Attest verified it.
        let keyRecords = request.keys.map { DeviceKeyRecord(deviceId: device.id!, purpose: $0.purpose, publicKey: $0.publicKey,
                                                           hardwareBacked: $0.hardwareBacked, now: now, attested: attestation.attested) }
        let family = principal.familyId
        let pendingSession: AuthSession?
        do {
            pendingSession = try await db.transaction { tx -> AuthSession? in
                var replacementSession: AuthSession?
                if replacingLive {
                    // The new device gets its own session, already bound to it; the caller's session stays with the old device.
                    let issued = try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: principal.consumerId.uuid, origin: "replace")
                    try await TokenFamilyRecord.query(on: tx).filter(\.$id == issued.familyId).set(\.$deviceId, to: device.id!)
                        .set(\.$enrollUntil, to: nil).update()
                    device.familyId = issued.familyId
                    replacementSession = session(consumerId: principal.consumerId.uuid, issued: issued)
                }
                try await device.create(on: tx)
                for key in keyRecords { try await key.create(on: tx) }
                if attestation.attested, let keyId = attestation.keyId, let publicKey = attestation.publicKey {
                    try await AppAttestKeyRecord(deviceId: device.id!, consumerId: principal.consumerId.uuid, keyId: keyId, publicKey: publicKey,
                                                 counter: attestation.counter, environment: attestation.environment ?? "production", now: now,
                                                 format: evidence?.format ?? .appleAppAttest).create(on: tx)
                }
                if replacingLive, let replaced, let oldId = replaced.id {
                    // The old device keeps working, and so does the caller's session. The new device takes over when it is confirmed or its
                    // cool-down ends (`IdentityMaintenance`), unless the owner cancels from the old device.
                    try await DeviceRecord.query(on: tx).filter(\.$id == oldId).set(\.$pendingReplacementBy, to: device.id!).update()
                    _ = try await AuditService(db: tx, ctx: ctx).record("device.replacement_pending", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                        consumerId: principal.consumerId, subjectType: "device", subjectId: DeviceID(oldId).description,
                        metadata: ["new_device": DeviceID(device.id!).description])
                } else {
                    try await Self.bindFamily(family, consumerId: principal.consumerId.uuid, to: device.id!, method: method,
                                              clipExpiry: device.expiresAt, now: now, on: tx)
                    if let replaced {
                        // The old device was already revoked (the normal biometric-change case): replaced at once.
                        _ = try await AuditService(db: tx, ctx: ctx).record("device.replaced", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                            consumerId: principal.consumerId, subjectType: "device", subjectId: DeviceID(replaced.id!).description,
                            metadata: ["new_device": DeviceID(device.id!).description, "mode": "immediate"])
                    }
                }
                var metadata = ["platform": request.platform.rawValue, "max_assurance": Device.maxAssurance(keys: request.keys).rawValue,
                                "method": method, "client_kind": kind.rawValue, "cool_down": coolDown ? "true" : "false",
                                "cool_down_hours": coolDown ? String(Int(coolDownLength / 3600)) : "0",
                                "attested": attestation.attested ? "true" : "false", "attestation": attestation.reason,
                                "attest_mode": mode.rawValue, "tier": device.trustTier, "integrity_format": evidence?.rawFormat ?? "none"]
                if unattestedInReport { metadata["flagged"] = "unattested" }
                _ = try await AuditService(db: tx, ctx: ctx).record("device.enrolled", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                    consumerId: principal.consumerId, subjectType: "device", subjectId: DeviceID(device.id!).description, metadata: metadata)
                return replacementSession
            }
        } catch {
            if error.isConstraintViolation, attestation.attested { throw APIError.conflict("This attestation was already used.") }
            throw error
        }
        // Every enrollment into an account that already had a device is announced (an App Clip too): in-app notice plus push to the other
        // devices. The first device of a new account has nobody to tell.
        if hadAppDevice || kind == .appClip {
            let notice: SecurityNotices.Notice = kind == .appClip ? .appClip : (replacingLive ? .devicePendingReplacement : (replaced != nil ? .deviceReplaced : .newDevice))
            await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: device.id!, notice: notice,
                                                                      subjectId: DeviceID(device.id!).description)
        }
        var dto = deviceDTO(device, keys: keyRecords, pendingReplacementAt: nil)
        dto.replacementSession = pendingSession
        return dto
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
            if let handle = assertion.userHandle, !ConstantTime.equals(handle, consumer.userHandle ?? "") {
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
        return devices.map { device in
            let due = device.pendingReplacementBy.flatMap { newId in devices.first { $0.id == newId }?.approvalsLockedUntil }
            return deviceDTO(device, keys: keys.filter { $0.deviceId == device.id }, pendingReplacementAt: due)
        }
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

    /// Approves `target` (§2.17, §2.5a): **another** D1 device of the same account signs a user-verified (biometric) `ConfirmationProof`, so a
    /// stolen bearer token plus the new (attacker) device cannot approve itself, and a device nobody approved cannot approve others. It ends the
    /// target's notice window and, when the target meets every D1 condition (a full-app device with a user-verified approval key and verified
    /// integrity where it is evaluated), makes it D1. This is the only way an existing account's device becomes D1.
    func confirm(_ principal: ConsumerPrincipal, target: DeviceID, proof: ConfirmationProof) async throws -> Device {
        try await ctx.limiter.enforce("device-confirm", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let now = ctx.now
        guard let confirmerId = principal.deviceId, proof.deviceId == confirmerId, confirmerId != target,
              let confirmer = try await DeviceRecord.find(confirmerId.uuid, on: db), confirmer.consumerId == principal.consumerId.uuid,
              confirmer.isTrusted(at: now),
              let device = try await DeviceRecord.query(on: db).filter(\.$id == target.uuid)
                  .filter(\.$consumerId == principal.consumerId.uuid).first(), device.revokedAt == nil else { throw APIError.forbidden }
        var keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == target.uuid).all()
        if device.approvalsLockedUntil != nil || !device.isTrusted(at: now) {
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
            let purposes = Set(keys.compactMap { DeviceKeyPurpose(rawValue: $0.purpose) })
            let facts = DeviceTrustFacts(isFullApp: device.kind == .app, revoked: false, expired: device.isExpired(at: now),
                                         hasUserVerifiedApprovalKey: purposes.contains(.approvalBiometric) || purposes.contains(.approvalUserPresence),
                                         integrityVerified: device.attestationStatus == "attested", integrityRequired: ctx.config.appAttestMode != .off)
            let elevate = !device.isTrusted(at: now) && TrustTierPolicy.mayElevate(target: facts, approverTier: DeviceTrust.tier(confirmer, at: now))
            device.approvalsLockedUntil = nil
            device.confirmedAt = now
            if elevate {
                device.trustTier = DeviceTrustTier.d1.rawValue
                device.elevatedAt = now
                device.elevatedBy = TrustElevation.trustedDeviceApproval.rawValue
            }
            try await db.transaction { tx in
                try await device.update(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("device.confirmed", principal: principal, subjectType: "device",
                    subjectId: target.description, metadata: ["assurance": proof.assurance.rawValue, "tier": device.trustTier,
                                                              "elevated": elevate ? "true" : "false", "by_device": confirmerId.description])
            }
        }
        // Confirming the new device completes any "Set up again" that was waiting on it: the replaced device goes now.
        try await IdentityMaintenance(db: db, ctx: ctx).finalizeReplacements(forNewDevice: target.uuid)
        keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == target.uuid).all()
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
