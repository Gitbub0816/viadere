import Fluent
import Foundation
import ViadereCore

/// Optional recovery credentials (WP-B4 "Protect your account", SECURITY.md §2.5a, §2.26): a passkey (synced where the platform allows) and
/// recovery codes. Both are added from a device that may manage the account, with a **user-verified proof from that device** over the
/// single-use, server-generated ceremony id (`ConfirmationProof`, subject `recoveryCredential`). Neither is required: an account without them is
/// lost with its only device, and the app says so before the person skips.
struct RecoveryCredentialService {
    let db: any Database
    let ctx: ServerContext

    static let maxPasskeys = 10
    static let rate = RateRule.perHour(20, burst: 10)

    // MARK: The device proof

    /// Verifies `proof` for the ceremony `ceremonyId`: made by the calling device, with its user-verified approval key (biometric, or the
    /// passcode key), fresh, single use. `403 insufficient_assurance` for a request key, `401` for anything that does not verify.
    func verifyProof(_ proof: ConfirmationProof, ceremonyId: UUID, principal: ConsumerPrincipal, device: DeviceRecord) async throws {
        guard let deviceId = device.id, proof.deviceId.uuid == deviceId else { throw APIError(.forbidden, .forbidden, "Confirm on this device.") }
        guard let purpose = proof.requiredKeyPurpose,
              let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId).filter(\.$purpose == purpose.rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
            throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID, Touch ID or your passcode.")
        }
        do {
            try await proof.verify(subject: .recoveryCredential, subjectId: ceremonyId.uuidString.lowercased(), publicKey: publicKey, now: ctx.now,
                                   replayGuard: DatabaseReplayGuard(db: db))
        } catch ConfirmationProof.Failure.replayed {
            throw APIError(.unauthorized, .replayDetected, "This confirmation was already used.")
        } catch ConfirmationProof.Failure.assuranceTooLow {
            throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID, Touch ID or your passcode.")
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("recovery.credential_proof_failed", outcome: .failure, principal: principal, subjectType: "recovery")
            throw APIError.signatureInvalid
        }
    }

    // MARK: Passkey

    /// The account's WebAuthn user handle, assigned on first use (a device-first account has none until it adds a passkey or recovers).
    static func ensureUserHandle(_ consumerId: UUID, db: any Database) async throws -> String {
        guard let consumer = try await ConsumerRecord.find(consumerId, on: db) else { throw APIError.notFound }
        if let handle = consumer.userHandle { return handle }
        _ = try await DB.swapFromNull(db, table: ConsumerRecord.schema, id: consumerId, column: "user_handle", newValue: SecureToken.generate(byteCount: 32))
        guard let handle = try await ConsumerRecord.find(consumerId, on: db)?.userHandle else { throw APIError.internalError }
        return handle
    }

    func passkeyBegin(_ principal: ConsumerPrincipal) async throws -> PasskeyRegistrationOptions {
        try await ctx.limiter.enforce("recovery-passkey", key: principal.consumerId.description, rule: Self.rate)
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        let consumerId = principal.consumerId.uuid
        let existing = try await PasskeyCredentialRecord.query(on: db).filter(\.$consumerId == consumerId).all()
        guard existing.count < Self.maxPasskeys else { throw APIError.conflict("This account already has the maximum number of passkeys.") }
        let handle = try await Self.ensureUserHandle(consumerId, db: db)
        let label = try await ConsumerRecord.find(consumerId, on: db)?.label ?? ConsumerRecord.neutralLabel
        let challenge = Base64URL.encode(ctx.passkeys.makeChallenge())
        let ceremony = PasskeyCeremonyRecord(kind: "recovery_passkey", challenge: challenge, consumerId: consumerId, displayName: nil, userHandle: handle,
                                             now: ctx.now, ttl: AuthService.ceremonyTTL)
        try await ceremony.create(on: db)
        return PasskeyRegistrationOptions(ceremonyId: CeremonyID(ceremony.id!), challenge: challenge, relyingPartyId: ctx.config.relyingPartyID,
                                          relyingPartyName: ctx.config.relyingPartyName, userId: handle, userName: label, userDisplayName: label,
                                          timeoutMilliseconds: Int(AuthService.ceremonyTTL * 1000), excludeCredentialIds: existing.map(\.credentialId))
    }

    func passkeyFinish(_ principal: ConsumerPrincipal, request: RecoveryPasskeyFinishRequest) async throws -> RecoveryPasskeyAdded {
        try await ctx.limiter.enforce("recovery-passkey", key: principal.consumerId.description, rule: Self.rate)
        let now = ctx.now
        let device = try await DeviceTrust.require(principal, db: db, now: now)
        let consumerId = principal.consumerId.uuid
        let invalid = APIError(.unauthorized, .unauthorized, "This passkey could not be added. Start again.")
        guard let ceremony = try await PasskeyCeremonyRecord.find(request.ceremonyId.uuid, on: db), ceremony.kind == "recovery_passkey",
              ceremony.state == "open", ceremony.expiresAt > now, ceremony.consumerId == consumerId,
              let challenge = Base64URL.decode(ceremony.challenge), request.credential.id.count <= 1024 else { throw invalid }
        try await verifyProof(request.proof, ceremonyId: request.ceremonyId.uuid, principal: principal, device: device)
        guard try await DB.swap(db, table: PasskeyCeremonyRecord.schema, id: request.ceremonyId.uuid, column: "state", expected: "open", newValue: "used") else {
            throw invalid
        }
        let database = db
        let verified: VerifiedPasskeyRegistration
        do {
            verified = try await ctx.passkeys.verifyRegistration(request.credential, challenge: challenge) { credentialId in
                try await PasskeyCredentialRecord.query(on: database).filter(\.$credentialId == credentialId).count() > 0
            }
        } catch {
            _ = try? await AuditService(db: db, ctx: ctx).record("recovery.passkey_failed", outcome: .failure, principal: principal, subjectType: "recovery")
            throw invalid
        }
        let count: Int = try await db.transaction { tx in
            guard try await PasskeyCredentialRecord.query(on: tx).filter(\.$consumerId == consumerId).count() < Self.maxPasskeys else {
                throw APIError.conflict("This account already has the maximum number of passkeys.")
            }
            try await PasskeyCredentialRecord(consumerId: consumerId, credentialId: verified.credentialId, publicKey: Base64URL.encode(verified.publicKey),
                                              signCount: Int(verified.signCount), backupEligible: verified.backupEligible, now: now).create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("recovery.passkey_added", principal: principal, subjectType: "recovery",
                                                               metadata: ["backup_eligible": verified.backupEligible ? "true" : "false",
                                                                          "assurance": request.proof.assurance.rawValue])
            return try await PasskeyCredentialRecord.query(on: tx).filter(\.$consumerId == consumerId).count()
        }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: consumerId, except: device.id, notice: .recoveryCredentialAdded)
        return RecoveryPasskeyAdded(backupEligible: verified.backupEligible, passkeyCount: count)
    }
}
