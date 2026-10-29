import Fluent
import Foundation
import ViadereCore

/// Device-first pseudonymous account creation (WP-B4, ADR-0013, SECURITY.md §2.5a).
///
/// 1. `begin` (public): a single-use challenge and a **reserved** account id. Nothing about existing accounts is revealed; the route has a
///    per-IP budget (middleware), a global budget, and the `signup.consumer` kill switch.
/// 2. `create` (public): every key proves possession over `VIADERE-ENROLL-V1` with the reserved id and the challenge; the integrity evidence is
///    evaluated under `APP_ATTEST_MODE` (an App Attest key backs one device only); the ceremony is consumed by compare-and-swap **after**
///    every other check passed; then one transaction creates the account (no name, no handle), the device (tier per `TrustTierPolicy`), its
///    keys, the attested App Attest key and a session already bound to the device. Accounts per App Attest environment and address bucket are
///    rationed per hour (a farm of devices behind one network cannot mint accounts at will).
struct AccountEnrollmentService {
    let db: any Database
    let ctx: ServerContext

    static let ceremonyTTL: TimeInterval = 5 * 60
    /// The label for the device list when the client sends none.
    static func defaultDeviceName(_ platform: DevicePlatform, kind: DeviceClientKind) -> String {
        let base: String
        switch platform {
        case .iOS: base = "iPhone"
        case .iPadOS: base = "iPad"
        case .watchOS: base = "Apple Watch"
        case .macOS: base = "Mac"
        case .android: base = "Android phone"
        case .web: base = "Browser"
        }
        return kind == .appClip ? "\(base) (App Clip)" : base
    }

    // MARK: Begin

    func begin() async throws -> AccountEnrollBeginResponse {
        try await ctx.limiter.enforce("account-enroll-begin-global", key: "all", rule: ctx.config.rateLimits.accountEnrollGlobal)
        let challenge = SecureToken.generate()
        let ceremony = AccountEnrollCeremonyRecord(reservedAccountId: UUID(), challengeHash: SecureToken.hash(challenge), now: ctx.now, ttl: Self.ceremonyTTL)
        try await ceremony.create(on: db)
        let mode = ctx.config.appAttestMode
        return AccountEnrollBeginResponse(ceremonyId: CeremonyID(ceremony.id!), accountId: ConsumerID(ceremony.reservedAccountId), challenge: challenge,
                                          expiresAt: ceremony.expiresAt,
                                          integrity: IntegrityRequirement(required: mode == .require ? [.appleAppAttest] : [], accepted: [.appleAppAttest]))
    }

    // MARK: Create

    /// The rate-limit bucket for "accounts per App Attest environment and network": the attested environment (or `unattested`) and the
    /// client's /24 (IPv4) or /64 (IPv6, as `ClientIP` already keys it).
    static func bucket(clientIP: String, environment: String?) -> String {
        var network = clientIP
        if !clientIP.contains(":") {
            let octets = clientIP.split(separator: ".")
            if octets.count == 4 { network = octets.prefix(3).joined(separator: ".") + ".0/24" }
        }
        return "\(environment ?? "unattested")|\(network)"
    }

    private func refused(_ reason: String, accountId: UUID? = nil) async {
        _ = try? await AuditService(db: db, ctx: ctx).record("account.create_failed", outcome: .failure, actor: AuditActor(kind: .system),
                                                            metadata: ["reason": reason])
    }

    func create(_ request: AccountCreateRequest, clientIP: String) async throws -> AccountCreateResponse {
        try await ctx.limiter.enforce("account-create-global", key: "all", rule: ctx.config.rateLimits.accountCreateGlobal)
        let invalid = APIError(.unauthorized, .unauthorized, "This sign-up could not be verified. Start again.")
        let now = ctx.now
        let kind = request.clientKind

        // Shape first: nothing below runs for a malformed request.
        try AuthService.validateKeysAndEvidence(request.keys, conflictingIntegrity: false)
        let purposes = request.keys.map(\.purpose)
        guard purposes.contains(.request), Set(purposes).count == purposes.count, request.keys.count <= DeviceKeyPurpose.allCases.count else {
            throw APIError.validation("Provide exactly one key per purpose, including a request key.", details: ["keys": "invalid"])
        }
        if kind == .appClip, purposes != [.request] {
            throw APIError.validation("An App Clip device can only register a request key.", details: ["keys": "appClipRequestKeyOnly"])
        }
        let name = (request.deviceName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard name.count <= 64, !DisplayTextSanitizer.containsDisallowedScalars(name) else {
            throw APIError.validation("A device name can have up to 64 characters.", details: ["deviceName": "invalid"])
        }
        let deviceName = name.isEmpty ? Self.defaultDeviceName(request.platform, kind: kind) : name

        // The ceremony: open, unexpired, and this exact challenge (constant-time hash comparison). Every failure is the same 401.
        guard request.challenge.count <= 128, let ceremony = try await AccountEnrollCeremonyRecord.find(request.ceremonyId.uuid, on: db),
              ceremony.state == "open", ceremony.expiresAt > now,
              ConstantTime.equals(ceremony.challengeHash, SecureToken.hash(request.challenge)) else {
            await refused("ceremony_invalid")
            throw invalid
        }
        let accountId = ConsumerID(ceremony.reservedAccountId)
        for key in request.keys where !DeviceEnrollment.verify(key, consumerId: accountId, challenge: request.challenge) {
            await refused("bad_proof")
            throw invalid
        }

        // Integrity under policy. An App Attest key vouches for one device, ever.
        let mode = ctx.config.appAttestMode
        let evidence = request.integrity
        let verified = await ctx.integrity.verifyEnrollment(integrity: evidence, consumerId: accountId, challenge: request.challenge,
                                                            keys: request.keys, clientKind: kind)
        var attestation = verified
        if verified.attested, let keyId = verified.keyId, try await AppAttestKeyRecord.query(on: db).filter(\.$keyId == keyId).count() > 0 {
            attestation = AttestationResult(attested: false, reason: "key_reused", format: verified.format)
        }
        if mode == .require, !attestation.attested {
            await refused("attestation_required:\(attestation.reason)")
            throw APIError(.forbidden, .attestationRequired, "This device could not be verified. Update Viadere and try again on a genuine device.")
        }

        // Anti-farming budget per App Attest environment and network. Charged now, refunded if the creation does not happen.
        let bucket = Self.bucket(clientIP: clientIP, environment: attestation.attested ? attestation.environment : nil)
        try await ctx.limiter.enforce("account-create-bucket", key: bucket, rule: ctx.config.rateLimits.accountCreatePerBucket)
        do {
            // Consumed only now that the request is otherwise acceptable; one ceremony, one account, whoever races.
            guard try await DB.swap(db, table: AccountEnrollCeremonyRecord.schema, id: ceremony.id!, column: "state", expected: "open", newValue: "used") else {
                await refused("ceremony_used")
                throw invalid
            }
            let response = try await persist(accountId: accountId.uuid, request: request, deviceName: deviceName, attestation: attestation, evidence: evidence,
                                              mode: mode, now: now)
            return response
        } catch {
            await ctx.limiter.refund("account-create-bucket", key: bucket, rule: ctx.config.rateLimits.accountCreatePerBucket)
            if error.isConstraintViolation {
                if attestation.attested { throw APIError.conflict("This attestation was already used.") }
                throw invalid
            }
            throw error
        }
    }

    private func persist(accountId: UUID, request: AccountCreateRequest, deviceName: String, attestation: AttestationResult, evidence: IntegrityEvidence?,
                         mode: AppAttestMode, now: Date) async throws -> AccountCreateResponse {
        let kind = request.clientKind
        let purposes = request.keys.map(\.purpose)
        let uvKey = purposes.contains(.approvalBiometric) || purposes.contains(.approvalUserPresence)
        // A brand-new account: this is its first app device, and it was never recovered.
        let elevation = TrustTierPolicy.initialElevation(DeviceTrustFacts(
            isFullApp: kind == .app, revoked: false, expired: false, hasUserVerifiedApprovalKey: uvKey, integrityVerified: attestation.attested,
            integrityRequired: mode != .off, firstAppDeviceOfAccount: true, accountRecovered: false))
        let device = DeviceRecord(consumerId: accountId, name: deviceName, platform: request.platform, now: now, clientKind: kind)
        device.enrollmentMethod = "account_create"
        device.attestationStatus = attestation.attested ? "attested" : (evidence == nil ? "unattested" : "rejected")
        device.integrityFormat = evidence?.format.rawValue
        device.expiresAt = kind == .appClip ? now.addingTimeInterval(AuthService.appClipLifetime) : nil
        if let elevation {
            device.trustTier = DeviceTrustTier.d1.rawValue
            device.elevatedAt = now
            device.elevatedBy = elevation.rawValue
        }
        let keyRecords = request.keys.map { DeviceKeyRecord(deviceId: device.id!, purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: $0.hardwareBacked,
                                                           now: now, attested: attestation.attested) }
        let issued: ConsumerTokenService.IssuedSession = try await db.transaction { tx in
            try await ConsumerRecord(id: accountId, displayName: nil, userHandle: nil, now: now, createdVia: "device").create(on: tx)
            try await device.create(on: tx)
            for key in keyRecords { try await key.create(on: tx) }
            if attestation.attested, let keyId = attestation.keyId, let publicKey = attestation.publicKey {
                try await AppAttestKeyRecord(deviceId: device.id!, consumerId: accountId, keyId: keyId, publicKey: publicKey, counter: attestation.counter,
                                             environment: attestation.environment ?? "production", now: now, format: evidence?.format ?? .appleAppAttest).create(on: tx)
            }
            // The session belongs to this device from the first request: no fresh-session enrollment window.
            let issued = try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: accountId, origin: "account_create")
            device.familyId = issued.familyId
            try await device.update(on: tx)
            try await TokenFamilyRecord.query(on: tx).filter(\.$id == issued.familyId).set(\.$deviceId, to: device.id!).set(\.$enrollUntil, to: nil)
                .set(\.$expiresAt, to: device.expiresAt).update()
            if let cap = device.expiresAt {
                try await AccessTokenRecord.query(on: tx).filter(\.$familyId == issued.familyId).filter(\.$expiresAt > cap).set(\.$expiresAt, to: cap).update()
                try await RefreshTokenRecord.query(on: tx).filter(\.$familyId == issued.familyId).filter(\.$expiresAt > cap).set(\.$expiresAt, to: cap).update()
            }
            var metadata = ["platform": request.platform.rawValue, "client_kind": kind.rawValue, "tier": device.trustTier,
                            "attested": attestation.attested ? "true" : "false", "attestation": attestation.reason, "attest_mode": mode.rawValue,
                            "integrity_format": evidence?.rawFormat ?? "none", "max_assurance": Device.maxAssurance(keys: request.keys).rawValue]
            if mode == .report, !attestation.attested { metadata["flagged"] = "unattested" }
            let audit = AuditService(db: tx, ctx: ctx)
            _ = try await audit.record("account.created", actor: AuditActor(kind: .device, id: DeviceID(device.id!).description), consumerId: ConsumerID(accountId),
                                       subjectType: "device", subjectId: DeviceID(device.id!).description, metadata: metadata)
            return issued
        }
        let cappedAccess = device.expiresAt.map { min($0, issued.accessExpiresAt) } ?? issued.accessExpiresAt
        let cappedRefresh = device.expiresAt.map { min($0, issued.refreshExpiresAt) } ?? issued.refreshExpiresAt
        let session = AuthSession(consumerId: ConsumerID(accountId), accessToken: issued.accessToken, expiresAt: cappedAccess,
                                  refreshToken: issued.refreshToken, refreshExpiresAt: cappedRefresh)
        let dto = AuthService.deviceDTO(device, keys: keyRecords, now: now)
        return AccountCreateResponse(accountId: ConsumerID(accountId), device: dto, session: session)
    }
}
