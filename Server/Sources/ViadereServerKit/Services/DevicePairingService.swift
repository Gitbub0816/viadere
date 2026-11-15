import Fluent
import Foundation
import SQLKit
import ViadereCore

/// Device pairing (WP-D1, SECURITY.md §2.107): adds a device to an account that has no passkey, by approval from one of its D1 devices.
///
/// * **Only the server names the account.** A D1 device makes a pairing code; the new device sends the code, never an account id. Nothing the
///   new device says (a tier, a name, an account) decides anything.
/// * **The nonce comes after the keys.** `start` stores the new device's proven keys and only then draws the 256-bit nonce; the comparison
///   digest binds pairing id, nonce and the key list, and the code the person reads off the new device comes from it.
/// * **Approval** is a biometric `VIADERE-PAIR-V1` statement from a **D1** device of the **same** account, fresh, bound to the stored pairing,
///   with the number the person typed; single use (replay guard on the statement, compare-and-swap on the state). Only then is the device
///   created, at D1 when it meets every D1 condition (an approval by a D1 device is the documented path to D1, §2.5a), D0 otherwise.
/// * Abuse: per-IP and per-account budgets (fail closed), one pending pairing per account (a new one cancels the old), ADR-0022 fatigue
///   rules for the alert, three wrong numbers end the pairing, an audit event for every state change and a notice on every other device.
struct DevicePairingService {
    let db: any Database
    let ctx: ServerContext

    static let pushBody = "Someone wants to add a device to your Viadere account. Open Viadere to review it."
    static let pushCategory = "viadere.security.pairing"

    static var noTrustedDevice: APIError {
        APIError(.conflict, .noTrustedDevice,
                 "No device on this account can approve a new one. To get back into your account, use account recovery with your recovery codes.",
                 details: ["recovery": "account_recovery"])
    }

    private static var invalid: APIError {
        APIError(.unauthorized, .unauthorized, "This code didn't work. Check it on your other device, or make a new one there.")
    }

    func codeHash(_ normalized: String) -> String { ctx.hasher.hmacHex("device-pairing-code", normalized) }

    // MARK: Audit

    private func audit(_ action: String, outcome: AuditEvent.Outcome = .success, account: UUID?, pairing: UUID?, device: UUID? = nil,
                       metadata: [String: String] = [:], on database: (any Database)? = nil) async throws {
        let actor = device.map { AuditActor(kind: .device, id: DeviceID($0).description) } ?? AuditActor(kind: .system)
        _ = try await AuditService(db: database ?? db, ctx: ctx).record(action, outcome: outcome, actor: actor, consumerId: account.map(ConsumerID.init),
                                                                          subjectType: "device_pairing", subjectId: pairing.map { DevicePairingID($0).description },
                                                                          metadata: metadata)
    }

    /// `device_pairing.refused` (best effort: the refusal itself must not fail on the audit write).
    private func refused(_ reason: String, account: UUID?, pairing: UUID?, device: UUID? = nil) async {
        try? await audit("device_pairing.refused", outcome: .failure, account: account, pairing: pairing, device: device, metadata: ["reason": reason])
    }

    // MARK: Invitation (trusted device)

    func invite(_ principal: ConsumerPrincipal) async throws -> DevicePairingInvitation {
        let now = ctx.now
        let account = principal.consumerId.uuid
        let device = try await DeviceTrust.requireActiveApp(principal, db: db, now: now)
        guard DeviceTrust.isTrusted(device, at: now) else {
            await refused("inviter_not_d1", account: account, pairing: nil, device: device.id)
            if try await !DeviceTrust.accountHasTrustedDevice(account, except: nil, db: db, now: now) { throw Self.noTrustedDevice }
            throw DeviceTrust.notTrustedError(device, at: now)
        }
        try await ctx.limiter.enforce("device-pairing-invite", key: principal.consumerId.description, rule: ctx.config.rateLimits.devicePairingInvitePerAccount)
        let code = DevicePairingCode.generate()
        guard let normalized = DevicePairingCode.normalize(code) else { throw APIError.internalError }
        let record = DevicePairingInvitationRecord(consumerId: account, codeHash: codeHash(normalized), createdBy: device.id!, now: now)
        try await db.transaction { tx in
            // One live code per account: a new one revokes the previous.
            try await DevicePairingInvitationRecord.query(on: tx).filter(\.$consumerId == account).filter(\.$state == "open").set(\.$state, to: "revoked").update()
            try await record.create(on: tx)
            try await audit("device_pairing.invited", account: account, pairing: nil, device: device.id, metadata: ["invitation": record.id!.uuidString.lowercased()], on: tx)
        }
        return DevicePairingInvitation(code: code, expiresAt: record.expiresAt)
    }

    // MARK: New device

    func begin(clientIP: String) async throws -> DevicePairingBeginResponse {
        try await ctx.limiter.enforce("device-pairing-begin", key: clientIP, rule: ctx.config.rateLimits.devicePairingBeginPerIP)
        let challenge = SecureToken.generate()
        let record = DevicePairingRecord(challengeHash: SecureToken.hash(challenge), now: ctx.now)
        try await record.create(on: db)
        let mode = ctx.config.appAttestMode
        return DevicePairingBeginResponse(pairingId: DevicePairingID(record.id!), challenge: challenge, expiresAt: record.expiresAt,
                                          integrity: IntegrityRequirement(required: mode == .require ? [.appleAppAttest] : [], accepted: [.appleAppAttest]))
    }

    func start(pairingId: DevicePairingID, request: DevicePairingStartRequest, clientIP: String) async throws -> DevicePairingStartResponse {
        try await ctx.limiter.enforce("device-pairing-start", key: clientIP, rule: ctx.config.rateLimits.devicePairingStartPerIP)
        let now = ctx.now
        let id = pairingId.uuid

        // Shape first.
        try AuthService.validateKeysAndEvidence(request.keys, conflictingIntegrity: false)
        let purposes = request.keys.map(\.purpose)
        guard purposes.contains(.request), Set(purposes).count == purposes.count, request.keys.count <= DeviceKeyPurpose.allCases.count else {
            throw APIError.validation("Provide exactly one key per purpose, including a request key.", details: ["keys": "invalid"])
        }
        let name = (request.deviceName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard name.count <= 64, !DisplayTextSanitizer.containsDisallowedScalars(name) else {
            throw APIError.validation("A device name can have up to 64 characters.", details: ["deviceName": "invalid"])
        }
        let deviceName = name.isEmpty ? AccountEnrollmentService.defaultDeviceName(request.platform, kind: .app) : name

        // The ceremony: this exact challenge, unexpired, not started yet. Every failure is the same 401.
        guard request.challenge.count <= 128, let pairing = try await DevicePairingRecord.find(id, on: db), pairing.state == "ceremony",
              pairing.expiresAt > now, ConstantTime.equals(pairing.challengeHash, SecureToken.hash(request.challenge)) else {
            await refused("ceremony_invalid", account: nil, pairing: id)
            throw Self.invalid
        }
        let subject = ConsumerID(id)
        for key in request.keys where !DeviceEnrollment.verify(key, consumerId: subject, challenge: request.challenge) {
            await refused("bad_proof", account: nil, pairing: id)
            throw Self.invalid
        }

        // Integrity under policy, bound to this pairing, challenge and key list. An App Attest key vouches for one device, ever.
        let mode = ctx.config.appAttestMode
        let verified = await ctx.integrity.verifyEnrollment(integrity: request.integrity, consumerId: subject, challenge: request.challenge,
                                                            keys: request.keys, clientKind: .app)
        let reused: Bool
        if verified.attested, let keyId = verified.keyId { reused = try await AppAttestKeyRecord.query(on: db).filter(\.$keyId == keyId).count() > 0 } else { reused = false }
        let attestation = reused ? AttestationResult(attested: false, reason: "key_reused", format: verified.format) : verified
        if mode == .require, !attestation.attested {
            await refused("attestation_required:\(attestation.reason)", account: nil, pairing: id)
            throw APIError(.forbidden, .attestationRequired, "This device could not be verified. Update Viadere and try again on a genuine device.")
        }

        // The code names the account, to the server only.
        guard request.pairingCode.count <= 64, let normalized = DevicePairingCode.normalize(request.pairingCode),
              let invitation = try await DevicePairingInvitationRecord.query(on: db).filter(\.$codeHash == codeHash(normalized)).first(),
              invitation.state == "open", invitation.expiresAt > now else {
            await refused("code_invalid", account: nil, pairing: id)
            throw Self.invalid
        }
        let account = invitation.consumerId
        do {
            try await ctx.limiter.enforce("device-pairing-account", key: account.uuidString.lowercased(), rule: ctx.config.rateLimits.devicePairingStartPerAccount)
        } catch {
            await refused("account_budget", account: account, pairing: id)
            throw error
        }
        // Someone must be able to approve: without a live D1 device the way back is account recovery, never pairing.
        guard try await DeviceTrust.accountHasTrustedDevice(account, except: nil, db: db, now: now) else {
            await refused("no_trusted_device", account: account, pairing: id)
            throw Self.noTrustedDevice
        }
        guard try await DeviceRecord.query(on: db).filter(\.$consumerId == account).filter(\.$revokedAt == nil).count() < AuthService.maxDevicesPerConsumer else {
            await refused("too_many_devices", account: account, pairing: id)
            throw APIError.conflict("This account has too many devices. Remove one on your other device first.")
        }
        let (silent, warning) = try await fatigue(account: account, now: now)

        // The nonce is drawn now, after the keys are fixed.
        let nonce = SecureToken.generate()
        let statusToken = SecureToken.generate()
        let keyListDigest = AppAttestBinding.keyListDigest(request.keys)
        let digest = DevicePairing.comparisonDigest(pairingId: pairingId, nonce: nonce, keyListDigest: keyListDigest)
        // Whole seconds: the expiry is signed as ISO-8601 milliseconds and must survive every database's datetime precision unchanged.
        let expires = Date(timeIntervalSince1970: (now.timeIntervalSince1970 + DevicePairing.pairingTTL).rounded(.down))
        let keysJSON = String(decoding: try ViadereJSON.encode(request.keys.map { StoredPairingKey(purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: $0.hardwareBacked) }),
                              as: UTF8.self)
        let attestationJSON = String(decoding: try ViadereJSON.encode(StoredPairingAttestation(
            attested: attestation.attested, reason: attestation.reason, keyId: attestation.keyId, publicKey: attestation.publicKey,
            counter: attestation.counter, environment: attestation.environment)), as: UTF8.self)
        let format: String? = request.integrity?.rawFormat
        do {
            try await db.transaction { tx in
                guard try await DB.swap(tx, table: DevicePairingInvitationRecord.schema, id: invitation.id!, column: "state", expected: "open", newValue: "used",
                                        extra: [("used_at", now)]) else { throw Self.invalid }
                // One pending pairing per account: the new one cancels the old (as for the key-log device add, ADR-0033 §4.1 item 3).
                for old in try await DevicePairingRecord.query(on: tx).filter(\.$consumerId == account).filter(\.$state == "pending").all() {
                    if try await DB.swap(tx, table: DevicePairingRecord.schema, id: old.id!, column: "state", expected: "pending", newValue: "cancelled",
                                         extra: [("end_reason", "superseded"), ("decided_at", now)]) {
                        try await audit("device_pairing.cancelled", account: account, pairing: old.id, metadata: ["reason": "superseded", "by": pairingId.description], on: tx)
                    }
                }
                guard try await DB.swap(tx, table: DevicePairingRecord.schema, id: id, column: "state", expected: "ceremony", newValue: "pending", extra: [
                    ("consumer_id", account), ("invitation_id", invitation.id!), ("nonce", nonce), ("device_name", deviceName),
                    ("platform", request.platform.rawValue), ("keys_json", keysJSON), ("key_list_digest", keyListDigest), ("comparison_digest", digest),
                    ("status_token_hash", SecureToken.hash(statusToken)), ("attestation_json", attestationJSON), ("integrity_format", format),
                    ("silent", silent), ("fatigue_warning", warning), ("started_at", now), ("expires_at", expires),
                ]) else { throw Self.invalid }
                var metadata = ["platform": request.platform.rawValue, "attested": attestation.attested ? "true" : "false", "attestation": attestation.reason,
                                "attest_mode": mode.rawValue, "silent": silent ? "true" : "false", "fatigue_warning": warning ? "true" : "false",
                                "max_assurance": Device.maxAssurance(keys: request.keys).rawValue]
                if mode == .report, !attestation.attested { metadata["flagged"] = "unattested" }
                try await audit("device_pairing.started", account: account, pairing: id, metadata: metadata, on: tx)
            }
        } catch let error as APIError {
            await refused("start_conflict", account: account, pairing: id)
            throw error
        } catch {
            if error.isConstraintViolation {
                await refused("concurrent_start", account: account, pairing: id)
                throw APIError.conflict("Another device is being added to this account right now. Try again in a moment.")
            }
            throw error
        }
        if !silent { await pushRequest(account: account) }
        return DevicePairingStartResponse(pairingId: pairingId, nonce: nonce, expiresAt: expires, statusToken: statusToken)
    }

    /// ADR-0022 §5.1 applied to pairings: from the third pairing in an hour the approving device shows the fatigue warning; after three denials
    /// or reports in the window (pause), or above the hourly budget, the request is still created but delivered silently (no alert push; the
    /// approving device finds it when it opens Viadere). Open pairings never silence the next one.
    func fatigue(account: UUID, now: Date) async throws -> (silent: Bool, warning: Bool) {
        let policy = ApprovalPromptPolicy.standard
        let rows = try await DevicePairingRecord.query(on: db).filter(\.$consumerId == account)
            .filter(\.$startedAt > now.addingTimeInterval(-policy.window)).all()
        let history: [ApprovalPromptPolicy.Record] = rows.compactMap { row in
            guard let started = row.startedAt else { return nil }
            let decision: ApprovalDecision? = row.state == "denied" ? (row.endReason == "report" ? .report : .deny) : nil
            return ApprovalPromptPolicy.Record(createdAt: started, decision: decision, isOpen: row.state == "pending")
        }
        switch policy.evaluate(history: history, now: now, limitOpenRequests: false) {
        case .allow(_, let showWarning): return (false, showWarning)
        case .rateLimited, .autoDeny: return (true, true)
        }
    }

    /// The alert to the account's D1 devices (the only ones that can approve). Lock-screen safe: no name, code or number.
    func pushRequest(account: UUID) async {
        let now = ctx.now
        do {
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == account).filter(\.$revokedAt == nil).all()
                .filter { DeviceTrust.isTrusted($0, at: now) }
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let record = token.record
                let message = PushMessage(deviceToken: record.token, environment: record.environment,
                                          topic: record.bundleId.isEmpty ? ctx.config.appBundleID : record.bundleId, title: PushPayloadBuilder.genericTitle,
                                          body: Self.pushBody, category: Self.pushCategory, threadID: "viadere.security", interruptionLevel: "active",
                                          mutableContent: false, interactionId: nil, highPriority: true)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: now).update()
                }
            }
        } catch {
            // Best effort: the pending list is the source of truth.
        }
    }

    private func authenticate(_ pairingId: DevicePairingID, token: String) async throws -> DevicePairingRecord {
        guard token.count <= 128, let pairing = try await DevicePairingRecord.find(pairingId.uuid, on: db), let hash = pairing.statusTokenHash,
              ConstantTime.equals(hash, SecureToken.hash(token)) else {
            throw APIError(.unauthorized, .unauthorized, "This request is no longer valid. Start again.")
        }
        return pairing
    }

    func status(pairingId: DevicePairingID, request: DevicePairingStatusRequest, clientIP: String) async throws -> DevicePairingStatus {
        try await ctx.limiter.enforce("device-pairing-status", key: clientIP, rule: ctx.config.rateLimits.devicePairingStatusPerIP)
        var pairing = try await authenticate(pairingId, token: request.statusToken)
        pairing = try await expireIfDue(pairing)
        let now = ctx.now
        var status = DevicePairingStatus(pairingId: pairingId, state: DevicePairingState(rawValue: pairing.state) ?? .unknown, expiresAt: pairing.expiresAt)
        guard pairing.state == "approved", pairing.sessionIssuedAt == nil, let newId = pairing.newDeviceId, let account = pairing.consumerId,
              let decided = pairing.decidedAt, now.timeIntervalSince(decided) <= DevicePairing.sessionPickupWindow,
              let device = try await DeviceRecord.find(newId, on: db), device.revokedAt == nil else { return status }
        // Exactly once: the first poll after approval gets a session already bound to the new device.
        let issued: ConsumerTokenService.IssuedSession? = try await db.transaction { tx in
            guard try await DB.swapFromNull(tx, table: DevicePairingRecord.schema, id: pairingId.uuid, column: "session_issued_at", newValue: now) else { return nil }
            let issued = try await ConsumerTokenService(db: tx, ctx: ctx).startSession(consumerId: account, origin: "device_pairing")
            try await TokenFamilyRecord.query(on: tx).filter(\.$id == issued.familyId).set(\.$deviceId, to: newId).set(\.$enrollUntil, to: nil).update()
            try await DeviceRecord.query(on: tx).filter(\.$id == newId).set(\.$familyId, to: issued.familyId).update()
            try await audit("device_pairing.completed", account: account, pairing: pairingId.uuid, device: newId, on: tx)
            return issued
        }
        guard let issued else { return status }
        let keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == newId).all()
        status.device = AuthService.deviceDTO(device, keys: keys, now: now)
        status.session = AuthSession(consumerId: ConsumerID(account), accessToken: issued.accessToken, expiresAt: issued.accessExpiresAt,
                                     refreshToken: issued.refreshToken, refreshExpiresAt: issued.refreshExpiresAt)
        return status
    }

    func cancel(pairingId: DevicePairingID, request: DevicePairingStatusRequest, clientIP: String) async throws -> DevicePairingStatus {
        try await ctx.limiter.enforce("device-pairing-status", key: clientIP, rule: ctx.config.rateLimits.devicePairingStatusPerIP)
        var pairing = try await authenticate(pairingId, token: request.statusToken)
        pairing = try await expireIfDue(pairing)
        if pairing.state == "pending",
           try await DB.swap(db, table: DevicePairingRecord.schema, id: pairingId.uuid, column: "state", expected: "pending", newValue: "cancelled",
                             extra: [("end_reason", "cancelled_by_new_device"), ("decided_at", ctx.now)]) {
            try await audit("device_pairing.cancelled", account: pairing.consumerId, pairing: pairingId.uuid, metadata: ["reason": "cancelled_by_new_device"])
            pairing.state = "cancelled"
        }
        return DevicePairingStatus(pairingId: pairingId, state: DevicePairingState(rawValue: pairing.state) ?? .unknown, expiresAt: pairing.expiresAt)
    }

    // MARK: Trusted device

    /// The account's pending pairing, for a D1 device only. The first D1 device that lists it records `device_pairing.shown`.
    func pending(_ principal: ConsumerPrincipal) async throws -> [DevicePairingRequest] {
        let now = ctx.now
        let account = principal.consumerId.uuid
        let device = try await DeviceTrust.requireActiveApp(principal, db: db, now: now)
        var rows: [DevicePairingRecord] = []
        for row in try await DevicePairingRecord.query(on: db).filter(\.$consumerId == account).filter(\.$state == "pending").all() {
            let current = try await expireIfDue(row)
            if current.state == "pending" { rows.append(current) }
        }
        guard DeviceTrust.isTrusted(device, at: now) else { return [] }
        var out: [DevicePairingRequest] = []
        for row in rows {
            guard let request = view(row) else { continue }
            if row.shownAt == nil, try await DB.swapFromNull(db, table: DevicePairingRecord.schema, id: row.id!, column: "shown_at", newValue: now) {
                try await audit("device_pairing.shown", account: account, pairing: row.id, device: device.id)
            }
            out.append(request)
        }
        return out
    }

    private func storedKeys(_ row: DevicePairingRecord) -> [StoredPairingKey]? {
        row.keysJSON.flatMap { try? ViadereJSON.decode([StoredPairingKey].self, from: Data($0.utf8)) }
    }

    private func view(_ row: DevicePairingRecord) -> DevicePairingRequest? {
        guard let id = row.id, let account = row.consumerId, let nonce = row.nonce, let keys = storedKeys(row), let kld = row.keyListDigest,
              let digest = row.comparisonDigest, let started = row.startedAt else { return nil }
        let attested = row.attestationJSON.flatMap { try? ViadereJSON.decode(StoredPairingAttestation.self, from: Data($0.utf8)) }?.attested ?? false
        return DevicePairingRequest(pairingId: DevicePairingID(id), accountId: ConsumerID(account), nonce: nonce,
                                    deviceName: String((row.deviceName ?? "").prefix(64)),
                                    platform: DevicePlatform(rawValue: row.platform ?? "") ?? .iOS,
                                    keys: keys.map { DevicePairingKey(purpose: $0.purpose, publicKey: $0.publicKey) }, newDeviceKeys: kld,
                                    comparisonDigest: digest, requestedAt: started, expiresAt: row.expiresAt,
                                    attemptsRemaining: max(0, DevicePairing.maxWrongEntries - row.attempts), fatigueWarning: row.fatigueWarning,
                                    integrityVerified: attested)
    }

    func approve(_ principal: ConsumerPrincipal, pairingId: DevicePairingID, approval: DevicePairingApproval) async throws -> DevicePairingApproveResponse {
        let now = ctx.now
        let account = principal.consumerId.uuid
        let id = pairingId.uuid
        try await ctx.limiter.enforce("device-pairing-approve", key: principal.consumerId.description, rule: ctx.config.rateLimits.devicePairingApprovePerAccount)
        func refuse(_ reason: String, _ error: APIError) async -> APIError {
            await refused(reason, account: account, pairing: id, device: principal.deviceId?.uuid)
            return error
        }

        // 1. The approving device: the caller, of this account, D1. A D0 device can never approve.
        guard let callerId = principal.deviceId, let caller = try await DeviceRecord.find(callerId.uuid, on: db), caller.consumerId == account else {
            throw APIError.signatureInvalid
        }
        guard approval.approverDeviceId == callerId else { throw await refuse("approver_not_caller", .forbidden) }
        guard DeviceTrust.isTrusted(caller, at: now) else { throw await refuse("approver_not_d1", DeviceTrust.notTrustedError(caller, at: now)) }

        // 2. The pairing is this account's (another account's pairing is simply not found).
        guard let pairing = try await DevicePairingRecord.find(id, on: db), pairing.consumerId == account, let nonce = pairing.nonce,
              let keyListDigest = pairing.keyListDigest, let digest = pairing.comparisonDigest else {
            throw await refuse("not_this_account", .notFound)
        }

        // 3. The statement names exactly this pairing as stored: account, pairing, nonce, the new device's keys, the expiry and the digest.
        guard approval.isBound(accountId: principal.consumerId, pairingId: pairingId, nonce: nonce, newDeviceKeys: keyListDigest, expiresAt: pairing.expiresAt),
              ConstantTime.equals(digest, approval.comparisonDigest) else {
            throw await refuse("binding_mismatch", APIError(.conflict, .pairingMismatch,
                                                           "This request doesn't match the new device, so nothing was added. Start again on the new device."))
        }

        // 4. Signed by this device's registered biometric key, fresh.
        guard let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == callerId.uuid)
                .filter(\.$purpose == DeviceKeyPurpose.approvalBiometric.rawValue).first(),
              let registered = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
            throw await refuse("no_biometric_key", APIError(.forbidden, .insufficientAssurance, "Approve with Face ID on a device you already trust."))
        }
        do {
            try approval.verify(registeredKey: registered, now: now)
        } catch DevicePairingApproval.Failure.assuranceTooLow {
            throw await refuse("assurance_too_low", APIError(.forbidden, .insufficientAssurance, "Approve with Face ID on a device you already trust."))
        } catch {
            throw await refuse("bad_signature:\(error)", .signatureInvalid)
        }

        // 5. Single use of this statement (content-keyed, never the signature string).
        guard try await DatabaseReplayGuard(db: db).registerIfFresh(nonce: approval.replayKey, scope: "pair:\(callerId)",
                                                                   expiresAt: approval.signedAt.addingTimeInterval(DevicePairingApproval.maxAge + DevicePairingApproval.allowedFutureSkew),
                                                                   now: now) else {
            throw await refuse("replayed", APIError(.unauthorized, .replayDetected, "This approval was already used."))
        }

        // 6. Still pending and unexpired.
        let current = try await expireIfDue(pairing)
        guard current.state == "pending", current.expiresAt > now else {
            if current.state == "expired" { throw await refuse("expired", APIError(.gone, .expired, "This request expired. Start again on the new device.")) }
            throw await refuse("not_pending:\(current.state)", APIError.conflict("This request was already answered."))
        }

        // 7. The number the person read off the new device. Three wrong numbers end the pairing.
        guard approval.matchesCode(of: digest) else { throw try await wrongNumber(pairing: current, account: account, device: callerId.uuid) }

        // 8. Add the device. The compare-and-swap decides between concurrent approvals; everything else is in the same transaction.
        guard try await DeviceRecord.query(on: db).filter(\.$consumerId == account).filter(\.$revokedAt == nil).count() < AuthService.maxDevicesPerConsumer else {
            throw await refuse("too_many_devices", APIError.conflict("This account has too many devices. Remove one first."))
        }
        guard let keys = storedKeys(current), !keys.isEmpty else { throw APIError.internalError }
        let attestation = current.attestationJSON.flatMap { try? ViadereJSON.decode(StoredPairingAttestation.self, from: Data($0.utf8)) }
            ?? StoredPairingAttestation(attested: false, reason: "not_provided", keyId: nil, publicKey: nil, counter: 0, environment: nil)
        let mode = ctx.config.appAttestMode
        let purposes = Set(keys.map(\.purpose))
        let facts = DeviceTrustFacts(isFullApp: true, revoked: false, expired: false,
                                     hasUserVerifiedApprovalKey: purposes.contains(.approvalBiometric) || purposes.contains(.approvalUserPresence),
                                     integrityVerified: attestation.attested, integrityRequired: mode != .off)
        let elevate = TrustTierPolicy.mayElevate(target: facts, approverTier: DeviceTrust.tier(caller, at: now))
        let platform = DevicePlatform(rawValue: current.platform ?? "") ?? .iOS
        let device = DeviceRecord(consumerId: account, name: current.deviceName ?? AccountEnrollmentService.defaultDeviceName(platform, kind: .app),
                                  platform: platform, now: now, clientKind: .app)
        device.enrollmentMethod = "device_pairing"
        device.attestationStatus = attestation.attested ? "attested" : (current.integrityFormat == nil ? "unattested" : "rejected")
        device.integrityFormat = current.integrityFormat
        device.keyAlgorithm = DeviceKeyAlgorithm.es256.rawValue
        // Approved by a D1 device now: there is no notice window to wait out (§2.17), and the window never elevates anything anyway.
        device.approvalsLockedUntil = nil
        device.confirmedAt = now
        if elevate {
            device.trustTier = DeviceTrustTier.d1.rawValue
            device.elevatedAt = now
            device.elevatedBy = TrustElevation.trustedDeviceApproval.rawValue
        }
        let newId = device.id!
        let keyRecords = keys.map { DeviceKeyRecord(deviceId: newId, purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: $0.hardwareBacked, now: now,
                                                    attested: attestation.attested) }
        do {
            try await db.transaction { tx in
                guard try await DB.swap(tx, table: DevicePairingRecord.schema, id: id, column: "state", expected: "pending", newValue: "approved",
                                        extra: [("decided_at", now), ("decided_by_device_id", callerId.uuid), ("new_device_id", newId)]) else {
                    throw APIError.conflict("This request was already answered.")
                }
                try await device.create(on: tx)
                for key in keyRecords { try await key.create(on: tx) }
                if attestation.attested, let keyId = attestation.keyId, let publicKey = attestation.publicKey {
                    try await AppAttestKeyRecord(deviceId: newId, consumerId: account, keyId: keyId, publicKey: publicKey, counter: attestation.counter,
                                                 environment: attestation.environment ?? "production", now: now).create(on: tx)
                }
                // Every other device of the account is told, in the same transaction (the notice must not be lost).
                try await SecurityNotices(db: tx, ctx: ctx).store(of: account, except: newId, notice: .newDevice, subjectId: DeviceID(newId).description)
                try await audit("device_pairing.approved", account: account, pairing: id, device: callerId.uuid, metadata: [
                    "new_device": DeviceID(newId).description, "tier": device.trustTier, "elevated": elevate ? "true" : "false",
                    "assurance": approval.assurance.rawValue, "attested": attestation.attested ? "true" : "false"], on: tx)
            }
        } catch let error as APIError {
            throw await refuse("lost_race", error)
        } catch {
            if error.isConstraintViolation {
                throw await refuse("constraint", APIError.conflict("This request was already answered."))
            }
            throw error
        }
        await SecurityNotices(db: db, ctx: ctx).push(to: account, except: newId, notice: .newDevice)
        return DevicePairingApproveResponse(pairingId: pairingId, state: .approved, device: AuthService.deviceDTO(device, keys: keyRecords, now: now))
    }

    /// One more wrong number (an atomic increment bounded by the cap, so concurrent wrong entries cannot exceed it); the third ends the pairing.
    private func wrongNumber(pairing: DevicePairingRecord, account: UUID, device: UUID) async throws -> APIError {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        let rows = try await sql.raw("""
            UPDATE device_pairings SET attempts = attempts + 1
            WHERE id = \(bind: pairing.id!) AND state = 'pending' AND attempts < \(bind: DevicePairing.maxWrongEntries) RETURNING attempts
            """).all()
        let attempts = try rows.first?.decode(column: "attempts", as: Int.self) ?? DevicePairing.maxWrongEntries
        let remaining = max(0, DevicePairing.maxWrongEntries - attempts)
        if remaining == 0 {
            if try await DB.swap(db, table: DevicePairingRecord.schema, id: pairing.id!, column: "state", expected: "pending", newValue: "failed",
                                 extra: [("end_reason", "wrong_number"), ("decided_at", ctx.now), ("decided_by_device_id", device)]) {
                try await audit("device_pairing.failed", outcome: .failure, account: account, pairing: pairing.id, device: device, metadata: ["reason": "wrong_number"])
            }
            return APIError(.conflict, .comparisonMismatch, "Nothing was added. Start again on the new device.", details: ["remaining": "0"])
        }
        await refused("wrong_number", account: account, pairing: pairing.id, device: device)
        return APIError(.conflict, .comparisonMismatch, "That number doesn't match the new device. Check it and try again.", details: ["remaining": String(remaining)])
    }

    /// Deny or "This wasn't me": any live app device of the account, D0 included (saying no is always safe). Answering a pairing that is no
    /// longer pending changes nothing and succeeds.
    func deny(_ principal: ConsumerPrincipal, pairingId: DevicePairingID, report: Bool) async throws {
        let now = ctx.now
        let account = principal.consumerId.uuid
        let device = try await DeviceTrust.requireActiveApp(principal, db: db, now: now)
        guard let pairing = try await DevicePairingRecord.find(pairingId.uuid, on: db), pairing.consumerId == account else { throw APIError.notFound }
        let current = try await expireIfDue(pairing)
        guard current.state == "pending",
              try await DB.swap(db, table: DevicePairingRecord.schema, id: pairingId.uuid, column: "state", expected: "pending", newValue: "denied",
                                extra: [("end_reason", report ? "report" : "deny"), ("decided_at", now), ("decided_by_device_id", device.id!)]) else { return }
        try await audit(report ? "device_pairing.reported" : "device_pairing.denied", account: account, pairing: pairingId.uuid, device: device.id)
        if report {
            await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: account, except: nil, notice: .devicePairingReported, subjectId: pairingId.description)
        }
    }

    // MARK: Lifecycle

    /// Moves a pending pairing past its expiry to `expired` (once, audited) and returns the current row.
    @discardableResult
    func expireIfDue(_ pairing: DevicePairingRecord) async throws -> DevicePairingRecord {
        guard pairing.state == "pending", pairing.expiresAt <= ctx.now, let id = pairing.id else { return pairing }
        if try await DB.swap(db, table: DevicePairingRecord.schema, id: id, column: "state", expected: "pending", newValue: "expired",
                             extra: [("end_reason", "expired"), ("decided_at", ctx.now)]) {
            try await audit("device_pairing.expired", account: pairing.consumerId, pairing: id)
        }
        return try await DevicePairingRecord.find(id, on: db) ?? pairing
    }

    /// Background sweep: expire due pairings, revoke devices whose session was never collected, purge old ceremonies and codes.
    func sweep() async throws {
        let now = ctx.now
        for row in try await DevicePairingRecord.query(on: db).filter(\.$state == "pending").filter(\.$expiresAt <= now).limit(200).all() {
            try await expireIfDue(row)
        }
        let cutoff = now.addingTimeInterval(-DevicePairing.sessionPickupWindow)
        for row in try await DevicePairingRecord.query(on: db).filter(\.$state == "approved").filter(\.$sessionIssuedAt == nil)
            .filter(\.$decidedAt < cutoff).limit(200).all() {
            guard let id = row.id, try await DB.swapFromNull(db, table: DevicePairingRecord.schema, id: id, column: "session_issued_at", newValue: now) else { continue }
            if let newId = row.newDeviceId {
                try await db.transaction { tx in
                    try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: [newId], now: now)
                    try await audit("device_pairing.unclaimed", account: row.consumerId, pairing: id, device: newId, on: tx)
                }
            }
        }
        let old = now.addingTimeInterval(-86_400)
        try await DevicePairingRecord.query(on: db).filter(\.$state == "ceremony").filter(\.$expiresAt < old).delete()
        try await DevicePairingInvitationRecord.query(on: db).filter(\.$expiresAt < old).delete()
    }

    /// Account deletion: open codes are revoked, pending pairings cancelled, reported names blanked.
    static func wipe(consumer: UUID, on db: any Database) async throws {
        try await DevicePairingInvitationRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$state == "open").set(\.$state, to: "revoked").update()
        try await DevicePairingRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$state == "pending").set(\.$state, to: "cancelled")
            .set(\.$endReason, to: "account_deleted").update()
        try await DevicePairingRecord.query(on: db).filter(\.$consumerId == consumer).set(\.$deviceName, to: nil).update()
    }
}
