import Fluent
import Foundation
import ViadereCore

/// Phone verification (OTP) and SMS link-token redemption.
struct PhoneLinkService {
    let db: any Database
    let ctx: ServerContext

    static let otpTTL: TimeInterval = 10 * 60
    static let maxOTPAttempts = 5
    static let maxLinksPerConsumer = 5
    static let maxLinkConfirmAttempts = 5
    /// A phone linked from an SMS link token is not used for delivery or replies for this long unless a trusted device confirms it.
    static let newLinkCoolDown: TimeInterval = 24 * 3600

    private func otpHash(linkId: UUID, code: String) -> String { ctx.hasher.hmacHex("otp", "\(linkId.uuidString.lowercased())|\(code)") }

    private func randomOTP() -> String {
        // Rejection sampling avoids modulo bias.
        let limit = UInt32.max - (UInt32.max % 1_000_000)
        while true {
            let bytes = SecureToken.randomBytes(4)
            let value = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            if value < limit { return String(format: "%06d", value % 1_000_000) }
        }
    }

    // MARK: OTP

    func start(principal: ConsumerPrincipal, request: PhoneLinkStartRequest) async throws -> PhoneLinkStartResponse {
        let limits = ctx.config.rateLimits
        let phoneHash = ctx.hasher.phoneHash(request.phone)
        // Toll-fraud defences: destination allowlist, a platform-wide ceiling, a per-prefix ceiling, and the attestation hook.
        guard PhoneRegions.isAllowed(request.phone, regions: ctx.config.otpAllowedCountries) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("phone_link.destination_refused", outcome: .denied, principal: principal,
                                                                metadata: ["prefix": PhoneRegions.budgetPrefix(of: request.phone, digits: 2)])
            throw APIError.validation("We can't send verification codes to that country yet.", details: ["phone": "countryNotSupported"])
        }
        if let deviceId = principal.deviceId, await ctx.integrity.assessSensitiveRequest(deviceId: deviceId, purpose: "otp") == .failed {
            throw APIError(.forbidden, .forbidden, "This device could not be verified.")
        }
        let prefix = PhoneRegions.budgetPrefix(of: request.phone, digits: ctx.config.otpPrefixDigits)
        for (name, key, rule, scope) in [("otp-prefix", prefix, limits.otpPerPrefix, "prefix"), ("otp-global", "all", limits.otpGlobal, "global")] {
            guard await ctx.limiter.allow(name, key: key, rule: rule) else {
                // An alert-level signal: a budget this high being exhausted usually means SMS pumping.
                ctx.logger.warning("otp budget exhausted", metadata: ["scope": "\(scope)", "prefix": "\(prefix)"])
                _ = try? await AuditService(db: db, ctx: ctx).record("phone_link.budget_exhausted", outcome: .denied, principal: principal,
                                                                    metadata: ["scope": scope, "prefix": prefix])
                throw APIError.rateLimited(retryAfter: 600)
            }
        }
        try await ctx.limiter.enforce("phonelink-consumer", key: principal.consumerId.description, rule: limits.phoneLinkStartPerConsumer)
        try await ctx.limiter.enforce("phonelink-phone", key: phoneHash, rule: limits.phoneLinkStartPerPhone)
        if let context = try await SMSContextRecord.query(on: db).filter(\.$phoneHash == phoneHash).first(), context.optedOut {
            throw APIError.conflict("This number has opted out of Viadere messages. Text START to resubscribe first.")
        }
        let existing = try await PhoneLinkRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$state != "revoked").count()
        guard existing < Self.maxLinksPerConsumer else { throw APIError.conflict("Too many phone numbers are linked to this account.") }
        let now = ctx.now
        let record = try PhoneLinkRecord(consumerId: principal.consumerId.uuid, phone: request.phone, hasher: ctx.hasher,
                                         cipher: ctx.cipher, now: now)
        let code = randomOTP()
        record.otpHash = otpHash(linkId: record.id!, code: code)
        record.otpExpiresAt = now.addingTimeInterval(Self.otpTTL)
        try await db.transaction { tx in
            // Only the newest pending code for this number works.
            try await PhoneLinkRecord.query(on: tx).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$phoneHash == phoneHash)
                .filter(\.$state == "pending").set(\.$state, to: "revoked").update()
            try await record.create(on: tx)
            try await OutboundSMS(db: tx, ctx: ctx).enqueue(
                to: request.phone, body: "Viadere: Your verification code is \(code). It expires in 10 minutes. Never share it.", sensitive: true)
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.started", principal: principal, subjectType: "phone_link",
                                                               subjectId: record.id?.uuidString.lowercased(), metadata: ["phone": request.phone.masked])
        }
        return PhoneLinkStartResponse(phoneLinkId: PhoneLinkID(record.id!), expiresAt: record.otpExpiresAt ?? now)
    }

    func verify(principal: ConsumerPrincipal, request: PhoneLinkVerifyRequest) async throws -> PhoneLink {
        try await ctx.limiter.enforce("phonelink-verify", key: principal.consumerId.description, rule: ctx.config.rateLimits.phoneLinkVerify)
        guard request.code.count == 6, request.code.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw APIError.validation("The code must be 6 digits.", details: ["code": "invalid"])
        }
        guard let link = try await PhoneLinkRecord.query(on: db).filter(\.$id == request.phoneLinkId.uuid)
            .filter(\.$consumerId == principal.consumerId.uuid).first(), link.state == "pending",
              let storedHash = link.otpHash, let expires = link.otpExpiresAt else { throw APIError.notFound }
        let now = ctx.now
        guard expires > now else { throw APIError.gone("This code has expired. Request a new one.") }
        guard link.otpAttempts < Self.maxOTPAttempts else {
            link.state = "revoked"
            try await link.update(on: db)
            throw APIError(.forbidden, .forbidden, "Too many incorrect attempts. Request a new code.")
        }
        guard ConstantTime.equals(otpHash(linkId: link.id!, code: request.code), storedHash) else {
            _ = try await DB.swap(db, table: PhoneLinkRecord.schema, id: link.id!, column: "otp_attempts", expected: link.otpAttempts,
                                  newValue: link.otpAttempts + 1)
            _ = try? await AuditService(db: db, ctx: ctx).record("phone_link.verify_failed", outcome: .failure, principal: principal,
                                                                subjectType: "phone_link", subjectId: link.id?.uuidString.lowercased())
            throw APIError(.forbidden, .forbidden, "The code is not correct.")
        }
        // Single use: exactly one concurrent verification can flip pending → verified.
        guard try await DB.swap(db, table: PhoneLinkRecord.schema, id: link.id!, column: "state", expected: "pending", newValue: "verified")
        else { throw APIError.conflict("This code was already used.") }
        guard let phone = PhoneNumber(try ctx.cipher.openString(link.phoneCiphertext, context: "phone_links.phone", rowId: link.id!)) else { throw APIError.internalError }
        // Proving control of the number through a code sent to it is enough to use it now, unless the device doing so is itself new.
        var usableFrom: Date?
        if let deviceId = principal.deviceId, let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.isCoolingDown(at: now) {
            usableFrom = device.approvalsLockedUntil
        }
        let verified = try await makeVerified(link: link, consumerId: principal.consumerId, phone: phone, now: now, source: "otp", usableFrom: usableFrom)
        try await GatewayService(db: db, ctx: ctx).accountLinked(consumerId: principal.consumerId, phone: phone)
        return PhoneLink(id: PhoneLinkID(verified.id!), maskedPhone: verified.phoneMasked, verifiedAt: now, usableFrom: usableFrom)
    }

    /// Marks a link verified and makes it the only verified link for that number.
    private func makeVerified(link: PhoneLinkRecord?, consumerId: ConsumerID, phone: PhoneNumber, now: Date, source: String,
                              usableFrom: Date?) async throws -> PhoneLinkRecord {
        let hash = ctx.hasher.phoneHash(phone)
        return try await db.transaction { tx in
            // A number is verified for one consumer at a time; proving control of it moves the link.
            let others = try await PhoneLinkRecord.query(on: tx).filter(\.$verifiedPhoneHash == hash).all()
            for other in others where other.id != link?.id {
                other.state = "revoked"
                other.verifiedPhoneHash = nil
                try await other.update(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.revoked", actor: AuditActor(kind: .system),
                    consumerId: ConsumerID(other.consumerId), subjectType: "phone_link", subjectId: other.id?.uuidString.lowercased(),
                    metadata: ["reason": "claimed_by_another_account"])
            }
            let record = try link ?? PhoneLinkRecord(consumerId: consumerId.uuid, phone: phone, hasher: ctx.hasher, cipher: ctx.cipher, now: now)
            record.state = "verified"
            record.verifiedPhoneHash = hash
            record.verifiedAt = now
            record.usableFrom = usableFrom
            record.source = source
            record.otpHash = nil
            record.otpExpiresAt = nil
            try await record.save(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.verified", actor: AuditActor(kind: .consumer, id: consumerId.description),
                consumerId: consumerId, subjectType: "phone_link", subjectId: record.id?.uuidString.lowercased(),
                metadata: ["method": source, "phone": phone.masked, "cool_down": usableFrom == nil ? "false" : "true"])
            return record
        }
    }

    // MARK: SMS account-link token

    /// The open account-link token and the live SMS thread it was minted for, or `gone`.
    private func openAccountLink(_ rawToken: String, now: Date) async throws -> (token: LinkTokenRecord, phone: PhoneNumber) {
        let gone = APIError.gone("This link is invalid or has expired. Text Viadere to get a new one.")
        guard Base64URL.isValid(rawToken, minLength: 20, maxLength: 64),
              let token = try await LinkTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(rawToken))
                  .filter(\.$kind == "accountLink").first(), token.state == "open", token.expiresAt > now,
              let phone = PhoneNumber((try? ctx.cipher.openString(token.phoneCiphertext, context: "link_tokens.phone", rowId: token.id!)) ?? "")
        else { throw gone }
        // The link must still belong to the live conversation it was texted into: that thread exists, has not been reset
        // (its revision never goes backwards) and has not opted out.
        let (thread, record) = try await GatewayService(db: db, ctx: ctx).loadContext(phone: phone, on: db)
        guard record != nil, thread.revision >= token.contextRevision, !thread.consent.optedOut else { throw gone }
        return (token, phone)
    }

    /// What a link token would link, without consuming it (device-signed and rate-limited, so it cannot be used to probe tokens).
    func previewAccountLink(principal: ConsumerPrincipal, token rawToken: String) async throws -> SMSLinkPreview {
        try await ctx.limiter.enforce("link-preview", key: principal.consumerId.description, rule: ctx.config.rateLimits.linkRedeem)
        let (token, phone) = try await openAccountLink(rawToken, now: ctx.now)
        return SMSLinkPreview(maskedPhone: phone.masked, expiresAt: token.expiresAt)
    }

    func redeemAccountLink(principal: ConsumerPrincipal, request: SMSLinkRedeemRequest) async throws -> PhoneLink {
        try await ctx.limiter.enforce("link-redeem", key: principal.consumerId.description, rule: ctx.config.rateLimits.linkRedeem)
        let now = ctx.now
        let (token, phone) = try await openAccountLink(request.token, now: now)
        let id = token.id!
        let gone = APIError.gone("This link is invalid or has expired. Text Viadere to get a new one.")
        // Explicit confirmation of the number the person was shown: the last 4 digits, and (when sent) the whole masked number.
        // A few wrong guesses burn the token.
        let maskedOK = request.confirmMaskedPhone.map { ConstantTime.equals($0, phone.masked) } ?? true
        guard request.confirmPhoneLast4.count == 4, ConstantTime.equals(request.confirmPhoneLast4, token.phoneLast4), maskedOK else {
            let attempts = token.attempts + 1
            if try await DB.swap(db, table: LinkTokenRecord.schema, id: id, column: "attempts", expected: token.attempts, newValue: attempts),
               attempts >= Self.maxLinkConfirmAttempts {
                try await LinkTokenRecord.query(on: db).filter(\.$id == id).set(\.$state, to: "revoked").update()
            }
            _ = try? await AuditService(db: db, ctx: ctx).record("sms_link.confirm_failed", outcome: .failure, principal: principal)
            throw APIError(.forbidden, .forbidden, "The phone confirmation did not match.")
        }
        // Single use: only one redemption can flip open → consumed.
        guard try await DB.swap(db, table: LinkTokenRecord.schema, id: id, column: "state", expected: "open", newValue: "consumed") else { throw gone }
        try await LinkTokenRecord.query(on: db).filter(\.$id == id).set(\.$consumedAt, to: now).set(\.$consumerId, to: principal.consumerId.uuid).update()
        let existing = try await PhoneLinkRecord.query(on: db).filter(\.$verifiedPhoneHash == token.phoneHash)
            .filter(\.$consumerId == principal.consumerId.uuid).first()
        let record: PhoneLinkRecord
        if let existing { record = existing } else {
            // A number linked this way is not an interaction target or a reply decider for 24 hours unless a trusted device confirms it.
            record = try await makeVerified(link: nil, consumerId: principal.consumerId, phone: phone, now: now, source: "sms_link",
                                            usableFrom: now.addingTimeInterval(Self.newLinkCoolDown))
            await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: principal.deviceId?.uuid, notice: .newPhone)
        }
        try await GatewayService(db: db, ctx: ctx).accountLinked(consumerId: principal.consumerId, phone: phone)
        return PhoneLink(id: PhoneLinkID(record.id!), maskedPhone: record.phoneMasked, verifiedAt: record.verifiedAt ?? now, usableFrom: record.usableFrom)
    }

    /// Makes a linked phone usable now. Signed by a trusted (not new, not App Clip) device with a user-verified approval key.
    func confirmLink(principal: ConsumerPrincipal, id: PhoneLinkID, proof: ConfirmationProof) async throws -> PhoneLink {
        try await ctx.limiter.enforce("phone-confirm", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let now = ctx.now
        guard let deviceId = principal.deviceId, proof.deviceId == deviceId,
              let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.revokedAt == nil, device.kind == .app,
              !device.isExpired(at: now), !device.isCoolingDown(at: now),
              let link = try await PhoneLinkRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == principal.consumerId.uuid)
                  .filter(\.$state == "verified").first() else { throw APIError.notFound }
        if link.usableFrom != nil {
            guard let purpose = proof.requiredKeyPurpose,
                  let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId.uuid).filter(\.$purpose == purpose.rawValue).first(),
                  let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
                throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID or your passcode.")
            }
            do {
                try await proof.verify(subject: .phoneLink, subjectId: id.description, publicKey: publicKey, now: now, replayGuard: DatabaseReplayGuard(db: db))
            } catch ConfirmationProof.Failure.replayed {
                throw APIError(.unauthorized, .replayDetected, "This confirmation was already used.")
            } catch ConfirmationProof.Failure.assuranceTooLow {
                throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID or your passcode.")
            } catch {
                throw APIError.signatureInvalid
            }
            link.usableFrom = nil
            link.confirmedAt = now
            try await db.transaction { tx in
                try await link.update(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.confirmed", principal: principal, subjectType: "phone_link",
                                                                   subjectId: id.description, metadata: ["assurance": proof.assurance.rawValue])
            }
        }
        return PhoneLink(id: id, maskedPhone: link.phoneMasked, verifiedAt: link.verifiedAt ?? link.createdAt, usableFrom: link.usableFrom)
    }

    // MARK: Handoff token

    enum TokenView: Equatable { case valid, expired, used, unknown }

    /// Read-only state for the landing pages (never consumes the token).
    func view(token: String, kind: String) async throws -> TokenView {
        guard Base64URL.isValid(token, minLength: 20, maxLength: 64),
              let record = try await LinkTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(token))
                  .filter(\.$kind == kind).first() else { return .unknown }
        if record.state == "consumed" { return .used }
        if record.state != "open" { return .unknown }
        return record.expiresAt > ctx.now ? .valid : .expired
    }

    /// The app redeems a handoff token (device-signed) to continue a secure flow. The token must have been
    /// minted for this consumer's verified phone.
    func redeemHandoff(principal: ConsumerPrincipal, token: String) async throws -> HandoffRedeemResponse {
        let gone = APIError.gone("This link is invalid or has expired.")
        guard Base64URL.isValid(token, minLength: 20, maxLength: 64),
              let record = try await LinkTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(token))
                  .filter(\.$kind == "handoff").first(), let id = record.id,
              record.state == "open", record.expiresAt > ctx.now else { throw gone }
        guard record.consumerId == principal.consumerId.uuid else { throw APIError.forbidden }
        guard try await DB.swap(db, table: LinkTokenRecord.schema, id: id, column: "state", expected: "open", newValue: "consumed") else { throw gone }
        try await LinkTokenRecord.query(on: db).filter(\.$id == id).set(\.$consumedAt, to: ctx.now).update()
        _ = try await AuditService(db: db, ctx: ctx).record("handoff.redeemed", principal: principal, subjectType: "handoff", subjectId: id.uuidString.lowercased())
        return HandoffRedeemResponse(purpose: HandoffPurpose(rawValue: record.purpose ?? "") ?? .accountHelp,
                                     interactionId: record.interactionId.map { InteractionID($0) })
    }
}
