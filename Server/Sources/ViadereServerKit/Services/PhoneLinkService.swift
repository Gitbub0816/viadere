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
        guard let phone = PhoneNumber(try ctx.cipher.openString(link.phoneCiphertext, context: "phone_links.phone")) else { throw APIError.internalError }
        let verified = try await makeVerified(link: link, consumerId: principal.consumerId, phone: phone, now: now, source: "otp")
        try await GatewayService(db: db, ctx: ctx).accountLinked(consumerId: principal.consumerId, phone: phone)
        return PhoneLink(id: PhoneLinkID(verified.id!), maskedPhone: verified.phoneMasked, verifiedAt: now)
    }

    /// Marks a link verified and makes it the only verified link for that number.
    private func makeVerified(link: PhoneLinkRecord?, consumerId: ConsumerID, phone: PhoneNumber, now: Date, source: String) async throws -> PhoneLinkRecord {
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
            record.otpHash = nil
            record.otpExpiresAt = nil
            try await record.save(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.verified", actor: AuditActor(kind: .consumer, id: consumerId.description),
                consumerId: consumerId, subjectType: "phone_link", subjectId: record.id?.uuidString.lowercased(),
                metadata: ["method": source, "phone": phone.masked])
            return record
        }
    }

    // MARK: SMS account-link token

    func redeemAccountLink(principal: ConsumerPrincipal, request: SMSLinkRedeemRequest) async throws -> PhoneLink {
        try await ctx.limiter.enforce("link-redeem", key: principal.consumerId.description, rule: ctx.config.rateLimits.linkRedeem)
        let gone = APIError.gone("This link is invalid or has expired. Text Viadere to get a new one.")
        guard Base64URL.isValid(request.token, minLength: 20, maxLength: 64),
              let token = try await LinkTokenRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(request.token))
                  .filter(\.$kind == "accountLink").first(), let id = token.id else { throw gone }
        let now = ctx.now
        guard token.state == "open", token.expiresAt > now else { throw gone }
        // Explicit confirmation of the last 4 digits; a few wrong guesses burn the token.
        guard request.confirmPhoneLast4.count == 4, ConstantTime.equals(request.confirmPhoneLast4, token.phoneLast4) else {
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
        guard let phone = PhoneNumber(try ctx.cipher.openString(token.phoneCiphertext, context: "link_tokens.phone")) else { throw APIError.internalError }
        let existing = try await PhoneLinkRecord.query(on: db).filter(\.$verifiedPhoneHash == token.phoneHash)
            .filter(\.$consumerId == principal.consumerId.uuid).first()
        let record: PhoneLinkRecord
        if let existing { record = existing } else {
            record = try await makeVerified(link: nil, consumerId: principal.consumerId, phone: phone, now: now, source: "sms_link")
        }
        try await GatewayService(db: db, ctx: ctx).accountLinked(consumerId: principal.consumerId, phone: phone)
        return PhoneLink(id: PhoneLinkID(record.id!), maskedPhone: record.phoneMasked, verifiedAt: record.verifiedAt ?? now)
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
