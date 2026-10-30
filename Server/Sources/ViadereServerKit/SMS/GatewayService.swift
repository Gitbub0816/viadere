import Fluent
import Foundation
import ViadereCore
import typealias ViadereCore.SessionID
import enum ViadereCore.Channel

/// Payload delivered to a business when a consumer's SMS is forwarded (`message.received`).
struct MessageReceivedPayload: Codable, Sendable {
    var sessionId: SessionID
    var relationshipId: RelationshipID
    /// The customer's pairwise reference (`subject_ref`).
    var subjectRef: SubjectRef?
    var messageId: MessageID
    var text: String
    var channel: Channel
    var receivedAt: Date
}

/// Runs the pure `SMSGatewayEngine` against persisted state and executes its effects.
///
/// One inbound message is handled in **one database transaction**: dedup marker (unique insert) →
/// context load → engine → compare-and-swap on `revision` → effects (outbound queue rows, webhook
/// deliveries, link tokens, consent and audit records). A lost CAS rolls everything back and retries,
/// so no effect is ever applied twice or half-applied.
struct GatewayService {
    let db: any Database
    let ctx: ServerContext

    static let providerLabel = "sms"
    static let handoffTTL: TimeInterval = 10 * 60
    static let maxConflictRetries = 6

    var configuration: GatewayConfiguration { GatewayConfiguration(menuRaceWindow: ctx.config.smsMenuRaceWindow) }

    func engine(on db: any Database) -> SMSGatewayEngine {
        SMSGatewayEngine(configuration: configuration, directory: DBDirectoryLookup(db: db))
    }

    enum InboundResult: Equatable { case processed, duplicate }
    private struct DuplicateInbound: Error {}

    // MARK: Inbound

    func handleInbound(_ sms: InboundSMS, provider: String) async throws -> InboundResult {
        for _ in 0..<Self.maxConflictRetries {
            do {
                try await db.transaction { tx in
                    do {
                        try await ProcessedProviderMessageRecord(provider: provider, providerMessageId: sms.providerMessageId,
                                                                 receivedAt: ctx.now).create(on: tx)
                    } catch {
                        if error.isConstraintViolation { throw DuplicateInbound() }
                        throw error
                    }
                    let (context, record) = try await loadContext(phone: sms.from, on: tx)
                    let transition = await engine(on: tx).handle(sms, context: context, now: ctx.now)
                    try await persist(transition.context, previous: record, on: tx)
                    try await execute(transition.effects, context: transition.context, on: tx)
                }
                return .processed
            } catch is DuplicateInbound {
                return .duplicate
            } catch is ConcurrencyConflict {
                continue
            }
        }
        throw APIError.unavailable("The gateway is busy. Please retry.")
    }

    // MARK: Account linking

    /// Called after a phone is verified for a consumer (link-token redemption or OTP). Moves an existing
    /// SMS thread forward and sends the confirmation.
    func accountLinked(consumerId: ConsumerID, phone: PhoneNumber) async throws {
        for _ in 0..<Self.maxConflictRetries {
            do {
                try await db.transaction { tx in
                    let (context, record) = try await loadContext(phone: phone, on: tx)
                    guard record != nil else { return } // never texted us: the next inbound message picks up the link
                    let transition = engine(on: tx).accountLinked(consumerId: consumerId, context: context, now: ctx.now)
                    try await persist(transition.context, previous: record, on: tx)
                    try await execute(transition.effects, context: transition.context, on: tx)
                }
                return
            } catch is ConcurrencyConflict { continue }
        }
        throw APIError.unavailable("The gateway is busy. Please retry.")
    }

    // MARK: Business → consumer

    /// Renders a business reply into the consumer's SMS thread if (and only if) it belongs to the active
    /// session; otherwise it stays in history. Returns true when an SMS was queued.
    @discardableResult
    func deliverBusinessMessage(businessId: BusinessID, sessionId: SessionID, text: String, messageId: UUID?, livemode: Bool = true) async throws -> Bool {
        // Emergency messaging restriction (G-6): the reply stays in the conversation history, it is not texted.
        guard await MessagingGate(db: db, ctx: ctx).decide(businessId: businessId.uuid, channel: .sms, purpose: InteractionPurpose.accountService.rawValue) == .allow else { return false }
        for _ in 0..<Self.maxConflictRetries {
            do {
                return try await db.transaction { tx in
                    guard let record = try await SMSContextRecord.query(on: tx).filter(\.$activeSessionId == sessionId.uuid).first()
                    else { return false }
                    let context = try decode(record)
                    let transition = engine(on: tx).deliverBusinessMessage(businessId: businessId, sessionId: sessionId, text: text,
                                                                           context: context, now: ctx.now)
                    try await persist(transition.context, previous: record, on: tx)
                    var queued = false
                    for effect in transition.effects {
                        if case .sendSMS(let body) = effect {
                            try await OutboundSMS(db: tx, ctx: ctx).enqueue(to: transition.context.phone, body: body, messageId: messageId)
                            // Transport metering is attributed to the business whose reply this is.
                            try await UsageMeter.record(.smsSegment, businessId: businessId.uuid, quantity: SMSEncoding.analyze(body).segments,
                                                        livemode: livemode, ref: "msg:" + (messageId?.uuidString.lowercased() ?? UUID().uuidString.lowercased()),
                                                        at: ctx.now, on: tx)
                            queued = true
                        }
                    }
                    return queued
                }
            } catch is ConcurrencyConflict { continue }
        }
        throw APIError.unavailable("The gateway is busy. Please retry.")
    }

    // MARK: Context persistence

    private func decode(_ record: SMSContextRecord) throws -> ConversationContext {
        let data = try ctx.cipher.open(record.contextCiphertext, context: "sms_contexts.context", rowId: record.id!)
        return try ViadereJSON.decode(ConversationContext.self, from: data)
    }

    /// Loads the thread for a phone (or a fresh `NEW` context). The linked consumer always comes from the
    /// verified phone-link table, never from stored state.
    func loadContext(phone: PhoneNumber, on db: any Database) async throws -> (ConversationContext, SMSContextRecord?) {
        let hash = ctx.hasher.phoneHash(phone)
        let record = try await SMSContextRecord.query(on: db).filter(\.$phoneHash == hash).first()
        var context = try record.map(decode) ?? ConversationContext(phone: phone, consentVersion: ConsentService.currentPolicyVersion)
        let link = try await PhoneLinkRecord.query(on: db).filter(\.$verifiedPhoneHash == hash).first()
        // A link that is still cooling down (or was never verified) is not a link: the number is **unlinked** for the gateway, so it
        // cannot open sessions, forward text, list recent businesses or answer as the account. Otherwise anyone who redeemed a link token
        // from their own device could use the victim's account over SMS at once, bypassing the cool-down that guards the other channels.
        if let link, link.state == "verified", link.isUsable(at: ctx.now) {
            context.consumerId = ConsumerID(link.consumerId)
        } else {
            context.consumerId = nil
        }
        return (context, record)
    }

    /// Compare-and-swap persist: succeeds only if nobody changed the row since `previous` was read.
    func persist(_ context: ConversationContext, previous: SMSContextRecord?, on db: any Database) async throws {
        let rowId = previous?.id ?? UUID()
        let sealed = try ctx.cipher.seal(try ViadereJSON.encode(context), context: "sms_contexts.context", rowId: rowId)
        let now = ctx.now
        if let previous, let id = previous.id {
            let swapped = try await DB.swap(db, table: SMSContextRecord.schema, id: id, column: "revision", expected: previous.revision,
                                            newValue: context.revision, extra: [("context_ciphertext", sealed), ("opted_out", context.consent.optedOut)])
            guard swapped else { throw ConcurrencyConflict() }
            try await SMSContextRecord.query(on: db).filter(\.$id == id).set(\.$consumerId, to: context.consumerId?.uuid)
                .set(\.$activeSessionId, to: context.session?.sessionId.uuid).set(\.$updatedAt, to: now).update()
        } else {
            let record = SMSContextRecord()
            record.id = rowId
            record.phoneHash = ctx.hasher.phoneHash(context.phone)
            record.contextCiphertext = sealed
            record.revision = context.revision
            record.consumerId = context.consumerId?.uuid
            record.activeSessionId = context.session?.sessionId.uuid
            record.optedOut = context.consent.optedOut
            record.updatedAt = now
            do { try await record.create(on: db) } catch {
                if error.isConstraintViolation { throw ConcurrencyConflict() }
                throw error
            }
        }
    }

    // MARK: Effects

    /// Executes engine effects strictly in order.
    func execute(_ effects: [GatewayEffect], context: ConversationContext, on db: any Database) async throws {
        let audit = AuditService(db: db, ctx: ctx)
        let queue = OutboundSMS(db: db, ctx: ctx)
        let phone = context.phone
        let phoneHash = ctx.hasher.phoneHash(phone)
        for effect in effects {
            switch effect {
            case .sendSMS(let body):
                try await queue.enqueue(to: phone, body: body, allowWhenOptedOut: context.consent.optedOut)

            case .openSession(let businessId, let sessionId):
                try await openSession(businessId: businessId, sessionId: sessionId, context: context, on: db)

            case .closeSession(_, let sessionId, _):
                try await ConversationSessionRecord.query(on: db).filter(\.$id == sessionId.uuid).filter(\.$state != "closed")
                    .set(\.$state, to: "closed").set(\.$closedAt, to: ctx.now).update()

            case .forwardToBusiness(let businessId, let sessionId, let text, let providerMessageId):
                try await forward(businessId: businessId, sessionId: sessionId, text: text, providerMessageId: providerMessageId,
                                  context: context, on: db)

            case .sendAccountLink:
                let token = try await mintToken(kind: "accountLink", context: context, consumerId: nil, purpose: nil,
                                                ttl: configuration.linkTTL, on: db)
                guard let url = APIRoutes.Web.accountLinkURL(token: token, domain: ctx.config.linkDomain) else { break }
                try await queue.enqueue(to: phone, body: GatewayCopy.accountLink(url: url, ttlMinutes: Int(configuration.linkTTL / 60)),
                                        sensitive: true)

            case .sendSecureHandoff(let purpose):
                let token = try await mintToken(kind: "handoff", context: context, consumerId: context.consumerId,
                                                purpose: purpose.rawValue, ttl: Self.handoffTTL, on: db)
                guard let url = APIRoutes.Web.handoffURL(token: token, domain: ctx.config.linkDomain) else { break }
                try await queue.enqueue(to: phone, body: GatewayCopy.secureHandoff(url: url, ttlMinutes: Int(Self.handoffTTL / 60)),
                                        sensitive: true)

            case .recordConsent(let optedOut, let keyword, let at):
                try await SMSConsentEventRecord(phoneHash: phoneHash, optedOut: optedOut, keyword: keyword, at: at).create(on: db)

            case .holdBusinessMessage:
                break // already stored in history by the sender; nothing is rendered in this thread

            case .audit(let entry):
                _ = try await audit.record(entry.action, actor: AuditActor(kind: .gateway, id: phone.masked),
                    consumerId: context.consumerId, businessId: entry.businessId, subjectType: "sms_thread",
                    subjectId: entry.sessionId?.description,
                    metadata: ["state_from": entry.from.rawValue, "state_to": entry.to.rawValue,
                               "provider_ref": entry.providerMessageId ?? "", "phone": phone.masked])
            }
        }
    }

    private func openSession(businessId: BusinessID, sessionId: SessionID, context: ConversationContext, on db: any Database) async throws {
        guard let consumerId = context.consumerId else { return }
        // Verification is re-checked when routing starts.
        guard try await DirectoryService(db: db).verified(id: businessId.uuid) != nil else {
            try await OutboundSMS(db: db, ctx: ctx).enqueue(to: context.phone, body: GatewayCopy.businessUnavailable(context.session?.business ?? placeholder(businessId)))
            return
        }
        // A blocked business is unavailable to this customer over SMS too (WP-1.5).
        if try await PreferenceService(db: db, ctx: ctx).isBlocked(consumer: consumerId.uuid, business: businessId.uuid) {
            try await OutboundSMS(db: db, ctx: ctx).enqueue(to: context.phone, body: GatewayCopy.businessUnavailable(context.session?.business ?? placeholder(businessId)))
            return
        }
        let relationship = try await RelationshipService(db: db, ctx: ctx)
            .connect(consumer: consumerId, request: ConnectRequest(businessId: businessId, source: .sms), channels: [.sms],
                     consentSource: .sms).relationship
        guard try await ConversationSessionRecord.find(sessionId.uuid, on: db) == nil else { return }
        try await ConversationSessionRecord(id: sessionId.uuid, businessId: businessId.uuid, consumerId: consumerId.uuid,
                                            relationshipId: relationship.id.uuid, channel: .sms, now: ctx.now).create(on: db)
    }

    private func placeholder(_ id: BusinessID) -> BusinessSummary {
        BusinessSummary(id: id, displayName: "This business", handle: nil, code: BusinessCode.generate(), verificationStatus: .suspended)
    }

    private func forward(businessId: BusinessID, sessionId: SessionID, text: String, providerMessageId: String,
                         context: ConversationContext, on db: any Database) async throws {
        let queue = OutboundSMS(db: db, ctx: ctx)
        guard let consumerId = context.consumerId,
              let session = try await ConversationSessionRecord.query(on: db).filter(\.$id == sessionId.uuid)
                  .filter(\.$businessId == businessId.uuid).filter(\.$consumerId == consumerId.uuid).first(),
              let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId)
                  .filter(\.$consumerId == consumerId.uuid).first(), relationship.isActive,
              try await DirectoryService(db: db).verified(id: businessId.uuid) != nil
        else {
            // Business no longer reachable (disconnected, suspended, or no linked consumer): say so, forward nothing.
            if let business = context.session?.business {
                try await queue.enqueue(to: context.phone, body: GatewayCopy.businessUnavailable(business))
            }
            return
        }
        let now = ctx.now
        let message = ConversationMessageRecord()
        message.id = UUID()
        message.sessionId = sessionId.uuid
        message.businessId = businessId.uuid
        message.consumerId = consumerId.uuid
        message.direction = MessageDirection.consumerToBusiness.rawValue
        message.senderType = MessageAttribution.SenderType.consumer.rawValue
        message.displayName = "You"
        message.bodyCiphertext = try ctx.cipher.seal(text, context: "conversation_messages.body", rowId: message.id!)
        message.channel = Channel.sms.rawValue
        message.deliveryStatus = DeliveryStatus.delivered.rawValue
        message.createdAt = now
        message.providerMessageId = providerMessageId
        try await message.create(on: db)
        try await UsageMeter.record(.smsSegment, businessId: businessId.uuid, quantity: SMSEncoding.analyze(text).segments, livemode: true,
                                    ref: "in:" + providerMessageId, at: now, on: db)
        session.lastMessageAt = now
        try await session.update(on: db)
        relationship.lastActivityAt = now
        try await relationship.update(on: db)
        try await WebhookService(db: db, ctx: ctx).enqueue(.messageReceived, businessId: businessId,
            payload: MessageReceivedPayload(sessionId: sessionId, relationshipId: RelationshipID(relationship.id!),
                                            subjectRef: ctx.subjects.subjectRef(businessId: BusinessID(relationship.businessId), consumerId: ConsumerID(relationship.consumerId)),
                                            messageId: MessageID(message.id!), text: text, channel: .sms, receivedAt: now))
    }

    // MARK: Tokens

    /// Mints a 256-bit single-use token; only its SHA-256 is stored. Earlier open tokens of the same kind
    /// for this phone are revoked, so only the newest link works.
    private func mintToken(kind: String, context: ConversationContext, consumerId: ConsumerID?, purpose: String?, ttl: TimeInterval,
                           on db: any Database) async throws -> String {
        let token = SecureToken.generate()
        let hash = ctx.hasher.phoneHash(context.phone)
        try await LinkTokenRecord.query(on: db).filter(\.$phoneHash == hash).filter(\.$kind == kind).filter(\.$state == "open")
            .set(\.$state, to: "revoked").update()
        let now = ctx.now
        let record = LinkTokenRecord()
        record.id = UUID()
        record.kind = kind
        record.tokenHash = SecureToken.hash(token)
        record.phoneHash = hash
        record.phoneCiphertext = try ctx.cipher.seal(context.phone.e164, context: "link_tokens.phone", rowId: record.id!)
        record.phoneLast4 = String(context.phone.e164.suffix(4))
        record.contextRevision = context.revision
        record.consumerId = consumerId?.uuid
        record.purpose = purpose
        record.attempts = 0
        record.state = "open"
        record.createdAt = now
        record.expiresAt = now.addingTimeInterval(ttl)
        try await record.create(on: db)
        return token
    }
}
