import Fluent
import Foundation
import ViadereCore

extension InteractionService {
    /// Records a decision that arrived on a *text channel* (RCS postback). Only what `AssurancePolicy` allows an
    /// unauthenticated reply to satisfy can pass: never `authenticate`, `authorize`, unknown kinds or anything
    /// whose required assurance exceeds `.channelReply`. Deny/report are refused on a channel (a text reply is
    /// not proof of who tapped). The pending → decided swap makes the outcome single-use across instances.
    @discardableResult
    func decideViaChannel(record: InteractionRecord, decision: Decision, selected: [String]?, reply: String?,
                          channel: DeliveryChannel, actor: AuditActor) async throws -> InteractionOutcome {
        let now = ctx.now
        guard record.statusValue == .pending else { throw APIError.conflict("This request has already been resolved.") }
        guard record.expiresAt > now else { throw APIError.gone("This request has expired.") }
        let interaction = try record.interaction()
        guard Decision.allowed(for: interaction.kind).contains(decision),
              AssurancePolicy.canSatisfy(interaction, channel: channel, provided: .unauthenticatedReply, decision: decision) else {
            throw APIError(.forbidden, .insufficientAssurance, "This request needs stronger verification than the channel provides.")
        }
        if case .choose(let choose) = interaction.payload, decision == .select {
            let valid = Set(choose.options.map(\.id))
            let chosen = selected ?? []
            guard !chosen.isEmpty, Set(chosen).count == chosen.count, Set(chosen).isSubset(of: valid),
                  choose.allowsMultiple || chosen.count == 1 else { throw APIError.validation("The selection is not valid.") }
        }
        if let reply, case .reply(let payload) = interaction.payload, reply.count > payload.maxLength {
            throw APIError.validation("The reply is too long.")
        }
        let outcome = InteractionOutcome(
            interactionId: InteractionID(record.id!), businessId: BusinessID(record.businessId), status: InteractionStatus(decision: decision),
            decision: decision, selectedOptionIds: selected, reply: reply, assurance: nil, channel: channel, decidedAt: now,
            correlationId: record.correlationId, signedDecision: nil)
        let outcomeJSON = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
        let id = record.id!
        try await db.transaction { tx in
            guard try await DB.swap(tx, table: InteractionRecord.schema, id: id, column: "status",
                                    expected: InteractionStatus.pending.rawValue, newValue: outcome.status.rawValue) else {
                throw APIError(.conflict, .replayDetected, "This request was already decided.")
            }
            try await InteractionRecord.query(on: tx).filter(\.$id == id).set(\.$decidedAt, to: now).set(\.$outcomeJSON, to: outcomeJSON).update()
            try await InteractionChallengeRecord.query(on: tx).filter(\.$interactionId == id).set(\.$consumedAt, to: now).update()
            try await WebhookService(db: tx, ctx: ctx).enqueue(.interactionDecided, businessId: outcome.businessId, payload: outcome)
            _ = try await AuditService(db: tx, ctx: ctx).record("interaction.decided", actor: actor, consumerId: ConsumerID(record.consumerId),
                businessId: outcome.businessId, subjectType: "interaction", subjectId: id.uuidString.lowercased(),
                metadata: ["decision": decision.rawValue, "assurance": "channel_reply", "channel": channel.rawValue])
        }
        return outcome
    }
}

/// Handles verified inbound RCS events: postbacks, free text and delivery receipts.
struct RCSInbound {
    let db: any Database
    let ctx: ServerContext

    enum Rejection: String, Equatable {
        case malformed, duplicate, unknown
        case wrongPhone = "wrong_phone"
        case replayed, stale, expired
        case notPending = "not_pending"
        case notPermitted = "not_permitted"
        case notLinked = "not_linked"
        case unavailable
    }

    enum PostbackResult: Equatable {
        case accepted
        case rejected(Rejection)
    }

    /// Dispatches events. Free text joins the same gateway thread as SMS (so `STOP`, `HELP`, `MENU` behave
    /// identically); the gateway answers by SMS.
    func handle(_ events: [ChannelInboundEvent]) async throws {
        for event in events {
            switch event {
            case .text(let phone, let text, let messageId, let receivedAt):
                let sms = InboundSMS(providerMessageId: messageId, from: phone, text: text, receivedAt: receivedAt)
                _ = try await GatewayService(db: db, ctx: ctx).handleInbound(sms, provider: "rcs")
            case .postback(let phone, let data, let messageId, _):
                _ = try await handlePostback(from: phone, data: data, messageId: messageId)
            case .receipt(let providerMessageId, let status, let errorCode):
                try await ChannelRouter(db: db, ctx: ctx).applyReceipt(providerMessageId: providerMessageId, status: status, errorCode: errorCode)
            }
        }
    }

    func handlePostback(from phone: PhoneNumber, data: String, messageId: String) async throws -> PostbackResult {
        let audit = AuditService(db: db, ctx: ctx)
        let actor = AuditActor(kind: .gateway, id: phone.masked)
        func reject(_ reason: Rejection, interaction: UUID? = nil, business: UUID? = nil, notify: Bool = false) async throws -> PostbackResult {
            _ = try await audit.record("rcs.postback_rejected", outcome: .denied, actor: actor, businessId: business.map(BusinessID.init),
                subjectType: interaction == nil ? nil : "interaction", subjectId: interaction?.uuidString.lowercased(),
                metadata: ["reason": reason.rawValue, "phone": phone.masked])
            if notify {
                try await OutboundSMS(db: db, ctx: ctx).enqueue(
                    to: phone, body: "Viadere: That option is no longer available. Use your most recent Viadere message.")
            }
            return .rejected(reason)
        }
        // Provider redeliveries of the same event are ignored.
        do {
            try await ProcessedProviderMessageRecord(provider: "rcs", providerMessageId: messageId, receivedAt: ctx.now).create(on: db)
        } catch {
            if error.isConstraintViolation { return .rejected(.duplicate) }
            throw error
        }
        let tokens = RCSPostbackTokens(hasher: ctx.hasher)
        guard tokens.isWellFormed(data) else { return try await reject(.malformed) }
        let phoneHash = ctx.hasher.phoneHash(phone)
        guard let postback = try await RCSPostbackRecord.query(on: db).filter(\.$tokenHash == RCSPostbackTokens.storedHash(data)).first(),
              let postbackId = postback.id else { return try await reject(.unknown) }
        let interactionId = postback.interactionId
        // The token only works from the phone it was sent to.
        guard ConstantTime.equals(postback.phoneHash, phoneHash) else { return try await reject(.wrongPhone, interaction: interactionId) }
        switch postback.state {
        case "consumed": return try await reject(.replayed, interaction: interactionId)
        case "open": break
        default: return try await reject(.stale, interaction: interactionId, notify: true)
        }
        let now = ctx.now
        // Same rules as SMS numbers: the menu must still be the active version and unexpired.
        guard let endpoint = try await ChannelEndpointRecord.query(on: db).filter(\.$channel == "rcs").filter(\.$phoneHash == phoneHash).first(),
              postback.menuVersion == endpoint.activeMenuVersion else { return try await reject(.stale, interaction: interactionId, notify: true) }
        guard now < postback.expiresAt, now < (endpoint.menuExpiresAt ?? .distantPast) else {
            return try await reject(.expired, interaction: interactionId, notify: true)
        }
        guard let record = try await InteractionRecord.find(interactionId, on: db), record.statusValue == .pending, record.expiresAt > now else {
            return try await reject(.notPending, interaction: interactionId)
        }
        let businessId = record.businessId
        guard try await DirectoryService(db: db).verified(id: businessId) != nil,
              let relationship = try await RelationshipRecord.find(record.relationshipId, on: db), relationship.isActive else {
            return try await reject(.unavailable, interaction: interactionId, business: businessId)
        }
        // The phone must be the verified phone of the consumer the interaction was issued to.
        guard let link = try await PhoneLinkRecord.query(on: db).filter(\.$verifiedPhoneHash == phoneHash).first(),
              link.consumerId == record.consumerId else { return try await reject(.notLinked, interaction: interactionId, business: businessId) }
        guard let interaction = try? record.interaction(), interaction.allowedChannels.contains(.rcs),
              let target = RCSPostbackTarget(storageValue: postback.target) else {
            return try await reject(.notPermitted, interaction: interactionId, business: businessId)
        }
        var decision: Decision
        var selected: [String]?
        var reply: String?
        switch target {
        case .decision(let d): decision = d
        case .option(let id):
            decision = .select
            selected = [id]
        case .suggestedReply(let index):
            guard case .reply(let payload) = interaction.payload, payload.suggestedReplies.indices.contains(index) else {
                return try await reject(.notPermitted, interaction: interactionId, business: businessId)
            }
            decision = .reply
            reply = payload.suggestedReplies[index]
        }
        do {
            // Consuming the token and recording the decision commit together; a lost race rolls both back.
            try await db.transaction { tx in
                guard try await DB.swap(tx, table: RCSPostbackRecord.schema, id: postbackId, column: "state", expected: "open", newValue: "consumed",
                                        extra: [("consumed_at", now)]) else { throw APIError(.conflict, .replayDetected, "replayed") }
                try await RCSPostbackRecord.query(on: tx).filter(\.$interactionId == interactionId).filter(\.$state == "open")
                    .set(\.$state, to: "revoked").update()
                _ = try await InteractionService(db: tx, ctx: ctx).decideViaChannel(record: record, decision: decision, selected: selected,
                                                                                    reply: reply, channel: .rcs, actor: actor)
            }
        } catch let error as APIError {
            switch error.code {
            case .replayDetected: return try await reject(.replayed, interaction: interactionId, business: businessId)
            case .insufficientAssurance: return try await reject(.notPermitted, interaction: interactionId, business: businessId)
            default: return try await reject(.notPending, interaction: interactionId, business: businessId)
            }
        }
        return .accepted
    }
}
