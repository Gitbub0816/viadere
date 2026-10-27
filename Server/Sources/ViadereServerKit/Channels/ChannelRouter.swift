import Fluent
import Foundation
import ViadereCore

/// Mints single-use `/h/{token}` secure-handoff links (kind `handoff`, bound to the consumer and interaction).
struct HandoffTokens {
    let ctx: ServerContext

    static let ttl: TimeInterval = GatewayService.handoffTTL

    func mint(consumerId: UUID, phone: PhoneNumber, interactionId: UUID, on db: any Database) async throws -> URL? {
        let token = SecureToken.generate()
        let record = LinkTokenRecord()
        record.id = UUID()
        record.kind = "handoff"
        record.tokenHash = SecureToken.hash(token)
        record.phoneHash = ctx.hasher.phoneHash(phone)
        record.phoneCiphertext = try ctx.cipher.seal(phone.e164, context: "link_tokens.phone", rowId: record.id!)
        record.phoneLast4 = String(phone.e164.suffix(4))
        record.contextRevision = 0
        record.consumerId = consumerId
        record.purpose = HandoffPurpose.interaction.rawValue
        record.interactionId = interactionId
        record.attempts = 0
        record.state = "open"
        record.createdAt = ctx.now
        record.expiresAt = ctx.now.addingTimeInterval(Self.ttl)
        try await record.create(on: db)
        return URL(string: ctx.config.publicBaseURL + APIRoutes.Web.handoffPrefix + token)
    }
}

/// Chooses a channel for an issued interaction, delivers it from a durable outbox and falls back to SMS.
///
/// Rules (spec §14):
/// * RCS is used only if the business allowed it, the adapter is configured, and the phone is RCS-capable
///   (provider lookup, cached 24 h per phone). Otherwise — or when the provider errors out — the **same**
///   interaction goes out by SMS.
/// * A sensitive interaction is never downgraded: both channels render a secure handoff link, and only the
///   native app / secure web flow can satisfy it.
/// * The phone must be the consumer's verified phone, must not have opted out (STOP applies to every text
///   channel), and non-essential purposes need a consent grant that covers text channels.
struct ChannelRouter {
    let db: any Database
    let ctx: ServerContext

    static let maxAttempts = 3
    static let backoff: [TimeInterval] = [30, 120]
    static let capabilityTTL: TimeInterval = 24 * 3600

    // MARK: Enqueue (inside the issue transaction)

    func enqueue(record: InteractionRecord, interaction: Interaction, on tx: any Database) async throws {
        guard record.livemode else { return }
        let allowed = Set(interaction.allowedChannels)
        guard allowed.contains(.rcs) || allowed.contains(.sms) else { return }
        // The newest link that is past its cool-down: a phone someone just linked does not displace the person's established one.
        let links = try await PhoneLinkRecord.query(on: tx).filter(\.$consumerId == record.consumerId)
            .filter(\.$state == "verified").sort(\.$verifiedAt, .descending).all()
        guard let link = links.first(where: { $0.isUsable(at: ctx.now) }) ?? links.first, let phoneHash = link.verifiedPhoneHash else { return }
        let audit = AuditService(db: tx, ctx: ctx)
        func skip(_ reason: String) async throws {
            _ = try await audit.record("channel.skipped", outcome: .denied, actor: AuditActor(kind: .system),
                consumerId: ConsumerID(record.consumerId), businessId: BusinessID(record.businessId), subjectType: "interaction",
                subjectId: record.id?.uuidString.lowercased(), metadata: ["reason": reason])
        }
        // A phone linked from an SMS link token is not a delivery target until its cool-down ends or a trusted device confirms it.
        if let usableFrom = link.usableFrom, usableFrom > ctx.now {
            try await skip("phone_link_cool_down")
            return
        }
        if let context = try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == phoneHash).first(), context.optedOut {
            try await skip("opted_out")
            return
        }
        guard try await textChannelConsent(record: record, interaction: interaction, on: tx) else {
            try await skip("no_text_channel_consent")
            return
        }
        let rcsWanted = allowed.contains(.rcs)
        let rcsUsable = rcsWanted && ctx.channels.rcs.isEnabled
        let row = ChannelOutboundRecord()
        row.id = UUID()
        row.businessId = record.businessId
        row.interactionId = record.id!
        row.consumerId = record.consumerId
        row.channel = rcsUsable ? "rcs" : "sms"
        row.preferredChannel = rcsWanted ? "rcs" : "sms"
        row.phoneHash = phoneHash
        guard let phone = PhoneNumber((try? ctx.cipher.openString(link.phoneCiphertext, context: "phone_links.phone", rowId: link.id!)) ?? "") else { return }
        row.phoneCiphertext = try ctx.cipher.seal(phone.e164, context: "channel_outbound.phone", rowId: row.id!)
        row.status = "queued"
        row.attempts = 0
        row.nextAttemptAt = ctx.now
        row.fallbackReason = rcsWanted && !rcsUsable ? "disabled" : nil
        row.createdAt = ctx.now
        try await row.create(on: tx)
    }

    /// Essential purposes ride on the verified phone link. Everything else needs a grant that names a text channel.
    private func textChannelConsent(record: InteractionRecord, interaction: Interaction, on db: any Database) async throws -> Bool {
        if interaction.purpose.isEssential { return true }
        let latest = try await ConsentService(db: db, ctx: ctx).latest(relationshipId: record.relationshipId)
        guard let grant = latest[interaction.purpose], grant.granted else { return false }
        let channels = Set(grant.channels.split(separator: ",").map(String.init))
        return channels.contains(DeliveryChannel.sms.rawValue) || channels.contains(DeliveryChannel.rcs.rawValue)
    }

    // MARK: Worker

    @discardableResult
    func deliverDue(limit: Int = 50) async throws -> Int {
        let now = ctx.now
        // A worker that died mid-send leaves a "sending" row behind; put it back after a 5 minute lease.
        // (Read first: an idle worker must not take a write lock on every tick.)
        let stuck = ChannelOutboundRecord.query(on: db).filter(\.$status == "sending").filter(\.$nextAttemptAt < now.addingTimeInterval(-300))
        if try await stuck.count() > 0 {
            try await ChannelOutboundRecord.query(on: db).filter(\.$status == "sending")
                .filter(\.$nextAttemptAt < now.addingTimeInterval(-300)).set(\.$status, to: "queued").update()
        }
        let due = try await ChannelOutboundRecord.query(on: db).filter(\.$status == "queued").filter(\.$nextAttemptAt <= now)
            .sort(\.$createdAt, .ascending).limit(limit).all()
        var handled = 0
        for row in due {
            guard let id = row.id,
                  try await DB.swap(db, table: ChannelOutboundRecord.schema, id: id, column: "status", expected: "queued", newValue: "sending",
                                    extra: [("next_attempt_at", now)])
            else { continue }
            row.status = "sending"
            try await process(row)
            handled += 1
        }
        return handled
    }

    private func finish(_ row: ChannelOutboundRecord, status: String, error: String? = nil) async throws {
        row.status = status
        row.errorCode = error
        try await row.update(on: db)
    }

    private func process(_ row: ChannelOutboundRecord) async throws {
        let audit = AuditService(db: db, ctx: ctx)
        guard let interactionRecord = try await InteractionRecord.find(row.interactionId, on: db),
              interactionRecord.statusValue == .pending, interactionRecord.expiresAt > ctx.now,
              let business = try await DirectoryService(db: db).verified(id: row.businessId),
              let summary = try await DirectoryService(db: db).summary(for: business),
              let interaction = try? interactionRecord.interaction(),
              let phone = PhoneNumber((try? ctx.cipher.openString(row.phoneCiphertext, context: "channel_outbound.phone", rowId: row.id!)) ?? "") else {
            try await finish(row, status: "cancelled", error: "not_deliverable")
            return
        }
        if let context = try await SMSContextRecord.query(on: db).filter(\.$phoneHash == row.phoneHash).first(), context.optedOut {
            try await finish(row, status: "cancelled", error: "opted_out")
            return
        }
        if row.channel == "rcs" {
            switch try await sendRCS(row, interaction: interaction, summary: summary, phone: phone) {
            case .sent: return
            case .retry: return
            case .fallback(let reason): row.fallbackReason = reason
            }
        }
        try await sendSMS(row, interaction: interaction, summary: summary, phone: phone, audit: audit)
    }

    // MARK: RCS

    private enum RCSOutcome { case sent, retry, fallback(String) }

    private func endpoint(for phoneHash: String) async throws -> ChannelEndpointRecord {
        if let existing = try await ChannelEndpointRecord.query(on: db).filter(\.$channel == "rcs").filter(\.$phoneHash == phoneHash).first() {
            return existing
        }
        let created = ChannelEndpointRecord(channel: "rcs", phoneHash: phoneHash, now: ctx.now)
        do {
            try await created.create(on: db)
            return created
        } catch {
            if error.isConstraintViolation,
               let existing = try await ChannelEndpointRecord.query(on: db).filter(\.$channel == "rcs").filter(\.$phoneHash == phoneHash).first() {
                return existing
            }
            throw error
        }
    }

    private func sendRCS(_ row: ChannelOutboundRecord, interaction: Interaction, summary: BusinessSummary, phone: PhoneNumber) async throws -> RCSOutcome {
        let adapter = ctx.channels.rcs
        guard adapter.isEnabled else { return .fallback("disabled") }
        let endpoint = try await endpoint(for: row.phoneHash)
        let now = ctx.now
        // Capability: cached per phone; refreshed when stale or unknown.
        if endpoint.capability == "unknown" || (endpoint.capabilityCheckedAt.map { now.timeIntervalSince($0) > Self.capabilityTTL } ?? true) {
            switch await adapter.capability(for: phone) {
            case .capable: endpoint.capability = "capable"
            case .incapable: endpoint.capability = "incapable"
            case .unknown:
                row.attempts += 1
                if row.attempts >= Self.maxAttempts { return .fallback("capability_unavailable") }
                try await requeue(row)
                return .retry
            }
            endpoint.capabilityCheckedAt = now
            endpoint.updatedAt = now
            try await endpoint.update(on: db)
        }
        guard endpoint.capability == "capable" else { return .fallback("not_capable") }

        // The phone's conversation thread is shared by every business (RCS and SMS alike). While it is connected to another business,
        // that business's reply handling would receive the person's answer to *this* message, so only a content-free notice is sent.
        if let active = try await activeOtherBusiness(phoneHash: row.phoneHash, sender: row.businessId) {
            let notice = GatewayCopy.newMessageNotice(from: summary, whileConnectedTo: active)
            let environment = ChannelEnvironment(db: db, ctx: ctx, reference: row.id?.uuidString.lowercased() ?? "", sensitive: false,
                                                 businessId: BusinessID(row.businessId))
            do {
                let result = try await adapter.send(OutboundChannelMessage(text: notice), to: phone, environment: environment)
                row.providerMessageId = result.providerMessageId
                row.sentAt = now
                row.attempts += 1
                row.status = "sent"
                row.fallbackReason = "thread_connected_elsewhere"
                try await row.update(on: db)
                try await UsageMeter.record(.rcsMessage, businessId: row.businessId, livemode: true, ref: "rcs:" + (row.id?.uuidString.lowercased() ?? ""), at: now, on: db)
                _ = try await AuditService(db: db, ctx: ctx).record("channel.rcs_notice_only", actor: AuditActor(kind: .gateway, id: phone.masked),
                    consumerId: ConsumerID(row.consumerId), businessId: BusinessID(row.businessId), subjectType: "interaction",
                    subjectId: row.interactionId.uuidString.lowercased(), metadata: ["reason": "thread_connected_elsewhere"])
                return .sent
            } catch let error as ChannelError {
                row.attempts += 1
                switch error {
                case .notCapable:
                    endpoint.capability = "incapable"
                    endpoint.capabilityCheckedAt = now
                    try await endpoint.update(on: db)
                    return .fallback("not_capable")
                case .transient:
                    if row.attempts >= Self.maxAttempts { return .fallback("provider_error") }
                    try await requeue(row)
                    return .retry
                default:
                    return .fallback("provider_error")   // the SMS path sends the same notice
                }
            }
        }

        // Render: sensitive (or not inline-presentable) → secure handoff via ChannelRenderer; answerable kinds the chips
        // cannot express → a plain "open in Viadere" link; everything else → suggested replies.
        let inline = AssurancePolicy.canPresentInline(interaction, on: .rcs)
        let answerable = rcsCanAnswerInline(interaction)
        var handoffURL: URL?
        if !inline || !answerable || isLinkKind(interaction) {
            handoffURL = try await HandoffTokens(ctx: ctx).mint(consumerId: row.consumerId, phone: phone, interactionId: row.interactionId, on: db)
        }
        let rendering: ChannelRendering
        if inline && !answerable {
            rendering = handoffOnlyRendering(interaction: interaction, summary: summary, url: handoffURL)
        } else {
            rendering = adapter.render(interaction, business: summary, handoffURL: handoffURL)
        }
        var outbound = OutboundChannelMessage(text: rendering.text)
        let reference = row.id?.uuidString.lowercased() ?? ""
        let environment = ChannelEnvironment(db: db, ctx: ctx, reference: reference, sensitive: false, businessId: BusinessID(row.businessId))
        let menuExpiry = min(interaction.expiresAt, now.addingTimeInterval(GatewayConfiguration().menuTTL))
        let tokens = RCSPostbackTokens(hasher: ctx.hasher)
        do {
            outbound.suggestions = try await db.transaction { tx -> [OutboundSuggestion] in
                var out: [OutboundSuggestion] = []
                let replyCount = rendering.suggestions.filter { if case .reply = $0.action { true } else { false } }.count
                var version = endpoint.activeMenuVersion
                if replyCount > 0 {
                    // A new menu supersedes every earlier one for this phone: bump the version by compare-and-swap.
                    guard try await DB.swap(tx, table: ChannelEndpointRecord.schema, id: endpoint.id!, column: "active_menu_version",
                                            expected: endpoint.activeMenuVersion, newValue: endpoint.activeMenuVersion + 1,
                                            extra: [("menu_expires_at", menuExpiry), ("updated_at", now)]) else { throw ConcurrencyConflict() }
                    version = endpoint.activeMenuVersion + 1
                    try await RCSPostbackRecord.query(on: tx).filter(\.$phoneHash == row.phoneHash).filter(\.$state == "open")
                        .set(\.$state, to: "revoked").update()
                }
                for suggestion in rendering.suggestions {
                    switch suggestion.action {
                    case .reply(let target):
                        let token = tokens.mint()
                        let postback = RCSPostbackRecord()
                        postback.id = UUID()
                        postback.tokenHash = RCSPostbackTokens.storedHash(token)
                        postback.phoneHash = row.phoneHash
                        postback.interactionId = row.interactionId
                        postback.menuVersion = version
                        postback.target = target.storageValue
                        postback.state = "open"
                        postback.expiresAt = menuExpiry
                        postback.createdAt = now
                        try await postback.create(on: tx)
                        out.append(.reply(suggestion.text, token: token))
                    case .openURL(let url):
                        out.append(.openURL(suggestion.text, url: url))
                    }
                }
                return out
            }
        } catch is ConcurrencyConflict {
            row.attempts += 1
            try await requeue(row)
            return .retry
        }
        do {
            let result = try await adapter.send(outbound, to: phone, environment: environment)
            row.providerMessageId = result.providerMessageId
            row.sentAt = now
            row.attempts += 1
            row.status = "sent"
            try await row.update(on: db)
            try await UsageMeter.record(.rcsMessage, businessId: row.businessId, livemode: true, ref: "rcs:" + reference, at: now, on: db)
            _ = try await AuditService(db: db, ctx: ctx).record("channel.rcs_sent", actor: AuditActor(kind: .gateway, id: phone.masked),
                consumerId: ConsumerID(row.consumerId), businessId: BusinessID(row.businessId), subjectType: "interaction",
                subjectId: row.interactionId.uuidString.lowercased(), metadata: ["handoff": rendering.isSecureHandoff ? "true" : "false"])
            return .sent
        } catch let error as ChannelError {
            // The tokens minted for this attempt are useless if nothing was sent.
            try await RCSPostbackRecord.query(on: db).filter(\.$phoneHash == row.phoneHash).filter(\.$interactionId == row.interactionId)
                .filter(\.$state == "open").set(\.$state, to: "revoked").update()
            row.attempts += 1
            switch error {
            case .notCapable:
                endpoint.capability = "incapable"
                endpoint.capabilityCheckedAt = now
                try await endpoint.update(on: db)
                return .fallback("not_capable")
            case .transient:
                if row.attempts >= Self.maxAttempts { return .fallback("provider_error") }
                try await requeue(row)
                return .retry
            default:
                return .fallback("provider_error")
            }
        }
    }

    /// RCS can show suggestion chips only for single-selection answers it can express.
    private func rcsCanAnswerInline(_ interaction: Interaction) -> Bool {
        switch interaction.payload {
        case .choose(let p): return !p.allowsMultiple && p.options.count <= 11
        case .reply(let p): return !p.suggestedReplies.isEmpty
        default: return true
        }
    }

    private func requiresAnswer(_ interaction: Interaction) -> Bool {
        switch interaction.payload {
        case .confirm, .choose, .acknowledge, .reply: true
        default: false
        }
    }

    /// Kinds whose text rendering includes a link (reward, ticket) — they need a handoff URL even when inline.
    private func isLinkKind(_ interaction: Interaction) -> Bool {
        switch interaction.payload {
        case .reward, .ticket: true
        default: false
        }
    }

    private func handoffOnlyRendering(interaction: Interaction, summary: BusinessSummary, url: URL?) -> ChannelRendering {
        let name = SMSEncoding.field(summary.displayName, maxLength: 40)
        var suggestions: [ChannelRendering.Suggestion] = []
        if let url { suggestions.append(.init(text: "Open in Viadere", action: .openURL(url))) }
        return ChannelRendering(text: "[\(name)]: A request needs your response in Viadere.", suggestions: suggestions, isSecureHandoff: false)
    }

    private func requeue(_ row: ChannelOutboundRecord) async throws {
        row.status = "queued"
        row.nextAttemptAt = ctx.now.addingTimeInterval(Self.backoff[min(max(row.attempts - 1, 0), Self.backoff.count - 1)])
        row.errorCode = "transient"
        try await row.update(on: db)
    }

    // MARK: SMS (also the fallback path)

    /// SMS text for an interaction. Numbered replies for interactions are not wired into the gateway engine, so
    /// anything that needs an answer is rendered as a secure handoff (the same rendering a sensitive interaction
    /// gets); informational kinds are sent as-is.
    static func smsRendering(for interaction: Interaction, business: BusinessSummary, handoffURL: URL?) -> ChannelRendering {
        var effective = interaction
        switch interaction.payload {
        case .confirm, .choose, .acknowledge, .reply:
            effective.sensitivity = max(interaction.sensitivity, .high)
        default: break
        }
        let sms = ChannelRenderer.sms(effective, business: business, handoffURL: handoffURL)
        return ChannelRendering(text: sms.body, suggestions: [], isSecureHandoff: sms.isSecureHandoff, smsSegments: sms.encoding.segments)
    }

    private func sendSMS(_ row: ChannelOutboundRecord, interaction: Interaction, summary: BusinessSummary, phone: PhoneNumber,
                         audit: AuditService) async throws {
        let adapter = ctx.channels.sms
        // The phone's SMS thread is shared by every business. While it is connected to another business, that business's reply
        // handling would receive the person's answer to *this* text, so only a content-free notice is sent.
        if let active = try await activeOtherBusiness(phoneHash: row.phoneHash, sender: row.businessId) {
            let notice = GatewayCopy.newMessageNotice(from: summary, whileConnectedTo: active)
            let environment = ChannelEnvironment(db: db, ctx: ctx, reference: row.id?.uuidString.lowercased() ?? "", sensitive: false,
                                                 businessId: BusinessID(row.businessId))
            do {
                let result = try await adapter.send(OutboundChannelMessage(text: notice), to: phone, environment: environment)
                row.channel = "sms"
                row.providerMessageId = result.providerMessageId
                row.sentAt = ctx.now
                row.attempts += 1
                row.status = "sent"
                row.fallbackReason = "thread_connected_elsewhere"
                try await row.update(on: db)
                try await UsageMeter.record(.smsSegment, businessId: row.businessId, quantity: max(1, SMSEncoding.analyze(notice).segments), livemode: true,
                                            ref: "sms:" + (row.id?.uuidString.lowercased() ?? ""), at: ctx.now, on: db)
                _ = try await audit.record("channel.sms_notice_only", actor: AuditActor(kind: .gateway, id: phone.masked),
                    consumerId: ConsumerID(row.consumerId), businessId: BusinessID(row.businessId), subjectType: "interaction",
                    subjectId: row.interactionId.uuidString.lowercased(), metadata: ["reason": "thread_connected_elsewhere"])
            } catch {
                row.channel = "sms"
                try await finish(row, status: "failed", error: "sms_enqueue_failed")
            }
            return
        }
        let preview = Self.smsRendering(for: interaction, business: summary, handoffURL: nil)
        var url: URL?
        let wantsLink = interaction.kind.isSecuritySensitive || interaction.requiredAssurance > .channelReply || isLinkKind(interaction)
            || requiresAnswer(interaction) || preview.isSecureHandoff
        if wantsLink {
            url = try await HandoffTokens(ctx: ctx).mint(consumerId: row.consumerId, phone: phone, interactionId: row.interactionId, on: db)
        }
        let rendering = Self.smsRendering(for: interaction, business: summary, handoffURL: url)
        let reference = row.id?.uuidString.lowercased() ?? ""
        let now = ctx.now
        let environment = ChannelEnvironment(db: db, ctx: ctx, reference: reference, sensitive: url != nil, businessId: BusinessID(row.businessId))
        do {
            let result = try await adapter.send(OutboundChannelMessage(text: rendering.text), to: phone, environment: environment)
            row.channel = "sms"
            row.providerMessageId = result.providerMessageId
            row.sentAt = now
            row.attempts += 1
            row.status = "sent"
            row.errorCode = nil
            try await row.update(on: db)
            try await UsageMeter.record(.smsSegment, businessId: row.businessId, quantity: max(1, rendering.smsSegments), livemode: true,
                                        ref: "sms:" + reference, at: now, on: db)
            _ = try await audit.record("channel.sms_sent", actor: AuditActor(kind: .gateway, id: phone.masked),
                consumerId: ConsumerID(row.consumerId), businessId: BusinessID(row.businessId), subjectType: "interaction",
                subjectId: row.interactionId.uuidString.lowercased(),
                metadata: ["handoff": rendering.isSecureHandoff ? "true" : "false", "fallback_reason": row.fallbackReason ?? ""])
        } catch {
            row.channel = "sms"
            try await finish(row, status: "failed", error: "sms_enqueue_failed")
        }
    }

    /// The business the phone's SMS thread is currently connected to, if it is not `sender`.
    private func activeOtherBusiness(phoneHash: String, sender: UUID) async throws -> BusinessSummary? {
        guard let record = try await SMSContextRecord.query(on: db).filter(\.$phoneHash == phoneHash).first(),
              let data = try? ctx.cipher.open(record.contextCiphertext, context: "sms_contexts.context", rowId: record.id!),
              let thread = try? ViadereJSON.decode(ConversationContext.self, from: data),
              thread.state == .connected || thread.state == .sessionMenu, let session = thread.session,
              session.business.id.uuid != sender else { return nil }
        return session.business
    }

    // MARK: Receipts

    /// Applies an RCS delivery receipt. A failed receipt re-routes a still-pending interaction to SMS.
    func applyReceipt(providerMessageId: String, status: ChannelReceiptStatus, errorCode: String?) async throws {
        guard let row = try await ChannelOutboundRecord.query(on: db).filter(\.$providerMessageId == providerMessageId).first(),
              let id = row.id, row.channel == "rcs" else { return }
        switch status {
        case .delivered, .read:
            if row.status == "sent" {
                _ = try await DB.swap(db, table: ChannelOutboundRecord.schema, id: id, column: "status", expected: "sent", newValue: "delivered")
            }
        case .failed:
            // sent → queued (as SMS): exactly one receipt can win the swap.
            let swapped = try await DB.swap(db, table: ChannelOutboundRecord.schema, id: id, column: "status", expected: "sent", newValue: "queued",
                                            extra: [("channel", "sms"), ("fallback_reason", "rcs_failed"), ("attempts", 0),
                                                    ("next_attempt_at", ctx.now), ("error_code", errorCode ?? "failed")])
            if swapped {
                try await RCSPostbackRecord.query(on: db).filter(\.$interactionId == row.interactionId).filter(\.$state == "open")
                    .set(\.$state, to: "revoked").update()
                if let endpoint = try await ChannelEndpointRecord.query(on: db).filter(\.$channel == "rcs").filter(\.$phoneHash == row.phoneHash).first() {
                    endpoint.capability = "incapable"
                    endpoint.capabilityCheckedAt = ctx.now
                    try await endpoint.update(on: db)
                }
            }
        }
    }
}
