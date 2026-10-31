import Fluent
import Foundation
import ViadereCore

/// Sends ActivityKit pushes for status interactions that carry a `LiveActivityStatus`.
///
/// Only statuses `LiveActivityPolicy` allows ever produce a push (ongoing, non-promotional purposes), so marketing, rewards and
/// security-purpose interactions never reach this path. The content is only the activity's own state; the start alert is neutral.
struct LiveActivityService {
    let db: any Database
    let ctx: ServerContext

    /// Best effort, like every push: the interaction is already stored and available through the API.
    func push(record: InteractionRecord, interaction: Interaction) async {
        guard interaction.allowedChannels.contains(.nativePush), case .status(let status) = interaction.payload,
              let content = status.liveActivity, LiveActivityPolicy.isEligible(purpose: interaction.purpose, status: content) else { return }
        do {
            try await send(record: record, interaction: interaction, content: content)
        } catch {
            // Never fails the request that issued the status.
        }
    }

    private func send(record: InteractionRecord, interaction: Interaction, content: LiveActivityStatus) async throws {
        let consumerId = record.consumerId
        let now = ctx.now
        let timestamp = Int(now.timeIntervalSince1970)
        guard let business = try await BusinessRecord.find(record.businessId, on: db),
              let summary = try await DirectoryService(db: db).summary(for: business) else { return }
        let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all()
        let deviceIds = devices.compactMap(\.id)
        guard !deviceIds.isEmpty else { return }
        let apnsTokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).all()
        func target(_ device: UUID) -> (APNsTokenRegistration.Environment, String) {
            if let token = apnsTokens.first(where: { $0.deviceId == device }) {
                return (APNsTokenRegistration.Environment(rawValue: token.environment) ?? .production,
                        token.bundleId.isEmpty ? ctx.config.appBundleID : token.bundleId)
            }
            return (ctx.config.apns.map { $0.useSandbox ? .sandbox : .production } ?? .production, ctx.config.appBundleID)
        }

        // The activity this update belongs to: every status interaction for the same ongoing event.
        var chain = [record.id!]
        if let key = record.activityKey {
            chain = try await InteractionRecord.query(on: db).filter(\.$businessId == record.businessId).filter(\.$consumerId == consumerId)
                .filter(\.$activityKey == key).all().compactMap(\.id)
        }
        let updateTokens = try await LiveActivityTokenRecord.query(on: db).filter(\.$consumerId == consumerId)
            .filter(\.$kind == LiveActivityTokenRegistration.Kind.update.rawValue).filter(\.$deviceId ~~ deviceIds)
            .filter(\.$businessId == record.businessId).filter(\.$interactionId ~~ chain).all()

        if !updateTokens.isEmpty {
            for token in updateTokens {
                let (environment, bundle) = target(token.deviceId)
                let push = LiveActivityPush(deviceToken: token.pushToken, environment: environment, bundleId: bundle,
                                            event: content.isTerminal ? .end : .update, content: content, timestamp: timestamp)
                if await ctx.apns.sendLiveActivity(push) == .tokenInvalid {
                    try await LiveActivityTokenRecord.query(on: db).filter(\.$id == token.id!).delete()
                }
            }
            return
        }
        // No running activity to update. A finished event never starts one; an ongoing one starts at most once per event.
        guard !content.isTerminal else { return }
        let startTokens = try await LiveActivityTokenRecord.query(on: db).filter(\.$consumerId == consumerId)
            .filter(\.$kind == LiveActivityTokenRegistration.Kind.pushToStart.rawValue).filter(\.$deviceId ~~ deviceIds).all()
        guard !startTokens.isEmpty else { return }
        if let key = record.activityKey {
            let marker = LiveActivityStartRecord()
            marker.id = UUID()
            marker.businessId = record.businessId
            marker.consumerId = consumerId
            marker.activityKey = key
            marker.createdAt = now
            do { try await marker.create(on: db) } catch {
                if error.isConstraintViolation { return }
                throw error
            }
        }
        for token in startTokens {
            let (environment, bundle) = target(token.deviceId)
            let attributes = LiveActivityPush.Attributes(businessName: summary.displayName, businessId: summary.id.description,
                                                         interactionId: interaction.id.description)
            let push = LiveActivityPush(deviceToken: token.pushToken, environment: environment, bundleId: bundle, event: .start, content: content,
                                        timestamp: timestamp, attributes: attributes, alertTitle: "Viadere", alertBody: "There is an update.")
            if await ctx.apns.sendLiveActivity(push) == .tokenInvalid {
                try await LiveActivityTokenRecord.query(on: db).filter(\.$id == token.id!).delete()
            }
        }
    }

    // MARK: Decision activities (docs/SECURITY.md §2.16)

    /// Seconds an ended decision activity stays on the Lock Screen showing its stage before it is dismissed.
    static let decisionDismissalDelay = 8
    /// The start alert of a decision activity: as neutral as the interaction's own push (`PushPayloadBuilder`).
    static let decisionAlertBody = "You have a new request."

    /// Starts a decision activity (Lock Screen buttons) for an eligible `confirm` / `choose` on the consumer's own app devices.
    ///
    /// Called by `InteractionService.push` only after the messaging gate allowed the push and only when the person has not muted the
    /// business, so it follows exactly the same rules. The content is the neutral `DecisionActivityState` (`LiveActivityPolicy`): no title,
    /// details, prompt, option labels or reference ever enter it; the app fetches and adds those itself. Delegates never get one.
    func startDecision(record: InteractionRecord, interaction: Interaction, business summary: BusinessSummary) async {
        guard let state = LiveActivityPolicy.neutralDecisionState(for: interaction, livemode: record.livemode) else { return }
        do {
            let consumerId = record.consumerId
            // App devices only: an App Clip can never decide, so it never gets buttons.
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all()
                .filter { $0.kind == .app }
            let deviceIds = devices.compactMap(\.id)
            guard !deviceIds.isEmpty else { return }
            let startTokens = try await LiveActivityTokenRecord.query(on: db).filter(\.$consumerId == consumerId)
                .filter(\.$kind == LiveActivityTokenRegistration.Kind.pushToStart.rawValue).filter(\.$deviceId ~~ deviceIds).all()
            guard !startTokens.isEmpty else { return }
            let routes = try await routing(deviceIds)
            let timestamp = Int(ctx.now.timeIntervalSince1970)
            let attributes = LiveActivityPush.Attributes(businessName: summary.displayName, businessId: summary.id.description,
                                                         interactionId: interaction.id.description)
            for token in startTokens {
                let (environment, bundle) = routes(token.deviceId)
                let push = LiveActivityPush(deviceToken: token.pushToken, environment: environment, bundleId: bundle, event: .start,
                                            content: .decision(state.neutral), timestamp: timestamp, attributes: attributes,
                                            alertTitle: PushPayloadBuilder.genericTitle, alertBody: Self.decisionAlertBody,
                                            staleDate: Int(interaction.expiresAt.timeIntervalSince1970))
                if await ctx.apns.sendLiveActivity(push) == .tokenInvalid {
                    try await LiveActivityTokenRecord.query(on: db).filter(\.$id == token.id!).delete()
                }
            }
        } catch {
            // Best effort: the notification and the app remain the way to answer.
        }
    }

    /// Ends the decision activity of an interaction that is no longer pending (answered, expired, withdrawn), on every device that
    /// registered an update token for it. The content is the neutral state with the final stage, never business text. Each token is
    /// used once and then deleted, so a repeated call sends nothing. Call it after the status change has committed.
    func endDecision(interactionId: UUID) async {
        do {
            guard let record = try await InteractionRecord.find(interactionId, on: db), record.livemode, record.statusValue != .pending else { return }
            let kind: DecisionActivityState.Kind
            switch InteractionKind(rawValue: record.kind) {
            case .confirm: kind = .confirm
            case .choose: kind = .choose
            default: return
            }
            let tokens = try await LiveActivityTokenRecord.query(on: db).filter(\.$consumerId == record.consumerId)
                .filter(\.$kind == LiveActivityTokenRegistration.Kind.update.rawValue).filter(\.$businessId == record.businessId)
                .filter(\.$interactionId == interactionId).all()
            guard !tokens.isEmpty else { return }
            let live = Set(try await DeviceRecord.query(on: db).filter(\.$id ~~ Set(tokens.map(\.deviceId))).filter(\.$revokedAt == nil).all().compactMap(\.id))
            let routes = try await routing(Array(live))
            let state = DecisionActivityState(interactionId: InteractionID(interactionId), kind: kind, expiresAt: record.expiresAt,
                                              stage: DecisionActivityState.stage(for: record.statusValue))
            let timestamp = Int(ctx.now.timeIntervalSince1970)
            for token in tokens {
                if live.contains(token.deviceId) {
                    let (environment, bundle) = routes(token.deviceId)
                    let push = LiveActivityPush(deviceToken: token.pushToken, environment: environment, bundleId: bundle, event: .end,
                                                content: .decision(state), timestamp: timestamp,
                                                dismissalDate: timestamp + Self.decisionDismissalDelay)
                    // A transient failure keeps the token so a later call can still end the activity (its stale date ends it anyway).
                    if await ctx.apns.sendLiveActivity(push) == .failed { continue }
                }
                try await LiveActivityTokenRecord.query(on: db).filter(\.$id == token.id!).delete()
            }
        } catch {
            // Best effort: the activity also goes stale at the interaction's expiry, and the app reconciles it on launch.
        }
    }

    /// APNs environment and bundle for each device, from its registered APNs token (else the server's configuration).
    private func routing(_ deviceIds: [UUID]) async throws -> @Sendable (UUID) -> (APNsTokenRegistration.Environment, String) {
        let tokens = deviceIds.isEmpty ? [] : try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).all()
        let byDevice = Dictionary(tokens.map { ($0.deviceId, (APNsTokenRegistration.Environment(rawValue: $0.environment) ?? .production, $0.bundleId)) },
                                  uniquingKeysWith: { first, _ in first })
        let fallbackEnvironment: APNsTokenRegistration.Environment = ctx.config.apns.map { $0.useSandbox ? .sandbox : .production } ?? .production
        let appBundle = ctx.config.appBundleID
        return { device in
            guard let (environment, bundle) = byDevice[device] else { return (fallbackEnvironment, appBundle) }
            return (environment, bundle.isEmpty ? appBundle : bundle)
        }
    }

    // MARK: Token registration

    static let maxTokensPerDevice = 40

    /// Stores a token, replacing the device's previous one for the same activity (or the single push-to-start slot).
    func register(principal: ConsumerPrincipal, body: LiveActivityTokenRegistration) async throws {
        guard let deviceId = principal.deviceId, (16...400).contains(body.pushToken.count), body.pushToken.allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
            throw APIError.validation("The push token is not valid.")
        }
        let now = ctx.now
        let activityId = body.activityId.map { String($0.prefix(128)) }
        var existing = LiveActivityTokenRecord.query(on: db).filter(\.$deviceId == deviceId.uuid).filter(\.$kind == body.kind.rawValue)
        if body.kind == .update {
            // An update token is only meaningful for a specific business's activity the person is connected to.
            guard let businessId = body.businessId, try await RelationshipRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid)
                .filter(\.$businessId == businessId.uuid).filter(\.$status == "active").count() > 0 else {
                throw APIError.validation("The token is not valid for this business.")
            }
            existing = existing.filter(\.$activityId == activityId)
        }
        if let current = try await existing.first() {
            current.pushToken = body.pushToken.lowercased()
            current.businessId = body.businessId?.uuid
            current.interactionId = body.interactionId?.uuid
            current.updatedAt = now
            try await current.update(on: db)
            return
        }
        // Bound the table per device: drop the oldest update tokens beyond the cap (the push-to-start token is never evicted).
        let all = try await LiveActivityTokenRecord.query(on: db).filter(\.$deviceId == deviceId.uuid)
            .filter(\.$kind == LiveActivityTokenRegistration.Kind.update.rawValue).sort(\.$updatedAt, .ascending).all()
        if body.kind == .update, all.count >= Self.maxTokensPerDevice {
            for stale in all.prefix(all.count - Self.maxTokensPerDevice + 1) { try await stale.delete(on: db) }
        }
        let record = LiveActivityTokenRecord()
        record.id = UUID()
        record.consumerId = principal.consumerId.uuid
        record.deviceId = deviceId.uuid
        record.kind = body.kind.rawValue
        record.activityId = activityId
        record.businessId = body.businessId?.uuid
        record.interactionId = body.interactionId?.uuid
        record.pushToken = body.pushToken.lowercased()
        record.updatedAt = now
        try await record.create(on: db)
    }
}

/// The acknowledgments a person has recorded, with the server's own timestamp.
struct AcknowledgmentService {
    let db: any Database
    let ctx: ServerContext

    /// Acknowledge-kind interactions the consumer decided (acknowledged or declined). `recordedAt` is the server time the
    /// signed decision was accepted, never a device clock.
    func list(consumer: ConsumerID) async throws -> [AcknowledgmentRecord] {
        let records = try await InteractionRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
            .filter(\.$kind == InteractionKind.acknowledge.rawValue)
            .filter(\.$status ~~ [InteractionStatus.acknowledged.rawValue, InteractionStatus.declined.rawValue])
            .sort(\.$decidedAt, .descending).limit(100).all()
        guard !records.isEmpty else { return [] }
        let decisions = try await DecisionRecord.query(on: db).filter(\.$interactionId ~~ records.compactMap(\.id)).all()
        let decisionByInteraction = Dictionary(decisions.map { ($0.interactionId, $0) }, uniquingKeysWith: { a, _ in a })
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Array(Set(records.map(\.businessId)))).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        let byId = Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { a, _ in a })
        return records.compactMap { record in
            // Erased (deleted-account) payloads and unknown businesses are skipped.
            guard let id = record.id, let summary = byId[record.businessId], let interaction = try? record.interaction(),
                  case .acknowledge(let payload) = interaction.payload else { return nil }
            let decision = decisionByInteraction[id]
            return AcknowledgmentRecord(
                id: InteractionID(id), business: summary, title: payload.title, documentVersion: payload.documentVersion,
                documentDigest: payload.documentDigest, acknowledged: record.statusValue == .acknowledged,
                recordedAt: decision?.decidedAt ?? record.decidedAt ?? record.createdAt, channel: decision.flatMap { Channel(rawValue: $0.channel) })
        }
    }
}
