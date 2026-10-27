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
