import Fluent
import Foundation
import ViadereCore

// MARK: - Analytics (aggregate only)

/// Aggregate analytics for one business. Counts, rates and latencies only: no consumer identifiers or content.
struct DashboardAnalytics {
    let db: any Database
    let ctx: ServerContext

    struct Overview {
        var days: Int
        var issuedByKind: [(kind: String, count: Int)] = []
        var decidedByKind: [(kind: String, count: Int)] = []
        var totalIssued = 0
        var totalDecided = 0
        var medianLatency: TimeInterval?
        var p90Latency: TimeInterval?
        var latencySamples = 0
        var webhookSucceeded = 0
        var webhookDead = 0
        var webhookPending = 0
        var channelDelivered = 0
        var channelFailed = 0
        var optOuts = 0
        var consentRevocations = 0
        var disconnects = 0
        var activeRelationships = 0
        var reports = 0
        /// Interactions issued per UTC day, oldest first.
        var daily: [(day: Date, count: Int)] = []

        var webhookSuccessRate: Double? {
            let done = webhookSucceeded + webhookDead
            return done == 0 ? nil : Double(webhookSucceeded) / Double(done)
        }
        var channelSuccessRate: Double? {
            let done = channelDelivered + channelFailed
            return done == 0 ? nil : Double(channelDelivered) / Double(done)
        }
    }

    static let decidedStatuses: [InteractionStatus] = [.approved, .denied, .confirmed, .declined, .selected, .replied, .acknowledged, .reported]

    func overview(businessId: UUID, days: Int) async throws -> Overview {
        let days = [7, 30, 90].contains(days) ? days : 30
        let now = ctx.now
        let from = now.addingTimeInterval(-TimeInterval(days) * 86_400)
        var out = Overview(days: days)
        for kind in InteractionKind.known {
            let issued = try await InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
                .filter(\.$createdAt >= from).filter(\.$kind == kind.rawValue).count()
            let decided = try await InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
                .filter(\.$createdAt >= from).filter(\.$kind == kind.rawValue).filter(\.$decidedAt != nil).count()
            out.issuedByKind.append((kind.rawValue, issued))
            out.decidedByKind.append((kind.rawValue, decided))
            out.totalIssued += issued
            out.totalDecided += decided
        }
        let timings = try await InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
            .filter(\.$createdAt >= from).filter(\.$decidedAt != nil).field(\.$createdAt).field(\.$decidedAt).limit(5000).all()
        let latencies = timings.compactMap { row -> TimeInterval? in row.decidedAt.map { max(0, $0.timeIntervalSince(row.createdAt)) } }.sorted()
        out.latencySamples = latencies.count
        out.medianLatency = Self.percentile(latencies, 0.5)
        out.p90Latency = Self.percentile(latencies, 0.9)
        func webhooks(_ status: String) async throws -> Int {
            try await WebhookDeliveryRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$createdAt >= from).filter(\.$status == status).count()
        }
        out.webhookSucceeded = try await webhooks("succeeded")
        out.webhookDead = try await webhooks("dead")
        out.webhookPending = try await webhooks("pending")
        for status in ["sent", "delivered"] {
            out.channelDelivered += try await ChannelOutboundRecord.query(on: db).filter(\.$businessId == businessId)
                .filter(\.$createdAt >= from).filter(\.$status == status).count()
        }
        out.channelFailed = try await ChannelOutboundRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$createdAt >= from)
            .filter(\.$status == "failed").count()
        let abuse = try await AbuseService(db: db, ctx: ctx).metrics(for: businessId, window: TimeInterval(days) * 86_400)
        out.optOuts = abuse.optOuts
        out.reports = abuse.reports
        out.activeRelationships = abuse.activeRelationships
        out.disconnects = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$disconnectedAt >= from).count()
        out.consentRevocations = max(0, abuse.optOuts - out.disconnects)
        // Daily series (UTC).
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .current
        let today = calendar.startOfDay(for: now)
        let span = min(days, 30)
        for offset in stride(from: span - 1, through: 0, by: -1) {
            guard let day = calendar.date(byAdding: .day, value: -offset, to: today), let next = calendar.date(byAdding: .day, value: 1, to: day) else { continue }
            let count = try await InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
                .filter(\.$createdAt >= day).filter(\.$createdAt < next).count()
            out.daily.append((day, count))
        }
        return out
    }

    static func percentile(_ sorted: [TimeInterval], _ p: Double) -> TimeInterval? {
        guard !sorted.isEmpty else { return nil }
        let index = min(sorted.count - 1, max(0, Int((Double(sorted.count - 1) * p).rounded(.up))))
        return sorted[index]
    }

    // MARK: Consent status (counts per purpose)

    struct ConsentRow {
        var purpose: InteractionPurpose
        var granted: Int
        var notGranted: Int
    }

    struct ConsentStatus {
        var active: Int
        var disconnected: Int
        var rows: [ConsentRow]
    }

    func consentStatus(businessId: UUID) async throws -> ConsentStatus {
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$businessId == businessId).field(\.$id).field(\.$status).limit(50_000).all()
        let active = relationships.filter { $0.status == "active" }
        let activeIds = Set(active.compactMap(\.id))
        let grants = try await ConsentGrantRecord.query(on: db).filter(\.$businessId == businessId).field(\.$relationshipId).field(\.$purpose)
            .field(\.$granted).field(\.$version).limit(200_000).all()
        var latest: [String: (version: Int, granted: Bool)] = [:]
        for grant in grants where activeIds.contains(grant.relationshipId) {
            let key = "\(grant.relationshipId)|\(grant.purpose)"
            if let existing = latest[key], existing.version >= grant.version { continue }
            latest[key] = (grant.version, grant.granted)
        }
        var rows: [ConsentRow] = []
        for purpose in InteractionPurpose.allCases {
            var granted = 0, notGranted = 0
            for id in activeIds {
                if let record = latest["\(id)|\(purpose.rawValue)"] {
                    if record.granted { granted += 1 } else { notGranted += 1 }
                } else if purpose.isGrantedByDefault { granted += 1 } else { notGranted += 1 }
            }
            rows.append(ConsentRow(purpose: purpose, granted: granted, notGranted: notGranted))
        }
        return ConsentStatus(active: active.count, disconnected: relationships.count - active.count, rows: rows)
    }

    // MARK: Billing

    func usage(businessId: UUID) async throws -> (totals: UsageMeter.Totals, invoice: InvoicePreview) {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .current
        let now = ctx.now
        let start = calendar.date(from: calendar.dateComponents([.year, .month], from: now)) ?? now
        let end = calendar.date(byAdding: .month, value: 1, to: start) ?? now
        let totals = try await UsageMeter.totals(businessId: businessId, from: start, to: end, on: db)
        return (totals, InvoicePreview.make(totals: totals, rates: ctx.config.billingRates, from: start, to: end))
    }
}

// MARK: - Payload redaction (webhook delivery log)

enum PayloadRedactor {
    /// Keys whose values are consumer-originated content or signature material.
    static let redactedKeys: Set<String> = ["text", "reply", "body", "signedDecision", "signature", "challenge", "payload", "phone", "email",
                                            "accountReference", "message"]

    static func redact(_ value: JSONValue, depth: Int = 0) -> JSONValue {
        guard depth < 8 else { return .string("[truncated]") }
        switch value {
        case .object(let object):
            var out: [String: JSONValue] = [:]
            for (key, inner) in object {
                out[key] = redactedKeys.contains(key) ? .string("[redacted]") : redact(inner, depth: depth + 1)
            }
            return .object(out)
        case .array(let items): return .array(items.prefix(20).map { redact($0, depth: depth + 1) })
        case .string(let s): return .string(s.count > 120 ? String(s.prefix(120)) + "…" : s)
        default: return value
        }
    }

    /// Pretty, sorted, redacted JSON for display.
    static func display(body: String) -> String {
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: Data(body.utf8)),
              let data = try? JSONEncoder.pretty.encode(redact(value)) else { return "[unavailable]" }
        return String(decoding: data, as: UTF8.self)
    }
}

extension JSONEncoder {
    static var pretty: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}

// MARK: - Templates

/// Ready-to-copy requests for common interaction kinds. Built from the real `ViadereCore` types, so they are
/// valid by construction (a test round-trips and validates every one).
struct InteractionTemplate {
    var id: String
    var title: String
    var summary: String
    var method: String
    var path: String
    var json: String
    var request: IssueInteractionRequest?
}

enum InteractionTemplates {
    static let placeholderRelationship = RelationshipID(UUID(uuidString: "00000000-0000-4000-8000-000000000000")!)

    static func all(now: Date) -> [InteractionTemplate] {
        let rel = placeholderRelationship
        func issue(_ id: String, _ title: String, _ summary: String, purpose: InteractionPurpose, payload: InteractionPayload,
                   sensitivity: Sensitivity, channels: [DeliveryChannel], ttl: Int) -> InteractionTemplate {
            let request = IssueInteractionRequest(relationshipId: rel, purpose: purpose, payload: payload, sensitivity: sensitivity,
                                                  allowedChannels: channels, ttlSeconds: ttl, idempotencyKey: "\(id)-0001",
                                                  correlationId: "your-reference-123")
            return InteractionTemplate(id: id, title: title, summary: summary, method: "POST", path: APIRoutes.businessIssueInteraction.template,
                                       json: pretty(request), request: request)
        }
        var templates: [InteractionTemplate] = [
            issue("sign-in", "Sign-in approval", "Ask the customer to approve a sign-in. Approved only with a device signature, never by text.",
                  purpose: .security,
                  payload: .authenticate(AuthenticatePayload(service: "Online account", device: "Chrome on macOS", approximateLocation: "Mesa, AZ", attemptedAt: now)),
                  sensitivity: .standard, channels: [.nativePush, .inApp], ttl: 120),
            issue("payment", "Payment approval", "Describe exactly what approving does. High-assurance: Face ID signs the decision.",
                  purpose: .security,
                  payload: .authorize(AuthorizePayload(actionDescription: "Card purchase", amount: try? MoneyAmount(string: "84.20", currency: .usd), merchant: "Example Store",
                                                       location: "Phoenix, AZ", effectOfApproval: "The purchase will go through.")),
                  sensitivity: .high, channels: [.nativePush, .inApp], ttl: 300),
            issue("booking", "Confirm a booking", "A yes/no confirmation. Works in the app and over RCS suggested replies.",
                  purpose: .transactional,
                  payload: .confirm(ConfirmPayload(title: "Confirm your appointment", details: "Thursday 10:30 at our Main Street office", reference: "BK-20418")),
                  sensitivity: .standard, channels: [.nativePush, .inApp, .rcs, .sms], ttl: 3600),
            issue("slot", "Choose a time", "Up to ten options. Rendered as notification actions, RCS chips or an in-app picker.",
                  purpose: .support,
                  payload: .choose(ChoosePayload(prompt: "Which time suits you?", options: [
                      ChoiceOption(id: "slot-0900", label: "9:00 am"), ChoiceOption(id: "slot-1030", label: "10:30 am"), ChoiceOption(id: "slot-1400", label: "2:00 pm"),
                  ])),
                  sensitivity: .standard, channels: [.nativePush, .inApp, .rcs, .sms], ttl: 3600),
            issue("terms", "Acknowledge an update", "Record that the customer saw a policy or terms change.",
                  purpose: .accountService,
                  payload: .acknowledge(AcknowledgePayload(title: "Updated terms", body: "We changed how we handle refunds.", documentURL: URL(string: "https://example.com/terms"), documentVersion: "2026-10")),
                  sensitivity: .low, channels: [.nativePush, .inApp], ttl: 7 * 86_400),
            issue("quick-reply", "Ask for a reply", "A short free-text answer, with optional suggested replies.",
                  purpose: .support,
                  payload: .reply(ReplyPayload(prompt: "Was your issue resolved?", maxLength: 280, suggestedReplies: ["Yes, thanks", "Not yet"])),
                  sensitivity: .low, channels: [.nativePush, .inApp, .rcs], ttl: 86_400),
        ]
        let status = BusinessStatusUpdateRequest(relationshipId: rel, purpose: .transactional,
                                                 status: StatusPayload(title: "Your order is out for delivery", body: "Arriving today between 2 and 4 pm."),
                                                 activityKey: "order-1042", idempotencyKey: "order-1042-status-3")
        templates.append(InteractionTemplate(id: "delivery-status", title: "Delivery status", summary: "An ongoing-event update; a newer update with the same activityKey replaces the last.",
                                             method: "POST", path: APIRoutes.businessUpdateStatus.template, json: pretty(status), request: nil))
        let message = BusinessSendMessageRequest(relationshipId: rel, body: "Thanks for waiting. Your refund has been issued.", agentName: "Sam", idempotencyKey: "msg-0001")
        templates.append(InteractionTemplate(id: "support-message", title: "Support reply", summary: "A message in the customer's conversation with you, attributed to your business.",
                                             method: "POST", path: APIRoutes.businessSendMessage.template, json: pretty(message), request: nil))
        return templates
    }

    static func pretty<T: Encodable>(_ value: T) -> String {
        guard let data = try? ViadereJSON.encode(value), let object = try? JSONSerialization.jsonObject(with: data),
              let out = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else { return "{}" }
        return String(decoding: out, as: UTF8.self)
    }
}
