import Foundation
import ViadereCore

/// What the notification service extension turns an opaque push into.
public struct EnrichedNotification: Sendable, Equatable {
    public var title: String
    public var subtitle: String
    public var body: String
    public var threadIdentifier: String
    public var interruptionLevel: NotificationRendering.InterruptionLevel
    public var category: NotificationCategoryModel
    public var userInfo: [String: String]
    public var requiresSecureFlow: Bool
    /// True when details could not be fetched and a generic "open Viadere" notification is shown instead.
    public var isFallback: Bool
}

/// The compact approval card shown by the notification *content* extension for sign-in and approval requests.
/// Rendered by the service extension from the fetched interaction and carried in `userInfo["viadere.card"]`
/// as JSON, so the content extension needs no network access and no credentials.
public struct NotificationCard: Codable, Sendable, Equatable {
    public struct Row: Codable, Sendable, Equatable {
        public var label: String
        public var value: String
        public var emphasized: Bool
    }

    public static let userInfoKey = "viadere.card"

    public var business: String
    /// Whether Viadere has verified this business (drives the badge; never assumed).
    public var isVerified: Bool
    /// True when the business name imitates "Viadere": the card shows a warning.
    public var impersonatesViadere: Bool
    public var kind: String
    public var kindLabel: String
    public var question: String
    public var rows: [Row]
    public var risks: [String]
    public var createdAt: Date
    public var expiresAt: Date
    public var verification: String?
    /// Sensitive approvals finish in the app (Face ID); the card says so.
    public var finishesInApp: Bool

    /// Every business-supplied string passes through `UntrustedText` (via `InteractionPresentation`).
    public init(envelope: InteractionEnvelope, now: Date, finishesInApp: Bool) {
        let interaction = envelope.interaction
        let name = UntrustedText.name(envelope.business.displayName, max: 40)
        business = name.text
        impersonatesViadere = name.impersonatesViadere
        isVerified = envelope.business.isVerified
        kind = interaction.kind.rawValue
        kindLabel = InteractionPresentation.kindLabel(interaction)
        question = InteractionPresentation.question(interaction)
        rows = InteractionPresentation.details(envelope, now: now)
            .filter { $0.label != "From" }
            .prefix(4)
            .map { Row(label: $0.label, value: $0.value, emphasized: $0.emphasized) }
        risks = InteractionPresentation.riskIndicators(interaction).prefix(2).map(\.label)
        createdAt = interaction.createdAt
        expiresAt = interaction.expiresAt
        verification = InteractionPresentation.verificationLabel(ApprovalPolicy.plan(for: interaction, device: DeviceRecord(
            deviceId: DeviceID(), consumerId: interaction.scope.consumerId, name: "", purposes: DeviceKeyPurpose.allCases, enrolledAt: now)))
        self.finishesInApp = finishesInApp
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        business = UntrustedText.name(try c.decode(String.self, forKey: .business), max: 40).text
        isVerified = try c.decodeIfPresent(Bool.self, forKey: .isVerified) ?? false
        impersonatesViadere = try c.decodeIfPresent(Bool.self, forKey: .impersonatesViadere) ?? false
        kind = try c.decode(String.self, forKey: .kind)
        kindLabel = try c.decode(String.self, forKey: .kindLabel)
        question = UntrustedText.line(try c.decode(String.self, forKey: .question), max: 400)
        rows = try c.decode([Row].self, forKey: .rows).map {
            Row(label: UntrustedText.line($0.label, max: 30), value: UntrustedText.line($0.value, max: 120), emphasized: $0.emphasized)
        }
        risks = try c.decode([String].self, forKey: .risks).map { UntrustedText.line($0, max: 60) }
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        verification = try c.decodeIfPresent(String.self, forKey: .verification)
        finishesInApp = try c.decode(Bool.self, forKey: .finishesInApp)
    }

    public func json() -> String? {
        (try? ViadereJSON.encode(self)).flatMap { String(data: $0, encoding: .utf8) }
    }

    public static func decode(json: String) -> NotificationCard? {
        try? ViadereJSON.decode(NotificationCard.self, from: Data(json.utf8))
    }
}

/// Fetches an interaction by its opaque id and renders it with `ChannelRenderer` (platform-neutral part of the
/// notification service extension). Also computes the per-interaction `choose` category the extension registers.
public struct NotificationEnricher: Sendable {
    private let api: any ViadereAPI
    private let preferences: (any PreferencesStore)?
    private let clock: @Sendable () -> Date

    /// - Parameter preferences: when `richNotificationPreviews` is off (the default, and the case when no store is
    ///   given) approval and sign-in notifications carry only a generic body on the lock screen
    ///   ("Approval requested by Northfield Market") and no detail card; the details appear inside the app.
    public init(api: any ViadereAPI, preferences: (any PreferencesStore)? = nil, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.preferences = preferences
        self.clock = clock
    }

    private var richPreviews: Bool { preferences?.bool(.richNotificationPreviews) ?? false }

    /// Returns `nil` if the push carries no interaction id (leave the notification untouched).
    public func enrich(userInfo: [AnyHashable: Any]) async -> EnrichedNotification? {
        guard let id = PushPayload.interactionId(from: userInfo) else { return nil }
        return await enrich(interactionId: id)
    }

    /// Fetches and renders one interaction (the service extension calls this with the id extracted from the push).
    public func enrich(interactionId id: InteractionID) async -> EnrichedNotification {
        guard let envelope = try? await api.interaction(id) else { return Self.fallback(interactionId: id) }
        let now = clock()

        if envelope.status != .pending && envelope.interaction.kind != .status {
            return EnrichedNotification(
                title: UntrustedText.name(envelope.business.displayName, max: 40).text, subtitle: "Already handled",
                body: "This request was already handled.", threadIdentifier: "business.\(envelope.business.id)",
                interruptionLevel: .passive, category: NotificationCategoryModel(identifier: "viadere.status", actions: []),
                userInfo: ["interactionId": id.description, "businessId": envelope.business.id.description], requiresSecureFlow: false,
                isFallback: false)
        }
        if envelope.interaction.isExpired(at: now) && envelope.interaction.kind != .status {
            return EnrichedNotification(
                title: UntrustedText.name(envelope.business.displayName, max: 40).text, subtitle: "Expired",
                body: "This request has expired.", threadIdentifier: "business.\(envelope.business.id)",
                interruptionLevel: .passive, category: NotificationCategoryModel(identifier: "viadere.status", actions: []),
                userInfo: ["interactionId": id.description, "businessId": envelope.business.id.description], requiresSecureFlow: false,
                isFallback: false)
        }
        let rendering = ChannelRenderer.notification(envelope.interaction, business: envelope.business)
        let business = UntrustedText.name(envelope.business.displayName, max: 40)
        let sensitive = envelope.interaction.kind.isSecuritySensitive
        var userInfo = rendering.userInfo
        var subtitle = UntrustedText.line(rendering.subtitle, max: 60)
        var body = UntrustedText.line(rendering.body, max: 200)
        if sensitive {
            if richPreviews {
                // The user opted in: show the facts, built from sanitized pieces (not the renderer's raw text).
                body = InteractionPresentation.question(envelope.interaction)
                if let card = NotificationCard(envelope: envelope, now: now, finishesInApp: rendering.requiresSecureFlow).json() {
                    userInfo[NotificationCard.userInfoKey] = card
                }
            } else {
                subtitle = InteractionPresentation.kindLabel(envelope.interaction)
                body = Self.genericBody(for: envelope.interaction.kind, business: business.text, verified: envelope.business.isVerified)
            }
        }
        let actions = rendering.category.actions.map { action -> NotificationActionModel in
            var model = NotificationActionModel(action)
            let title = UntrustedText.line(model.title, max: 40)
            model.title = title.isEmpty ? "Option" : title
            return model
        }
        return EnrichedNotification(
            title: business.text, subtitle: subtitle, body: body, threadIdentifier: rendering.threadIdentifier,
            interruptionLevel: rendering.interruptionLevel,
            category: NotificationCategoryModel(identifier: rendering.category.identifier, actions: actions), userInfo: userInfo,
            requiresSecureFlow: rendering.requiresSecureFlow, isFallback: false)
    }

    /// Lock-screen text that names only who is asking, never what for.
    public static func genericBody(for kind: InteractionKind, business: String, verified: Bool) -> String {
        let who = verified ? business : "unverified business \(business)"
        switch kind {
        case .authenticate: return "Sign-in approval requested by \(who)"
        default: return "Approval requested by \(who)"
        }
    }

    /// Generic notification when the interaction cannot be fetched (offline, device locked before first unlock).
    public static func fallback(interactionId: InteractionID) -> EnrichedNotification {
        EnrichedNotification(
            title: "Viadere", subtitle: "Action needed", body: "Open Viadere to review a request.",
            threadIdentifier: "viadere.general", interruptionLevel: .active,
            category: NotificationCategoryModel(identifier: "viadere.unknown", actions: [
                NotificationActionModel(identifier: "viadere.open", title: "Open", requiresAuthentication: true, opensApp: true),
            ]),
            userInfo: ["interactionId": interactionId.description], requiresSecureFlow: true, isFallback: true)
    }

    /// Static categories (`ChannelRenderer.staticCategories`) with their actions, so the app registers the
    /// same shapes the renderer produces. Built by rendering a representative interaction per category.
    public static func staticCategorySpecs() -> [NotificationCategoryModel] {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let business = PreviewData.northfield
        let rel = RelationshipID()
        func scope() -> RelationshipScope { RelationshipScope(consumerId: PreviewData.consumerId, relationshipId: rel) }
        func make(_ payload: InteractionPayload, sensitivity: Sensitivity, purpose: InteractionPurpose = .transactional) -> Interaction {
            Interaction(businessId: business.id, scope: scope(), purpose: purpose, payload: payload, sensitivity: sensitivity,
                        createdAt: now, expiresAt: now.addingTimeInterval(600), idempotencyKey: "static")
        }
        let auth = AuthenticatePayload(service: "x", device: "x", attemptedAt: now)
        let authz = AuthorizePayload(actionDescription: "x")
        let samples: [Interaction] = [
            make(.authenticate(auth), sensitivity: .low, purpose: .security),
            make(.authenticate(auth), sensitivity: .high, purpose: .security),
            make(.authorize(authz), sensitivity: .low, purpose: .security),
            make(.authorize(authz), sensitivity: .high, purpose: .security),
            make(.confirm(ConfirmPayload(title: "x")), sensitivity: .low),
            make(.confirm(ConfirmPayload(title: "x")), sensitivity: .high),
            make(.acknowledge(AcknowledgePayload(title: "x", body: "x")), sensitivity: .low),
            make(.acknowledge(AcknowledgePayload(title: "x", body: "x")), sensitivity: .high),
            make(.reply(ReplyPayload(prompt: "x")), sensitivity: .low),
            make(.status(StatusPayload(title: "x")), sensitivity: .low),
            make(.reward(RewardPayload(rewardId: RewardID(), title: "x")), sensitivity: .low, purpose: .rewards),
            make(.ticket(TicketPayload(title: "x", ticketType: "event")), sensitivity: .low),
            make(.message(MessagePayload(text: "x")), sensitivity: .low),
            make(.unknown(.null), sensitivity: .critical),
        ]
        var seen = Set<String>()
        var specs: [NotificationCategoryModel] = []
        for interaction in samples {
            let spec = ChannelRenderer.notification(interaction, business: business).category
            if ChannelRenderer.staticCategories.contains(spec.identifier), seen.insert(spec.identifier).inserted {
                specs.append(NotificationCategoryModel(spec))
            }
        }
        return specs
    }
}
