import Foundation

/// Order progress.
public struct OrderActivityState: Codable, Sendable, Hashable {
    public enum Stage: String, Codable, Sendable { case placed, preparing, ready, completed, cancelled }
    public var orderReference: String
    public var stage: Stage
    public var estimatedReadyAt: Date?
    public var note: String?

    public init(orderReference: String, stage: Stage, estimatedReadyAt: Date? = nil, note: String? = nil) {
        self.orderReference = orderReference
        self.stage = stage
        self.estimatedReadyAt = estimatedReadyAt
        self.note = note
    }
}

/// Delivery / shipment tracking.
public struct DeliveryActivityState: Codable, Sendable, Hashable {
    public enum Stage: String, Codable, Sendable { case labelCreated, inTransit, outForDelivery, delivered, exception }
    public var trackingReference: String
    public var stage: Stage
    public var carrierName: String?
    public var estimatedDeliveryAt: Date?
    public var stopsAway: Int?

    public init(trackingReference: String, stage: Stage, carrierName: String? = nil, estimatedDeliveryAt: Date? = nil,
                stopsAway: Int? = nil) {
        self.trackingReference = trackingReference
        self.stage = stage
        self.carrierName = carrierName
        self.estimatedDeliveryAt = estimatedDeliveryAt
        self.stopsAway = stopsAway
    }
}

/// Flight status.
public struct FlightActivityState: Codable, Sendable, Hashable {
    public enum Stage: String, Codable, Sendable { case scheduled, delayed, boarding, departed, landed, cancelled, diverted }
    public var flightNumber: String
    /// IATA codes.
    public var departureAirport: String
    public var arrivalAirport: String
    public var stage: Stage
    public var scheduledDeparture: Date
    public var estimatedDeparture: Date?
    public var estimatedArrival: Date?
    public var gate: String?
    public var seat: String?

    public init(flightNumber: String, departureAirport: String, arrivalAirport: String, stage: Stage, scheduledDeparture: Date,
                estimatedDeparture: Date? = nil, estimatedArrival: Date? = nil, gate: String? = nil, seat: String? = nil) {
        self.flightNumber = flightNumber
        self.departureAirport = departureAirport
        self.arrivalAirport = arrivalAirport
        self.stage = stage
        self.scheduledDeparture = scheduledDeparture
        self.estimatedDeparture = estimatedDeparture
        self.estimatedArrival = estimatedArrival
        self.gate = gate
        self.seat = seat
    }
}

/// Appointment status.
public struct AppointmentActivityState: Codable, Sendable, Hashable {
    public enum Stage: String, Codable, Sendable { case upcoming, checkInOpen, checkedIn, inProgress, completed, cancelled }
    public var title: String
    public var startsAt: Date
    public var location: String?
    public var providerName: String?
    public var stage: Stage

    public init(title: String, startsAt: Date, location: String? = nil, providerName: String? = nil, stage: Stage) {
        self.title = title
        self.startsAt = startsAt
        self.location = location
        self.providerName = providerName
        self.stage = stage
    }
}

/// A business decision (`confirm` or `choose`) waiting on the Lock Screen / Dynamic Island.
///
/// Privacy rule (docs/SECURITY.md §2.16): the server only ever fills `interactionId`, `kind`, `expiresAt` and `stage`. The
/// enrichment fields (`title`, `detail`, `options`) carry business-authored text and are written **on the device only**, after the
/// app fetched the interaction over the authenticated API and sanitized it; a server push always leaves them `nil`.
public struct DecisionActivityState: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable, CaseIterable { case confirm, choose }
    public enum Stage: String, Codable, Sendable, CaseIterable { case pending, answered, expired, cancelled }

    /// One inline choice (device-side enrichment only).
    public struct Option: Codable, Sendable, Hashable {
        public var id: String
        public var label: String
        public init(id: String, label: String) {
            self.id = id
            self.label = label
        }
    }

    /// At most this many inline options (Lock Screen space, and `LiveActivityPolicy.maxInlineOptions`).
    public static let maxOptions = 3

    public var interactionId: InteractionID
    public var kind: Kind
    public var expiresAt: Date
    public var stage: Stage
    /// Device-side enrichment only; always `nil` in a server push.
    public var title: String?
    /// Device-side enrichment only; always `nil` in a server push.
    public var detail: String?
    /// Device-side enrichment only (≤ `maxOptions`); always `nil` in a server push.
    public var options: [Option]?

    public init(interactionId: InteractionID, kind: Kind, expiresAt: Date, stage: Stage = .pending, title: String? = nil,
                detail: String? = nil, options: [Option]? = nil) {
        self.interactionId = interactionId
        self.kind = kind
        self.expiresAt = expiresAt
        self.stage = stage
        self.title = title
        self.detail = detail
        self.options = options.map { Array($0.prefix(Self.maxOptions)) }
    }

    /// The stage an interaction status maps to (a superseded `delivered` reads as cancelled; every decision as answered).
    public static func stage(for status: InteractionStatus) -> Stage {
        switch status {
        case .pending: .pending
        case .expired: .expired
        case .cancelled, .delivered: .cancelled
        case .approved, .denied, .confirmed, .declined, .selected, .replied, .acknowledged, .reported: .answered
        }
    }

    /// True when any business-authored enrichment is present (a server push must never set this).
    public var isEnriched: Bool { title != nil || detail != nil || options != nil }

    /// The same state with every business-authored field removed: what a server push may carry.
    public var neutral: DecisionActivityState {
        DecisionActivityState(interactionId: interactionId, kind: kind, expiresAt: expiresAt, stage: stage)
    }

    private enum CodingKeys: String, CodingKey { case interactionId, kind, expiresAt, stage, title, detail, options }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        interactionId = try c.decode(InteractionID.self, forKey: .interactionId)
        kind = try c.decode(Kind.self, forKey: .kind)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        stage = try c.decode(Stage.self, forKey: .stage)
        title = try c.decodeIfPresent(String.self, forKey: .title)
        detail = try c.decodeIfPresent(String.self, forKey: .detail)
        // Bounded however it was produced.
        options = try c.decodeIfPresent([Option].self, forKey: .options).map { Array($0.prefix(Self.maxOptions)) }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(interactionId, forKey: .interactionId)
        try c.encode(kind, forKey: .kind)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encode(stage, forKey: .stage)
        // Absent (not `null`) when not enriched, so a neutral server state has no text keys at all.
        try c.encodeIfPresent(title, forKey: .title)
        try c.encodeIfPresent(detail, forKey: .detail)
        try c.encodeIfPresent(options, forKey: .options)
    }
}

/// Live Activity content state. Wire: `{"type":"delivery","delivery":{…}}`.
/// Suitable as an ActivityKit `ContentState` (Codable & Hashable).
public enum LiveActivityStatus: Codable, Sendable, Hashable {
    case order(OrderActivityState)
    case delivery(DeliveryActivityState)
    case flight(FlightActivityState)
    case appointment(AppointmentActivityState)
    /// A pending `confirm` / `choose` decision (server pushes carry only the neutral fields; see `DecisionActivityState`).
    /// Never accepted from a business status update (`InteractionValidation`, `LiveActivityPolicy.isEligible`).
    case decision(DecisionActivityState)

    private enum CodingKeys: String, CodingKey { case type, order, delivery, flight, appointment, decision }

    /// Type discriminator.
    public var type: String {
        switch self {
        case .order: "order"
        case .delivery: "delivery"
        case .flight: "flight"
        case .appointment: "appointment"
        case .decision: "decision"
        }
    }

    /// True for the decision case (driven by Viadere for a `confirm`/`choose` interaction, never by a business status).
    public var isDecision: Bool {
        if case .decision = self { return true }
        return false
    }

    /// True when the activity should end (completed, delivered, landed, cancelled…).
    public var isTerminal: Bool {
        switch self {
        case .order(let s): s.stage == .completed || s.stage == .cancelled
        case .delivery(let s): s.stage == .delivered
        case .flight(let s): s.stage == .landed || s.stage == .cancelled || s.stage == .diverted
        case .appointment(let s): s.stage == .completed || s.stage == .cancelled
        case .decision(let s): s.stage != .pending
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "order": self = .order(try c.decode(OrderActivityState.self, forKey: .order))
        case "delivery": self = .delivery(try c.decode(DeliveryActivityState.self, forKey: .delivery))
        case "flight": self = .flight(try c.decode(FlightActivityState.self, forKey: .flight))
        case "appointment": self = .appointment(try c.decode(AppointmentActivityState.self, forKey: .appointment))
        case "decision": self = .decision(try c.decode(DecisionActivityState.self, forKey: .decision))
        default: throw DecodingError.dataCorruptedError(forKey: .type, in: c, debugDescription: "Unknown live activity type")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(type, forKey: .type)
        switch self {
        case .order(let s): try c.encode(s, forKey: .order)
        case .delivery(let s): try c.encode(s, forKey: .delivery)
        case .flight(let s): try c.encode(s, forKey: .flight)
        case .appointment(let s): try c.encode(s, forKey: .appointment)
        case .decision(let s): try c.encode(s, forKey: .decision)
        }
    }
}

/// Live Activity eligibility (spec §8, §19 #6): only genuinely ongoing, non-promotional events.
public enum LiveActivityPolicy {
    /// Purposes allowed to drive a Live Activity.
    public static let eligiblePurposes: Set<InteractionPurpose> = [.transactional, .accountService, .support]

    /// Whether a status update may start/update a Live Activity. A business status can never carry a decision activity: that case is
    /// produced only by Viadere itself for an eligible `confirm`/`choose` (`isDecisionEligible`).
    public static func isEligible(purpose: InteractionPurpose, status: LiveActivityStatus?) -> Bool {
        // Terminal updates are still eligible so an existing activity can be ended.
        guard let status, !status.isDecision else { return false }
        return eligiblePurposes.contains(purpose)
    }

    /// Most options a `choose` may have to be answered from the Lock Screen.
    public static let maxInlineOptions = DecisionActivityState.maxOptions

    /// Whether an issued interaction may get a decision Live Activity with Lock Screen buttons (docs/SECURITY.md §2.16).
    ///
    /// All of: a live key; kind `confirm`, or `choose` with a single answer and at most `maxInlineOptions` options; an ongoing,
    /// non-promotional purpose (`eligiblePurposes`: never marketing, rewards or security); native push allowed; and a rendering the
    /// notification renderer would **not** mark secure (`ChannelRenderer.requiresSecureFlow`: no step-up, Face ID or passcode). Sign-in,
    /// approval and unknown kinds never qualify. A `choose` that does not fit inline gets no Live Activity at all (its notification and
    /// the app stay the way to answer it).
    public static func isDecisionEligible(_ interaction: Interaction, livemode: Bool) -> Bool {
        guard livemode, eligiblePurposes.contains(interaction.purpose), interaction.allowedChannels.contains(.nativePush),
              !ChannelRenderer.requiresSecureFlow(interaction) else { return false }
        switch (interaction.kind, interaction.payload) {
        case (.confirm, .confirm):
            return true
        case (.choose, .choose(let p)):
            return !p.allowsMultiple && !p.options.isEmpty && p.options.count <= maxInlineOptions
        default:
            return false
        }
    }

    /// The neutral, text-free decision state the server sends to start an activity for an eligible interaction (`nil` otherwise).
    public static func neutralDecisionState(for interaction: Interaction, livemode: Bool) -> DecisionActivityState? {
        guard isDecisionEligible(interaction, livemode: livemode) else { return nil }
        let kind: DecisionActivityState.Kind = interaction.kind == .confirm ? .confirm : .choose
        return DecisionActivityState(interactionId: interaction.id, kind: kind, expiresAt: interaction.expiresAt, stage: .pending)
    }
}
