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

/// Live Activity content state. Wire: `{"type":"delivery","delivery":{…}}`.
/// Suitable as an ActivityKit `ContentState` (Codable & Hashable).
public enum LiveActivityStatus: Codable, Sendable, Hashable {
    case order(OrderActivityState)
    case delivery(DeliveryActivityState)
    case flight(FlightActivityState)
    case appointment(AppointmentActivityState)

    private enum CodingKeys: String, CodingKey { case type, order, delivery, flight, appointment }

    /// Type discriminator.
    public var type: String {
        switch self {
        case .order: "order"
        case .delivery: "delivery"
        case .flight: "flight"
        case .appointment: "appointment"
        }
    }

    /// True when the activity should end (completed, delivered, landed, cancelled…).
    public var isTerminal: Bool {
        switch self {
        case .order(let s): s.stage == .completed || s.stage == .cancelled
        case .delivery(let s): s.stage == .delivered
        case .flight(let s): s.stage == .landed || s.stage == .cancelled || s.stage == .diverted
        case .appointment(let s): s.stage == .completed || s.stage == .cancelled
        }
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "order": self = .order(try c.decode(OrderActivityState.self, forKey: .order))
        case "delivery": self = .delivery(try c.decode(DeliveryActivityState.self, forKey: .delivery))
        case "flight": self = .flight(try c.decode(FlightActivityState.self, forKey: .flight))
        case "appointment": self = .appointment(try c.decode(AppointmentActivityState.self, forKey: .appointment))
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
        }
    }
}

/// Live Activity eligibility (spec §8, §19 #6): only genuinely ongoing, non-promotional events.
public enum LiveActivityPolicy {
    /// Purposes allowed to drive a Live Activity.
    public static let eligiblePurposes: Set<InteractionPurpose> = [.transactional, .accountService, .support]

    /// Whether a status update may start/update a Live Activity.
    public static func isEligible(purpose: InteractionPurpose, status: LiveActivityStatus?) -> Bool {
        // Terminal updates are still eligible so an existing activity can be ended.
        guard status != nil else { return false }
        return eligiblePurposes.contains(purpose)
    }
}
