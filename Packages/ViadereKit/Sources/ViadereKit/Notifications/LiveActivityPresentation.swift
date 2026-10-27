import Foundation
import ViadereCore

/// What a Live Activity / Dynamic Island shows for each `LiveActivityStatus`, as plain data. The widget extension
/// only lays it out; the wording is unit-tested here.
public struct LiveActivityPresentation: Equatable, Sendable {
    public var headline: String
    public var detail: String
    /// One short token for the compact Dynamic Island ("B12", "Ready", "3 stops").
    public var compact: String
    /// 0...1 progress through the lifecycle, if it has one.
    public var progress: Double?
    public var symbol: String
    /// A moment to show as a time/countdown (ETA, departure, start).
    public var target: Date?
    public var isAlert: Bool

    public init(status: LiveActivityStatus, businessName: String) {
        switch status {
        case .order(let s):
            headline = "Order \(s.orderReference)"
            symbol = "bag"
            target = s.estimatedReadyAt
            isAlert = s.stage == .cancelled
            switch s.stage {
            case .placed: detail = "Order placed"; compact = "Placed"; progress = 0.2
            case .preparing: detail = "Being prepared"; compact = "Prep"; progress = 0.55
            case .ready: detail = "Ready for pickup"; compact = "Ready"; progress = 0.9
            case .completed: detail = "Completed"; compact = "Done"; progress = 1
            case .cancelled: detail = "Cancelled"; compact = "Off"; progress = nil
            }
            if let note = s.note { detail += " · \(note)" }
        case .delivery(let s):
            headline = s.carrierName.map { "\($0) delivery" } ?? "Delivery"
            symbol = "shippingbox"
            target = s.estimatedDeliveryAt
            isAlert = s.stage == .exception
            switch s.stage {
            case .labelCreated: detail = "Label created"; compact = "Soon"; progress = 0.1
            case .inTransit: detail = "In transit"; compact = "On way"; progress = 0.5
            case .outForDelivery:
                detail = "Out for delivery"
                compact = "Today"
                progress = 0.8
                if let stops = s.stopsAway {
                    detail += stops == 0 ? " · arriving now" : " · \(stops) \(stops == 1 ? "stop" : "stops") away"
                    compact = stops == 0 ? "Now" : "\(stops) stops"
                }
            case .delivered: detail = "Delivered"; compact = "Done"; progress = 1
            case .exception: detail = "Delivery problem"; compact = "Issue"; progress = nil
            }
        case .flight(let s):
            headline = "\(s.flightNumber) · \(s.departureAirport) to \(s.arrivalAirport)"
            symbol = "airplane"
            target = s.estimatedDeparture ?? s.scheduledDeparture
            isAlert = s.stage == .delayed || s.stage == .cancelled || s.stage == .diverted
            switch s.stage {
            case .scheduled: detail = "On time"; progress = 0.05
            case .delayed: detail = "Delayed"; progress = 0.05
            case .boarding: detail = "Boarding"; progress = 0.3
            case .departed: detail = "In the air"; progress = 0.6
            case .landed: detail = "Landed"; progress = 1
            case .cancelled: detail = "Cancelled"; progress = nil
            case .diverted: detail = "Diverted"; progress = nil
            }
            if let gate = s.gate, s.stage == .scheduled || s.stage == .delayed || s.stage == .boarding { detail += " · Gate \(gate)" }
            compact = s.gate.flatMap { s.stage == .boarding || s.stage == .scheduled ? $0 : nil } ?? String(detail.split(separator: " ").first ?? "")
        case .appointment(let s):
            headline = s.title
            symbol = "calendar"
            target = s.startsAt
            isAlert = s.stage == .cancelled
            switch s.stage {
            case .upcoming: detail = "Upcoming"; compact = "Soon"; progress = 0.1
            case .checkInOpen: detail = "Check-in is open"; compact = "Check in"; progress = 0.4
            case .checkedIn: detail = "You're checked in"; compact = "In"; progress = 0.6
            case .inProgress: detail = "In progress"; compact = "Now"; progress = 0.8
            case .completed: detail = "Completed"; compact = "Done"; progress = 1
            case .cancelled: detail = "Cancelled"; compact = "Off"; progress = nil
            }
            if let provider = s.providerName ?? Optional(businessName), s.stage != .completed { detail += " · \(provider)" }
        }
    }
}
