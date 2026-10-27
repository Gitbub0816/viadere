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
    /// What happens next, in a few words ("We'll tell you when it's ready"). Shown in the expanded Dynamic Island
    /// and on the Lock Screen. `nil` when the activity is finished.
    public var nextStep: String?
    /// What the compact trailing slot and the expanded trailing region show.
    public var trailing: Trailing

    /// The right-hand slot: a live countdown when the moment is close, otherwise a short status word.
    public enum Trailing: Equatable, Sendable {
        /// Count down to this moment (`Text(timerInterval:)`).
        case countdown(to: Date)
        case text(String)
    }

    /// A countdown is only worth showing inside this window; farther out, a status word is calmer.
    public static let countdownWindow: TimeInterval = 99 * 60

    public init(status: LiveActivityStatus, businessName rawBusinessName: String, now: Date = Date()) {
        let businessName = UntrustedText.name(rawBusinessName, max: 40, attribution: nil).text
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
        // Business-supplied references, notes and names were interpolated above: sanitize the finished strings.
        // The stage word always comes first in `detail`, so a long note is what gets cut.
        headline = UntrustedText.line(headline, max: 60)
        detail = UntrustedText.line(detail, max: 100)
        compact = UntrustedText.line(compact, max: 16)
        nextStep = Self.nextStep(for: status)
        if let target, !status.isTerminal, !isAlert, target.timeIntervalSince(now) > 0, target.timeIntervalSince(now) <= Self.countdownWindow {
            trailing = .countdown(to: target)
        } else {
            trailing = .text(compact)
        }
    }

    /// The next step, in the business's voice-free, calm wording. `nil` once the activity has ended.
    static func nextStep(for status: LiveActivityStatus) -> String? {
        if status.isTerminal { return nil }
        switch status {
        case .order(let s):
            switch s.stage {
            case .placed: return "Next: they start preparing it"
            case .preparing: return "Next: we'll tell you when it's ready"
            case .ready: return "Next: pick it up at the counter"
            case .completed, .cancelled: return nil
            }
        case .delivery(let s):
            switch s.stage {
            case .labelCreated: return "Next: the carrier collects it"
            case .inTransit: return "Next: out for delivery"
            case .outForDelivery: return "Next: watch for the driver"
            case .exception: return "Next: check with the business"
            case .delivered: return nil
            }
        case .flight(let s):
            switch s.stage {
            case .scheduled: return "Next: boarding opens at the gate"
            case .delayed: return "Next: watch for a new gate time"
            case .boarding: return "Next: head to the gate"
            case .departed: return "Next: arrival"
            case .landed, .cancelled, .diverted: return nil
            }
        case .appointment(let s):
            switch s.stage {
            case .upcoming: return "Next: check-in opens before your visit"
            case .checkInOpen: return "Next: check in when you arrive"
            case .checkedIn: return "Next: you'll be called in"
            case .inProgress: return "Next: we'll follow up afterwards"
            case .completed, .cancelled: return nil
            }
        }
    }
}
