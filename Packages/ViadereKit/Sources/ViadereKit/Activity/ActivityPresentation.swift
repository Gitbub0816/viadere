import Foundation
import ViadereCore

/// Copy for Activity rows and the detail screen. Pure and testable; views only lay it out.
public enum ActivityPresentation {
    static func format(_ date: Date, date dateStyle: Date.FormatStyle.DateStyle, time timeStyle: Date.FormatStyle.TimeStyle, zone: TimeZone) -> String {
        var style = Date.FormatStyle(date: dateStyle, time: timeStyle)
        style.timeZone = zone
        return date.formatted(style)
    }

    /// "Today 4:30 PM", "Tomorrow", "Fri, Oct 30": calm, relative where it helps.
    public static func whenText(_ date: Date, now: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let time = format(date, date: .omitted, time: .shortened, zone: timeZone)
        if calendar.isDate(date, inSameDayAs: now) { return "Today \(time)" }
        if let tomorrow = calendar.date(byAdding: .day, value: 1, to: now), calendar.isDate(date, inSameDayAs: tomorrow) { return "Tomorrow \(time)" }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(date, inSameDayAs: yesterday) { return "Yesterday" }
        return format(date, date: .abbreviated, time: .omitted, zone: timeZone)
    }

    /// One calm subtitle line for a row: "Being prepared · Today 4:38 PM".
    public static func rowSubtitle(_ item: ActivityItem, now: Date, timeZone: TimeZone = .current) -> String {
        var parts: [String] = []
        if let status = item.statusText { parts.append(status) }
        switch item.phase {
        case .past: break
        default:
            if item.category == .event || item.category == .reservation || item.category == .appointment || item.phase == .upcoming {
                parts.append(whenText(item.date, now: now, timeZone: timeZone))
            }
        }
        if parts.isEmpty, let subtitle = item.subtitle { parts.append(subtitle) }
        return parts.joined(separator: " · ")
    }

    /// Facts for the detail screen, specific to what the item is.
    public static func details(_ item: ActivityItem, now: Date, timeZone: TimeZone = .current) -> [PresentedDetail] {
        var rows: [PresentedDetail] = []
        func time(_ date: Date) -> String { format(date, date: .abbreviated, time: .shortened, zone: timeZone) }
        if let live = item.live {
            switch live {
            case .order(let s):
                rows.append(PresentedDetail(label: "Order", value: s.orderReference))
                if let ready = s.estimatedReadyAt { rows.append(PresentedDetail(label: "Estimated ready", value: time(ready), emphasized: true)) }
                if let note = s.note { rows.append(PresentedDetail(label: "Note", value: note)) }
            case .delivery(let s):
                rows.append(PresentedDetail(label: "Tracking", value: s.trackingReference))
                if let carrier = s.carrierName { rows.append(PresentedDetail(label: "Carrier", value: carrier)) }
                if let eta = s.estimatedDeliveryAt { rows.append(PresentedDetail(label: "Estimated delivery", value: time(eta), emphasized: true)) }
                if let stops = s.stopsAway { rows.append(PresentedDetail(label: "Stops away", value: stops == 0 ? "Arriving now" : String(stops))) }
            case .flight(let s):
                rows.append(PresentedDetail(label: "Flight", value: s.flightNumber))
                rows.append(PresentedDetail(label: "Route", value: "\(s.departureAirport) to \(s.arrivalAirport)"))
                rows.append(PresentedDetail(label: "Scheduled", value: time(s.scheduledDeparture)))
                if let estimate = s.estimatedDeparture, estimate != s.scheduledDeparture {
                    rows.append(PresentedDetail(label: "Now departing", value: time(estimate), emphasized: true))
                }
                if let gate = s.gate { rows.append(PresentedDetail(label: "Gate", value: gate)) }
                if let seat = s.seat { rows.append(PresentedDetail(label: "Seat", value: seat)) }
            case .appointment(let s):
                rows.append(PresentedDetail(label: "When", value: time(s.startsAt), emphasized: true))
                if let provider = s.providerName { rows.append(PresentedDetail(label: "With", value: provider)) }
                if let location = s.location { rows.append(PresentedDetail(label: "Where", value: location)) }
            case .decision:
                break
            }
        }
        // Tickets and confirmations that ride along with the item.
        for envelope in [item.latest] where item.live == nil {
            switch envelope.interaction.payload {
            case .ticket(let t):
                if let holder = t.holderName { rows.append(PresentedDetail(label: "Holder", value: holder)) }
                if let from = t.validFrom { rows.append(PresentedDetail(label: item.category == .reservation ? "Check-in" : "Starts", value: time(from), emphasized: true)) }
                if let until = t.validUntil { rows.append(PresentedDetail(label: item.category == .reservation ? "Check-out" : "Ends", value: time(until))) }
            case .confirm(let c):
                if let reference = c.reference { rows.append(PresentedDetail(label: "Reference", value: reference)) }
                if let at = c.scheduledAt { rows.append(PresentedDetail(label: "When", value: time(at), emphasized: true)) }
            default: break
            }
        }
        // Business-supplied references, notes and names: single-line and bounded.
        return rows.map { row in
            var copy = row
            copy.value = UntrustedText.line(row.value, max: 100)
            return copy
        }
    }

    /// Shown when an item's actions open the secure approval screen.
    public static let secureSheetNote = "Rebooking can change what you pay or who is travelling, so it opens in the secure approval screen."

    public static func needsSecureNote(_ item: ActivityItem) -> Bool {
        item.actions.contains { $0.route == .secureSheet } && (item.category == .travel || item.category == .reservation)
    }

    public static let emptyTitle = "Nothing in progress"
    public static let emptyMessage = "Orders, deliveries, appointments, trips and tickets from your businesses appear here, grouped by business."
}
