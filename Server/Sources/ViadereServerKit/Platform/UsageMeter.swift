import Fluent
import Foundation
import ViadereCore

/// Metering: what each business consumed, never what it paid. Platform fee basis (`interaction`) is kept apart
/// from carrier/provider transport (`sms_segment`, `rcs_message`). Events are idempotent on `(meter, ref)`.
enum UsageMeter {
    enum Meter: String, CaseIterable {
        case interaction
        case smsSegment = "sms_segment"
        case rcsMessage = "rcs_message"

        var category: String { self == .interaction ? "platform" : "transport" }
        var title: String {
            switch self {
            case .interaction: "Interactions issued"
            case .smsSegment: "SMS segments"
            case .rcsMessage: "RCS messages"
            }
        }
    }

    /// Records usage. A repeated `(meter, ref)` is ignored, so retries never double count.
    static func record(_ meter: Meter, businessId: UUID, quantity: Int = 1, livemode: Bool, ref: String, at: Date,
                       on db: any Database) async throws {
        guard quantity > 0 else { return }
        // Pre-check so a duplicate never aborts a surrounding PostgreSQL transaction; the unique index still
        // decides any race.
        if try await UsageEventRecord.query(on: db).filter(\.$meter == meter.rawValue).filter(\.$ref == String(ref.prefix(100))).count() > 0 { return }
        let event = UsageEventRecord()
        event.id = UUID()
        event.businessId = businessId
        event.meter = meter.rawValue
        event.category = meter.category
        event.quantity = quantity
        event.livemode = livemode
        event.ref = String(ref.prefix(100))
        event.occurredAt = at
        do {
                        try await event.create(on: db)
        } catch {
            if error.isConstraintViolation { return }
            throw error
        }
    }

    struct Totals: Equatable {
        var interactions = 0
        var smsSegments = 0
        var rcsMessages = 0
    }

    /// Live usage in `[from, to)`.
    static func totals(businessId: UUID, from: Date, to: Date, on db: any Database) async throws -> Totals {
        let events = try await UsageEventRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$livemode == true)
            .filter(\.$occurredAt >= from).filter(\.$occurredAt < to).all()
        var out = Totals()
        for event in events {
            switch Meter(rawValue: event.meter) {
            case .interaction: out.interactions += event.quantity
            case .smsSegment: out.smsSegments += event.quantity
            case .rcsMessage: out.rcsMessages += event.quantity
            case nil: break
            }
        }
        return out
    }
}

/// An invoice *preview*: no payment processor, no tax, no commitment. Platform fees and transport are separate
/// sections so transport pass-through is never presented as a Viadere fee.
struct InvoicePreview: Equatable {
    struct Line: Equatable {
        var title: String
        var quantity: Int
        /// Micro-USD per unit (0 = not configured).
        var unitMicros: Int
        var totalMicros: Int
        var note: String?
    }

    var periodStart: Date
    var periodEnd: Date
    var platform: [Line]
    var transport: [Line]
    var platformTotalMicros: Int { platform.reduce(0) { $0 + $1.totalMicros } }
    var transportTotalMicros: Int { transport.reduce(0) { $0 + $1.totalMicros } }
    var totalMicros: Int { platformTotalMicros + transportTotalMicros }

    static func make(totals: UsageMeter.Totals, rates: BillingRates, from: Date, to: Date) -> InvoicePreview {
        let billable = max(0, totals.interactions - rates.includedInteractionsPerMonth)
        let platform = Line(title: "Interactions beyond included", quantity: billable, unitMicros: rates.platformMicrosPerInteraction,
                            totalMicros: billable * rates.platformMicrosPerInteraction,
                            note: "\(min(totals.interactions, rates.includedInteractionsPerMonth)) of \(rates.includedInteractionsPerMonth) included interactions used")
        let sms = Line(title: "SMS segments (carrier pass-through)", quantity: totals.smsSegments, unitMicros: rates.transportMicrosPerSMSSegment,
                       totalMicros: totals.smsSegments * rates.transportMicrosPerSMSSegment,
                       note: rates.transportMicrosPerSMSSegment == 0 ? "Rate not configured" : nil)
        let rcs = Line(title: "RCS messages (provider pass-through)", quantity: totals.rcsMessages, unitMicros: rates.transportMicrosPerRCSMessage,
                       totalMicros: totals.rcsMessages * rates.transportMicrosPerRCSMessage,
                       note: rates.transportMicrosPerRCSMessage == 0 ? "Rate not configured" : nil)
        return InvoicePreview(periodStart: from, periodEnd: to, platform: [platform], transport: [sms, rcs])
    }

    /// `1234567` → `$1.234567`, trimmed to at least 2 decimals.
    static func format(micros: Int) -> String {
        let dollars = micros / 1_000_000
        var fraction = String(format: "%06d", abs(micros % 1_000_000))
        while fraction.count > 2, fraction.hasSuffix("0") { fraction.removeLast() }
        return "$\(dollars).\(fraction)"
    }
}
