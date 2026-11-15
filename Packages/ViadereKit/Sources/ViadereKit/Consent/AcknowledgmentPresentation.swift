import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Copy and structure for the `acknowledge` flow. An acknowledgment records that the person read a document and when.
/// It is **not** a legal e-signature, and the copy never says or implies it is.
public enum AcknowledgmentPresentation {
    /// Shown on every acknowledgment screen.
    public static let disclaimer = "Acknowledging records that you read this and when. It isn't a legal signature and doesn't replace any agreement with the business."

    public static let recordNote = "Viadere keeps this record with the document version, so you and the business can see what was shown."

    /// The first lines of the body as a summary (full text stays one tap away).
    public static func summary(_ payload: AcknowledgePayload, limit: Int = 220) -> String {
        let text = UntrustedText.paragraphs(payload.body, max: 20_000)
        guard text.count > limit else { return text }
        let cut = text.prefix(limit)
        if let stop = cut.lastIndex(where: { $0 == "." || $0 == "!" || $0 == "?" }), cut.distance(from: cut.startIndex, to: stop) > limit / 2 {
            return String(cut[...stop])
        }
        return String(cut).trimmingCharacters(in: .whitespaces) + "…"
    }

    public static func isTruncated(_ payload: AcknowledgePayload, limit: Int = 220) -> Bool {
        UntrustedText.paragraphs(payload.body, max: 20_000).count > limit
    }

    public static func versionLabel(_ payload: AcknowledgePayload) -> String? {
        UntrustedText.optionalLine(payload.documentVersion, max: 20).map { "Version \($0)" }
    }

    /// The full document text, sanitized (paragraph breaks kept, no bidi/zero-width/control characters).
    public static func body(_ payload: AcknowledgePayload) -> String { UntrustedText.paragraphs(payload.body, max: 20_000) }
    public static func title(_ payload: AcknowledgePayload) -> String { UntrustedText.line(payload.title, max: InteractionPresentation.Limit.title) }

    /// Only `https` documents open; anything else is ignored rather than handed to the system.
    public static func documentURL(_ payload: AcknowledgePayload) -> URL? {
        guard let url = payload.documentURL, url.scheme?.lowercased() == "https", url.host?.isEmpty == false else { return nil }
        return url
    }

    /// Facts shown before acknowledging.
    public static func documentRows(_ envelope: InteractionEnvelope, payload: AcknowledgePayload, now: Date) -> [PresentedDetail] {
        var rows = [PresentedDetail(label: "From", value: UntrustedText.name(envelope.business.displayName).text), PresentedDetail(label: "Document", value: title(payload))]
        if let version = UntrustedText.optionalLine(payload.documentVersion, max: 20) { rows.append(PresentedDetail(label: "Version", value: version)) }
        if let account = UntrustedText.optionalLine(envelope.interaction.scope.accountReference, max: 40) { rows.append(PresentedDetail(label: "Account", value: account)) }
        rows.append(PresentedDetail(label: "Sent", value: InteractionPresentation.relative(envelope.interaction.createdAt, now: now)))
        return rows
    }

    /// The receipt shown after deciding. The timestamp is the server's `decidedAt`; the device clock is a fallback only
    /// when the server omitted it.
    public static func receiptRows(_ envelope: InteractionEnvelope, payload: AcknowledgePayload, outcome: InteractionOutcome?,
                                   fallback: Date, timeZone: TimeZone = .current) -> [PresentedDetail] {
        var rows = [PresentedDetail(label: "Document", value: title(payload))]
        if let version = UntrustedText.optionalLine(payload.documentVersion, max: 20) { rows.append(PresentedDetail(label: "Version", value: version)) }
        rows.append(PresentedDetail(label: "Business", value: UntrustedText.name(envelope.business.displayName).text))
        let recorded = outcome?.decidedAt ?? fallback
        rows.append(PresentedDetail(label: "Recorded", value: timestamp(recorded, timeZone: timeZone), emphasized: true))
        rows.append(PresentedDetail(label: "Reference", value: reference(envelope.id)))
        return rows
    }

    public static func timestamp(_ date: Date, timeZone: TimeZone = .current) -> String {
        var style = Date.FormatStyle(date: .abbreviated, time: .standard)
        style.timeZone = timeZone
        return date.formatted(style)
    }

    /// A short, stable reference ("VD-3F9A21C4") for support conversations.
    public static func reference(_ id: InteractionID) -> String {
        "VD-" + id.description.replacingOccurrences(of: "-", with: "").prefix(8).uppercased()
    }

    public static func resultTitle(acknowledged: Bool) -> String { acknowledged ? "Acknowledged" : "Declined" }

    public static func resultMessage(acknowledged: Bool, business: String) -> String {
        acknowledged ? "We recorded that you read this and let \(business) know." : "We let \(business) know you declined."
    }
}

/// Settings → Acknowledgments: the server's records of what the person acknowledged or declined.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AcknowledgmentsViewModel {
    public enum Phase: Equatable, Sendable { case idle, loading, loaded, unavailable, failed(String) }

    public private(set) var records: [AcknowledgmentRecord] = []
    public private(set) var phase: Phase = .idle
    private let services: ViadereServices

    public init(services: ViadereServices) { self.services = services }

    public func load() async {
        if records.isEmpty { phase = .loading }
        do {
            records = try await services.api.acknowledgments().sorted { $0.recordedAt > $1.recordedAt }
            phase = .loaded
        } catch let error as APIError {
            phase = error.code == .notFound ? .unavailable : .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    public func subtitle(_ record: AcknowledgmentRecord) -> String {
        var parts = [record.acknowledged ? "Acknowledged" : "Declined"]
        if let version = record.documentVersion { parts.append("v\(version)") }
        parts.append(AcknowledgmentPresentation.timestamp(record.recordedAt))
        return parts.joined(separator: " · ")
    }
}
