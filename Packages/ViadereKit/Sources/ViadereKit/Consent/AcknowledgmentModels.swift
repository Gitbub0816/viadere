import Foundation
import ViadereCore

/// The server's durable record of an acknowledgment, listed under Settings → Acknowledgments.
public struct AcknowledgmentRecord: Codable, Sendable, Hashable, Identifiable {
    public var id: InteractionID
    public var business: BusinessSummary
    public var title: String
    public var documentVersion: String?
    /// SHA-256 (hex) of the document the person saw, when the business supplied one.
    public var documentDigest: String?
    /// `acknowledged` or `declined`.
    public var acknowledged: Bool
    /// Server time. The record's timestamp is the server's, never the device clock.
    public var recordedAt: Date
    public var channel: Channel?

    public init(id: InteractionID, business: BusinessSummary, title: String, documentVersion: String? = nil,
                documentDigest: String? = nil, acknowledged: Bool, recordedAt: Date, channel: Channel? = .inApp) {
        self.id = id
        self.business = business
        self.title = title
        self.documentVersion = documentVersion
        self.documentDigest = documentDigest
        self.acknowledged = acknowledged
        self.recordedAt = recordedAt
        self.channel = channel
    }
}
