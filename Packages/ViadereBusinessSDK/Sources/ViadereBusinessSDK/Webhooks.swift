import Foundation
import ViadereCore

/// Verifies Viadere webhook deliveries (`Viadere-Signature: t={unix},v1={hex HMAC-SHA256("{t}." + rawBody)}`).
///
/// Use the **raw request body bytes** exactly as received — never a re-serialized JSON value. Reject the request (and do
/// not process the event) when `verify` throws.
///
/// ```swift
/// let verifier = WebhookVerifier(secrets: [currentSecret, previousSecretDuringRotation])
/// let event = try verifier.verify(headers: request.headers, body: rawBody)
/// ```
public struct WebhookVerifier: Sendable {
    public static let signatureHeader = ViadereHeader.signature
    public static let eventIdHeader = ViadereHeader.eventId
    public static let eventTypeHeader = ViadereHeader.eventType

    private let secrets: [String]
    private let tolerance: TimeInterval
    private let clock: @Sendable () -> Date

    /// - Parameters:
    ///   - secrets: the endpoint's `whsec_…` secret; pass the old one too during a rotation (any match is accepted).
    ///   - tolerance: allowed clock difference in seconds (default 300, the protocol maximum).
    public init(secrets: [String], tolerance: TimeInterval = WebhookSignature.defaultTolerance, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.secrets = secrets
        self.tolerance = min(max(tolerance, 1), WebhookSignature.defaultTolerance)
        self.clock = clock
    }

    public init(secret: String, tolerance: TimeInterval = WebhookSignature.defaultTolerance, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.init(secrets: [secret], tolerance: tolerance, clock: clock)
    }

    /// Verifies the signature and returns the decoded event. Header names are matched case-insensitively.
    @discardableResult
    public func verify(headers: [String: String], body: Data, deduplicator: (any WebhookEventDeduplicator)? = nil) throws -> WebhookEvent {
        func header(_ name: String) -> String? { headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
        guard let signature = header(Self.signatureHeader) else { throw WebhookVerificationError.missingSignatureHeader }
        do {
            try WebhookSignature.verify(header: signature, body: body, secrets: secrets, now: clock(), tolerance: tolerance)
        } catch let error as WebhookSignature.Error {
            switch error {
            case .malformedHeader: throw WebhookVerificationError.malformedSignature
            case .timestampOutsideTolerance: throw WebhookVerificationError.timestampOutsideTolerance
            case .noMatchingSignature: throw WebhookVerificationError.noMatchingSignature
            }
        }
        guard let event = try? ViadereJSON.decode(WebhookEvent.self, from: body) else { throw WebhookVerificationError.malformedBody }
        // The convenience headers must agree with the signed body (they are not signed themselves).
        if let id = header(Self.eventIdHeader), id.lowercased() != event.id.description.lowercased() { throw WebhookVerificationError.headerBodyMismatch }
        if let type = header(Self.eventTypeHeader), type != event.type.rawValue { throw WebhookVerificationError.headerBodyMismatch }
        if let deduplicator, !deduplicator.markProcessing(eventId: event.id.description) { throw WebhookVerificationError.duplicateEvent }
        return event
    }
}

/// Deliveries are at-least-once: the same event id can arrive again after a timeout. Record ids you have processed.
public protocol WebhookEventDeduplicator: Sendable {
    /// Returns `true` the first time an id is seen, `false` for a repeat.
    func markProcessing(eventId: String) -> Bool
}

/// A bounded in-memory deduplicator for a single process. Use a shared store (database unique key) when you run several instances.
public final class InMemoryWebhookDeduplicator: WebhookEventDeduplicator, @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [String] = []
    private var set = Set<String>()
    private let capacity: Int

    public init(capacity: Int = 10_000) { self.capacity = max(1, capacity) }

    public func markProcessing(eventId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard set.insert(eventId).inserted else { return false }
        seen.append(eventId)
        if seen.count > capacity { set.remove(seen.removeFirst()) }
        return true
    }
}

// MARK: - Typed payloads

/// `message.received` — a customer's message forwarded to you.
public struct MessageReceivedEvent: Codable, Sendable, Equatable {
    public var sessionId: SessionID
    public var relationshipId: RelationshipID
    /// The customer's pairwise reference: the same value at every call, and unrelated to the same customer's reference at any other business.
    public var subjectRef: SubjectRef?
    public var messageId: MessageID
    public var text: String
    public var channel: Channel
    public var receivedAt: Date
}

/// `relationship.connected` / `relationship.disconnected`.
public struct RelationshipEvent: Codable, Sendable, Equatable {
    public var relationshipId: RelationshipID
    public var subjectRef: SubjectRef?
    public var source: ConnectSource?
    public var occurredAt: Date
}

/// `consent.updated`.
public struct ConsentUpdatedEvent: Codable, Sendable, Equatable {
    public var relationshipId: RelationshipID
    public var subjectRef: SubjectRef?
    public var purpose: InteractionPurpose
    public var granted: Bool
    public var occurredAt: Date
}

/// A decoded event. Unknown types (Viadere may add more) arrive as `.other` — acknowledge them with `2xx` and ignore them.
public enum TypedWebhookEvent: Sendable, Equatable {
    case interactionDecided(InteractionOutcome)
    case interactionExpired(InteractionOutcome)
    case interactionCancelled(InteractionOutcome)
    case messageReceived(MessageReceivedEvent)
    case relationshipConnected(RelationshipEvent)
    case relationshipDisconnected(RelationshipEvent)
    case consentUpdated(ConsentUpdatedEvent)
    case other(type: WebhookEventType, data: JSONValue)
}

extension WebhookEvent {
    /// Decodes `data` according to `type`.
    public func typed() throws -> TypedWebhookEvent {
        do {
            switch type {
            case .interactionDecided: return .interactionDecided(try decodeData(InteractionOutcome.self))
            case .interactionExpired: return .interactionExpired(try decodeData(InteractionOutcome.self))
            case .interactionCancelled: return .interactionCancelled(try decodeData(InteractionOutcome.self))
            case .messageReceived: return .messageReceived(try decodeData(MessageReceivedEvent.self))
            case .relationshipConnected: return .relationshipConnected(try decodeData(RelationshipEvent.self))
            case .relationshipDisconnected: return .relationshipDisconnected(try decodeData(RelationshipEvent.self))
            case .consentUpdated: return .consentUpdated(try decodeData(ConsentUpdatedEvent.self))
            default: return .other(type: type, data: data)
            }
        } catch {
            throw WebhookVerificationError.malformedBody
        }
    }
}
