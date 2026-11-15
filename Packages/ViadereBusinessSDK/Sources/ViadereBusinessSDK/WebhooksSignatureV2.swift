import Foundation
import ViadereCore

/// A durable record of processed webhook event ids (ADR-0025 section 2 rule 4, fixes F-22). Keep an id for `WebhookRetrySchedule.dedupHorizon` (the retry
/// horizon plus 300 s) **measured from first receipt**; the documented minimum is 72 h. Implement it with an atomic insert on a unique key, for example:
///
/// ```sql
/// CREATE TABLE viadere_webhook_events (event_id TEXT PRIMARY KEY, first_seen TIMESTAMPTZ NOT NULL);
/// INSERT INTO viadere_webhook_events (event_id, first_seen) VALUES ($1, now()) ON CONFLICT DO NOTHING; -- 1 row = first time
/// DELETE FROM viadere_webhook_events WHERE first_seen < now() - interval '72 hours';
/// ```
public protocol WebhookReplayStore: Sendable {
    /// Atomically records `eventId` and returns `true` the first time, `false` for a repeat (still inside the horizon).
    func recordFirstReceipt(eventId: String, at: Date) -> Bool
}

/// In-memory store for tests and single-process receivers. Entries expire after `horizon` from first receipt.
public final class InMemoryWebhookReplayStore: WebhookReplayStore, @unchecked Sendable {
    private let lock = NSLock()
    private var firstSeen: [String: Date] = [:]
    private let horizon: TimeInterval

    public init(horizon: TimeInterval = WebhookRetrySchedule.documentedMinimumRetention) { self.horizon = horizon }

    public func recordFirstReceipt(eventId: String, at: Date) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        firstSeen = firstSeen.filter { at.timeIntervalSince($0.value) < horizon }
        guard firstSeen[eventId] == nil else { return false }
        firstSeen[eventId] = at
        return true
    }
}

/// A verified signature-v2 delivery.
public struct VerifiedWebhookV2: Sendable, Equatable {
    public var eventId: String
    public var tenantId: String
    public var timestamp: Int64
    public var body: Data
}

/// Verifies signature `v2` (`Viadere-Signature: t=…,v2=<kid>:<mac>`; method, host, path, timestamp, event id, tenant, key id and body digest are signed).
///
/// Build it with the **endpoint URL you registered** (never a value rewritten by a proxy), your tenant id and the secrets by key id (`Viadere-Key-Id` of a
/// delivery names the current one; keep the previous secret during a rotation). Use the raw body bytes.
public struct WebhookVerifierV2: Sendable {
    public enum Failure: Error, Sendable, Equatable {
        case missingHeader(String)
        case malformedSignature
        case timestampOutsideTolerance
        case noMatchingSignature
        case tenantMismatch
        case digestMismatch
        /// The event id was already processed (acknowledge `200`, do not process again).
        case duplicateEvent
    }

    private let endpoint: URL
    private let tenantId: String
    private let keys: [String: String]
    private let tolerance: TimeInterval
    private let clock: @Sendable () -> Date

    public init(endpoint: URL, tenantId: String, keys: [String: String], tolerance: TimeInterval = WebhookSignature.defaultTolerance, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.endpoint = endpoint
        self.tenantId = tenantId
        self.keys = keys
        self.tolerance = min(max(tolerance, 1), WebhookSignature.defaultTolerance)
        self.clock = clock
    }

    @discardableResult
    public func verify(headers: [String: String], body: Data, method: String = "POST", replayStore: (any WebhookReplayStore)? = nil) throws(Failure) -> VerifiedWebhookV2 {
        func header(_ name: String) -> String? { headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
        guard let signature = header(ViadereHeader.signature) else { throw .missingHeader(ViadereHeader.signature) }
        guard let eventId = header(ViadereHeader.eventId) else { throw .missingHeader(ViadereHeader.eventId) }
        guard let tenant = header(ViadereHeader.tenant) else { throw .missingHeader(ViadereHeader.tenant) }
        guard let context = WebhookSignatureV2.Context(endpoint: endpoint, method: method, eventId: eventId, tenantId: tenant) else { throw .malformedSignature }
        let timestamp: Int64
        do {
            timestamp = try WebhookSignatureV2.verify(header: signature, body: body, contentDigestHeader: header(ViadereHeader.contentDigest), context: context,
                                                      expectedTenant: tenantId, keys: keys, now: clock(), tolerance: tolerance)
        } catch {
            switch error {
            case .malformedHeader: throw .malformedSignature
            case .timestampOutsideTolerance: throw .timestampOutsideTolerance
            case .noMatchingSignature: throw .noMatchingSignature
            case .tenantMismatch: throw .tenantMismatch
            case .digestMismatch: throw .digestMismatch
            }
        }
        // Only a delivery that verified is recorded, so a forged one cannot burn a genuine event id.
        if let replayStore, !replayStore.recordFirstReceipt(eventId: eventId, at: clock()) { throw .duplicateEvent }
        return VerifiedWebhookV2(eventId: eventId, tenantId: tenant, timestamp: timestamp, body: body)
    }

    /// Verifies and decodes the opaque envelope of an `auth.*` event.
    public func verifyEnvelope(headers: [String: String], body: Data, replayStore: (any WebhookReplayStore)? = nil) throws -> WebhookEnvelopeV2 {
        try verify(headers: headers, body: body, replayStore: replayStore)
        guard let envelope = try? ViadereJSON.decode(WebhookEnvelopeV2.self, from: body), envelope.version == WebhookEnvelopeV2.version else { throw WebhookVerificationError.malformedBody }
        return envelope
    }
}

/// `signAuthDestination` (ADR-0031 section 6): signs the statement that commits to the exact URL a delivery carries. Keep the key in your KMS; `key` only signs.
public func signAuthDestination(url: String, subjectRef: SubjectRef, requestId: String, purpose: AuthDeliveryPurpose, tenantId: String, kid: String,
                                key: any DeviceSigningKey, issuedAt: Date = Date(), lifetime: Int64 = 300) async throws -> String {
    try await AuthDestinationStatement.build(url: url, tenantId: tenantId, subjectRef: subjectRef, requestId: requestId, purpose: purpose, kid: kid,
                                             issuedAt: issuedAt, lifetime: lifetime).sign(with: key)
}
