import Foundation
import ViadereCore

/// A verified opaque (`2026-10-27`) webhook delivery.
public struct VerifiedEnvelope: Sendable, Equatable {
    public var envelope: WebhookEnvelopeV2
    /// `Viadere-Delivery-Id`: stable across retries of one delivery.
    public var deliveryId: String?
    /// `Viadere-Key-Id`: `whk_{subscription prefix}_v{secret version}`. Record it: a change means the secret was rotated.
    public var keyId: String?
}

extension WebhookVerifier {
    /// Verifies a delivery to a subscription that opted into the opaque envelope: signature over the raw bytes, timestamp window, strict
    /// envelope (no unknown members), and agreement of `Viadere-Event-Id`, `Viadere-Event-Type` and `Viadere-Webhook-Version` with the signed body.
    ///
    /// The envelope names **what** happened and **where** to fetch it (`result_ref` with `ViadereBusinessClient.approvalResult`); it carries no
    /// decision, amount or personal data, and a status in it would not be trusted anyway.
    @discardableResult
    public func verifyEnvelope(headers: [String: String], body: Data, deduplicator: (any WebhookEventDeduplicator)? = nil) throws -> VerifiedEnvelope {
        func header(_ name: String) -> String? { headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
        guard let signature = header(Self.signatureHeader) else { throw WebhookVerificationError.missingSignatureHeader }
        do {
            try WebhookSignature.verify(header: signature, body: body, secrets: secretList, now: now(), tolerance: toleranceValue)
        } catch let error as WebhookSignature.Error {
            switch error {
            case .malformedHeader: throw WebhookVerificationError.malformedSignature
            case .timestampOutsideTolerance: throw WebhookVerificationError.timestampOutsideTolerance
            case .noMatchingSignature: throw WebhookVerificationError.noMatchingSignature
            }
        }
        guard let envelope = try? ViadereJSON.decode(WebhookEnvelopeV2.self, from: body), envelope.version == WebhookEnvelopeV2.version else { throw WebhookVerificationError.malformedBody }
        if let id = header(Self.eventIdHeader), id != envelope.id { throw WebhookVerificationError.headerBodyMismatch }
        if let type = header(Self.eventTypeHeader), type != envelope.type { throw WebhookVerificationError.headerBodyMismatch }
        if let version = header(ViadereHeader.webhookVersion), version != envelope.version { throw WebhookVerificationError.headerBodyMismatch }
        if let deduplicator, !deduplicator.markProcessing(eventId: envelope.id) { throw WebhookVerificationError.duplicateEvent }
        return VerifiedEnvelope(envelope: envelope, deliveryId: header(ViadereHeader.deliveryId), keyId: header(ViadereHeader.keyId))
    }
}
