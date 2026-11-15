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

extension WebhookVerifier {
    /// Answers Viadere's endpoint-ownership challenge (`webhook.verification`). Call it for a request whose `Viadere-Event-Type` is
    /// `webhook.verification`, and return the result as the `2xx` response body (`Content-Type: application/json`).
    ///
    /// The request is verified exactly like a delivery (signature over the raw bytes, timestamp window), and the answer is
    /// `{"challenge_response": HMAC-SHA256(signing secret, challenge)}`. **Echoing the challenge does not work**: only a receiver that holds the
    /// endpoint's signing secret can answer, which is what proves the URL belongs to the registrant.
    ///
    /// ```swift
    /// if request.headers["Viadere-Event-Type"] == "webhook.verification" {
    ///     return .ok(json: try verifier.verificationResponse(headers: request.headers, body: rawBody))
    /// }
    /// ```
    public func verificationResponse(headers: [String: String], body: Data) throws -> Data {
        func header(_ name: String) -> String? { headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
        guard let signature = header(Self.signatureHeader) else { throw WebhookVerificationError.missingSignatureHeader }
        var matched: String?
        var failure = WebhookSignature.Error.noMatchingSignature
        for candidate in secretList {
            do {
                try WebhookSignature.verify(header: signature, body: body, secrets: [candidate], now: now(), tolerance: toleranceValue)
                matched = candidate
                break
            } catch let error as WebhookSignature.Error { failure = error }
        }
        guard let secret = matched else {
            switch failure {
            case .malformedHeader: throw WebhookVerificationError.malformedSignature
            case .timestampOutsideTolerance: throw WebhookVerificationError.timestampOutsideTolerance
            case .noMatchingSignature: throw WebhookVerificationError.noMatchingSignature
            }
        }
        guard let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any], object["type"] as? String == "webhook.verification",
              let challenge = object["challenge"] as? String, !challenge.isEmpty, challenge.count <= 256 else { throw WebhookVerificationError.notAVerificationRequest }
        if let type = header(Self.eventTypeHeader), type != "webhook.verification" { throw WebhookVerificationError.headerBodyMismatch }
        return try ViadereJSON.encode(["challenge_response": WebhookSignature.verificationResponse(secret: secret, challenge: challenge)])
    }
}
